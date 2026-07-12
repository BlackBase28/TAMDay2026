#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "請使用 sudo 執行：sudo ./deploy/update.sh [FQDN或VM-IP]"
  exit 1
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE=/etc/kernel-cve-radar.env
LOG_DIR=/var/log/kernel-cve-radar
MAINTENANCE_DOCROOT=/var/www/kernel-cve-radar-maintenance
OLD_LOG_DIR=/var/lib/kernel-cve-radar/logs
HTTPD_CONF=/etc/httpd/conf.d/kernel-cve-radar.conf
HTTPD_BASE_CONF=/etc/httpd/conf.d/00-kernel-cve-radar-base.conf
VENDOR_SSL_CONF=/etc/httpd/conf.d/ssl.conf
VENDOR_SSL_DISABLED=/etc/httpd/conf.d/ssl.conf.vendor-disabled
LEGACY_LISTEN_CONF=/etc/httpd/conf.d/00-listen-443.conf
LEGACY_SSL_VHOST=/etc/httpd/conf.d/kernel-cve-radar-ssl.conf
LEGACY_CVE_RADAR_CONF=/etc/httpd/conf.d/cve-radar.conf
LEGACY_CVE_RADAR_DISABLED=/etc/httpd/conf.d/cve-radar.conf.legacy-disabled
CERT_FILE=/etc/pki/tls/certs/kernel-cve-radar.crt
KEY_FILE=/etc/pki/tls/private/kernel-cve-radar.key
EXPLICIT_SERVER_NAME="${1:-}"
cd "${APP_DIR}"

set_env_value() {
  local key="$1" value="$2" file="$3"
  if grep -q "^${key}=" "${file}"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "${file}"
  else
    printf '%s=%s\n' "${key}" "${value}" >> "${file}"
  fi
}

ensure_env_default() {
  local key="$1" value="$2" file="$3"
  if ! grep -q "^${key}=" "${file}"; then
    printf '%s=%s\n' "${key}" "${value}" >> "${file}"
  fi
}

env_value() {
  local key="$1" file="$2" value
  value="$(awk -F= -v wanted="${key}" '$1 == wanted {sub(/^[^=]*=/, ""); print; exit}' "${file}")"
  value="${value%\"}"
  value="${value#\"}"
  value="${value%\'}"
  value="${value#\'}"
  printf '%s' "${value}"
}

get_server_name() {
  if [[ -n "${EXPLICIT_SERVER_NAME}" ]]; then
    printf '%s' "${EXPLICIT_SERVER_NAME}"
    return
  fi
  if [[ -f "${HTTPD_CONF}" ]]; then
    local configured
    configured="$(awk '$1 == "ServerName" {print $2; exit}' "${HTTPD_CONF}")"
    if [[ -n "${configured}" && "${configured}" != "kernel-cve.example.com" ]]; then
      printf '%s' "${configured}"
      return
    fi
  fi
  hostname -f 2>/dev/null || hostname
}

ensure_env_file() {
  if [[ ! -f "${ENV_FILE}" ]]; then
    cat > "${ENV_FILE}" <<ENVEOF
SECRET_KEY=$(openssl rand -hex 32)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=
INITIAL_USER_USERNAME=user1
INITIAL_USER_PASSWORD=
INITIAL_USER_DISPLAY_NAME=一般使用者
INITIAL_CREDENTIALS_FILE=/data/initial-credentials.txt
DATABASE_PATH=/data/kernel_cve.db
TRUST_PROXY_HEADERS=true
PROXY_FIX_X_FOR=1
SESSION_COOKIE_SECURE=true
AUTH_EVENT_LOG_FILE=/var/log/kernel-cve-radar/auth-events.jsonl
AUTH_EVENT_STDOUT=true
ENVEOF
  fi
  set_env_value AUTH_EVENT_LOG_FILE /var/log/kernel-cve-radar/auth-events.jsonl "${ENV_FILE}"
  ensure_env_default TRUST_PROXY_HEADERS true "${ENV_FILE}"
  ensure_env_default PROXY_FIX_X_FOR 1 "${ENV_FILE}"
  set_env_value SESSION_COOKIE_SECURE true "${ENV_FILE}"
  chmod 0600 "${ENV_FILE}"
}

install_maintenance_static() {
  install -d -m 0755 "${MAINTENANCE_DOCROOT}"
  install -m 0644 "${APP_DIR}/deploy/maintenance/maintenance.html" "${MAINTENANCE_DOCROOT}/maintenance.html"
  sed "s/__VERSION__/$(cat "${APP_DIR}/VERSION" 2>/dev/null || echo unknown)/g" \
    "${APP_DIR}/deploy/maintenance/healthz.json" > "${MAINTENANCE_DOCROOT}/healthz.json"
  chmod 0644 "${MAINTENANCE_DOCROOT}/healthz.json"
  restorecon -RF "${MAINTENANCE_DOCROOT}" >/dev/null 2>&1 || true
}

configure_httpd_base() {
  if [[ -f "${VENDOR_SSL_CONF}" ]]; then
    mv -f "${VENDOR_SSL_CONF}" "${VENDOR_SSL_DISABLED}"
  fi
  # Disable files created by earlier manual recovery steps to avoid duplicate
  # Listen 443 directives or duplicate HTTPS virtual hosts.
  if [[ -f "${LEGACY_LISTEN_CONF}" ]]; then
    mv -f "${LEGACY_LISTEN_CONF}" "${LEGACY_LISTEN_CONF}.legacy-disabled"
  fi
  if [[ -f "${LEGACY_SSL_VHOST}" ]]; then
    mv -f "${LEGACY_SSL_VHOST}" "${LEGACY_SSL_VHOST}.legacy-disabled"
  fi

  # Disable old deployment file name used by early builds. If it remains active,
  # httpd may keep writing to cve-radar_access.log / cve-radar_error.log or load
  # duplicate VirtualHosts instead of this version's canonical config.
  if [[ -f "${LEGACY_CVE_RADAR_CONF}" && "${LEGACY_CVE_RADAR_CONF}" != "${HTTPD_CONF}" ]]; then
    mv -f "${LEGACY_CVE_RADAR_CONF}" "${LEGACY_CVE_RADAR_DISABLED}"
  fi
  cat > "${HTTPD_BASE_CONF}" <<BASEEOF
ServerName ${SERVER_NAME}
Listen 443 https
BASEEOF
  chmod 0644 "${HTTPD_BASE_CONF}"
}

verify_proxy_environment() {
  local output expected_trust expected_hops
  output="$(podman exec kernel-cve-radar env 2>/dev/null || true)"
  expected_trust="$(env_value TRUST_PROXY_HEADERS "${ENV_FILE}")"
  expected_hops="$(env_value PROXY_FIX_X_FOR "${ENV_FILE}")"
  expected_trust="${expected_trust:-true}"
  expected_hops="${expected_hops:-1}"

  grep -q "^TRUST_PROXY_HEADERS=${expected_trust}$" <<<"${output}" || {
    echo "錯誤：容器未取得 TRUST_PROXY_HEADERS=${expected_trust}" >&2
    return 1
  }
  grep -q "^PROXY_FIX_X_FOR=${expected_hops}$" <<<"${output}" || {
    echo "錯誤：容器未取得 PROXY_FIX_X_FOR=${expected_hops}" >&2
    return 1
  }
}

SERVER_NAME="$(get_server_name)"

echo "[1/7] 備份資料庫"
if [[ -f /var/lib/kernel-cve-radar/kernel_cve.db ]]; then
  install -d -m 0750 /var/backups/kernel-cve-radar
  ./scripts/backup-db.sh /var/lib/kernel-cve-radar/kernel_cve.db /var/backups/kernel-cve-radar
fi

echo "[2/7] 使用目前工作目錄中的版本"
echo "版本：$(cat VERSION 2>/dev/null || echo unknown)"

echo "[3/7] 補齊環境設定、HTTPS 套件與日誌目錄"
dnf install -y httpd mod_ssl openssl curl firewalld
systemctl enable --now firewalld
install -d -o 1001 -g 0 -m 0770 "${LOG_DIR}"
install_maintenance_static
if [[ -d "${OLD_LOG_DIR}" ]]; then
  shopt -s nullglob
  old_files=("${OLD_LOG_DIR}"/auth-events.jsonl*)
  if (( ${#old_files[@]} > 0 )); then
    cp -an "${old_files[@]}" "${LOG_DIR}/" || true
    chown 1001:0 "${LOG_DIR}"/auth-events.jsonl* 2>/dev/null || true
    chmod 0640 "${LOG_DIR}"/auth-events.jsonl* 2>/dev/null || true
  fi
  shopt -u nullglob
fi
ensure_env_file

echo "[4/7] 重建容器映像"
podman build --no-cache -t localhost/kernel-cve-radar:latest -f Containerfile .

echo "[5/7] 更新 Quadlet 並強制重建容器"
install -d -m 0755 /etc/containers/systemd
install -m 0644 deploy/kernel-cve-radar.container /etc/containers/systemd/kernel-cve-radar.container
install -m 0644 deploy/kernel-cve-radar.logrotate /etc/logrotate.d/kernel-cve-radar
systemctl stop kernel-cve-radar.service 2>/dev/null || true
podman rm -f kernel-cve-radar 2>/dev/null || true
systemctl daemon-reload
# Quadlet 產生的 service 是 generated unit，不能使用 systemctl enable。
# [Install] WantedBy=multi-user.target 會由 Quadlet generator 建立開機依賴。
systemctl start kernel-cve-radar.service

echo "[6/7] 產生或沿用自簽憑證並啟用 HTTPS"
if [[ -n "${EXPLICIT_SERVER_NAME}" || ! -f "${CERT_FILE}" || ! -f "${KEY_FILE}" ]]; then
  "${APP_DIR}/deploy/generate-self-signed-cert.sh" "${SERVER_NAME}" --force
else
  "${APP_DIR}/deploy/generate-self-signed-cert.sh" "${SERVER_NAME}"
fi
configure_httpd_base
install -m 0644 deploy/httpd-kernel-cve.conf "${HTTPD_CONF}"
sed -i "s/kernel-cve.example.com/${SERVER_NAME}/g" "${HTTPD_CONF}"
setsebool -P httpd_can_network_connect 1
apachectl configtest
systemctl enable --now httpd
systemctl restart httpd

echo "[7/7] 開放 HTTP 轉址、HTTPS 並執行健康檢查"
firewall-cmd --permanent --add-service=http >/dev/null
firewall-cmd --permanent --add-service=https >/dev/null
firewall-cmd --reload >/dev/null

for _ in {1..15}; do
  if curl -fsS http://127.0.0.1:8000/healthz >/dev/null && \
     curl -kfsS --resolve "${SERVER_NAME}:443:127.0.0.1" "https://${SERVER_NAME}/healthz" >/dev/null && \
     verify_proxy_environment; then
    echo "更新完成。"
    echo "登入頁：https://${SERVER_NAME}/login"
    echo "HTTP 已自動導向 HTTPS。"
    echo "應用日誌：${LOG_DIR}"
    echo "自簽憑證：${CERT_FILE}"
    echo "版本確認：curl -ks https://${SERVER_NAME}/healthz"
    echo "來源 IP 設定確認：podman exec kernel-cve-radar env | grep -E '^(TRUST_PROXY_HEADERS|PROXY_FIX_X_FOR)='"
    if [[ -f /var/lib/kernel-cve-radar/initial-credentials.txt ]]; then
      echo "初始帳密：sudo cat /var/lib/kernel-cve-radar/initial-credentials.txt"
    fi
    exit 0
  fi
  sleep 2
done

echo "更新後健康檢查失敗，請查看 ${LOG_DIR}/error.log 與 /var/log/httpd/error_log"
exit 1
