#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "請使用 sudo 執行：sudo ./deploy/install.sh <FQDN或VM-IP>"
  exit 1
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_NAME="${1:-$(hostname -f 2>/dev/null || hostname)}"
ENV_FILE=/etc/kernel-cve-radar.env
DATA_DIR=/var/lib/kernel-cve-radar
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

migrate_old_logs() {
  if [[ -d "${OLD_LOG_DIR}" ]]; then
    shopt -s nullglob
    local files=("${OLD_LOG_DIR}"/auth-events.jsonl*)
    if (( ${#files[@]} > 0 )); then
      echo "偵測到舊版登入事件，複製到 ${LOG_DIR}"
      cp -an "${files[@]}" "${LOG_DIR}/" || true
      chown 1001:0 "${LOG_DIR}"/auth-events.jsonl* 2>/dev/null || true
      chmod 0640 "${LOG_DIR}"/auth-events.jsonl* 2>/dev/null || true
    fi
    shopt -u nullglob
  fi
}

random_password() {
  local candidate=""
  while true; do
    candidate="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9')"
    candidate="${candidate:0:12}"
    if [[ ${#candidate} -eq 12 && "${candidate}" =~ [a-z] && "${candidate}" =~ [A-Z] && "${candidate}" =~ [0-9] ]]; then
      printf '%s' "${candidate}"
      return
    fi
  done
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
  # RHEL mod_ssl ships a vendor ssl.conf that references localhost.crt and also
  # defines its own default :443 vhost. This project owns the only HTTPS vhost,
  # so disable the vendor file and provide an explicit listener.
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

printf '\n[1/8] 安裝 Podman、Apache HTTPS 與必要工具\n'
dnf install -y podman httpd mod_ssl firewalld openssl curl
systemctl enable --now firewalld

printf '\n[2/8] 建立資料與日誌目錄\n'
install -d -o 1001 -g 0 -m 0770 "${DATA_DIR}" "${LOG_DIR}"
install_maintenance_static
migrate_old_logs

if [[ ! -f "${ENV_FILE}" ]]; then
  printf '\n[3/8] 產生初始帳號與隨機密碼\n'
  ADMIN_PASSWORD="$(random_password)"
  INITIAL_USER_PASSWORD="$(random_password)"

  cat > "${ENV_FILE}" <<ENVEOF
SECRET_KEY=$(openssl rand -hex 32)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=${ADMIN_PASSWORD}
INITIAL_USER_USERNAME=user1
INITIAL_USER_PASSWORD=${INITIAL_USER_PASSWORD}
INITIAL_USER_DISPLAY_NAME=一般使用者
INITIAL_CREDENTIALS_FILE=/data/initial-credentials.txt
DATABASE_PATH=/data/kernel_cve.db
TRUST_PROXY_HEADERS=true
PROXY_FIX_X_FOR=1
SESSION_COOKIE_SECURE=true
AUTH_EVENT_LOG_FILE=/var/log/kernel-cve-radar/auth-events.jsonl
AUTH_EVENT_STDOUT=true
ENVEOF
  chmod 0600 "${ENV_FILE}"
  unset ADMIN_PASSWORD INITIAL_USER_PASSWORD
else
  printf '\n[3/8] 保留既有環境設定並補齊 HTTPS／真實來源 IP 參數\n'
  set_env_value AUTH_EVENT_LOG_FILE /var/log/kernel-cve-radar/auth-events.jsonl "${ENV_FILE}"
  ensure_env_default TRUST_PROXY_HEADERS true "${ENV_FILE}"
  ensure_env_default PROXY_FIX_X_FOR 1 "${ENV_FILE}"
  set_env_value SESSION_COOKIE_SECURE true "${ENV_FILE}"
  chmod 0600 "${ENV_FILE}"
fi

printf '\n[4/8] 建置容器映像\n'
cd "${APP_DIR}"
podman build --no-cache -t localhost/kernel-cve-radar:latest -f Containerfile .

printf '\n[5/8] 安裝 Quadlet 並強制重建容器\n'
install -d -m 0755 /etc/containers/systemd
install -m 0644 deploy/kernel-cve-radar.container /etc/containers/systemd/kernel-cve-radar.container
install -m 0644 deploy/kernel-cve-radar.logrotate /etc/logrotate.d/kernel-cve-radar
systemctl stop kernel-cve-radar.service 2>/dev/null || true
podman rm -f kernel-cve-radar 2>/dev/null || true
systemctl daemon-reload
# Quadlet 產生的 service 是 generated unit，不能使用 systemctl enable。
# [Install] WantedBy=multi-user.target 會由 Quadlet generator 建立開機依賴。
systemctl start kernel-cve-radar.service

printf '\n[6/8] 產生自簽憑證並設定 Apache HTTPS\n'
"${APP_DIR}/deploy/generate-self-signed-cert.sh" "${SERVER_NAME}" --force
configure_httpd_base
install -m 0644 deploy/httpd-kernel-cve.conf "${HTTPD_CONF}"
sed -i "s/kernel-cve.example.com/${SERVER_NAME}/g" "${HTTPD_CONF}"
setsebool -P httpd_can_network_connect 1
apachectl configtest
systemctl enable --now httpd
systemctl restart httpd

printf '\n[7/8] 開放 HTTP 轉址與 HTTPS 防火牆服務\n'
firewall-cmd --permanent --add-service=http >/dev/null
firewall-cmd --permanent --add-service=https >/dev/null
firewall-cmd --reload >/dev/null

printf '\n[8/8] 健康檢查與代理設定驗證\n'
for _ in {1..15}; do
  if curl -fsS http://127.0.0.1:8000/healthz >/dev/null && \
     curl -kfsS --resolve "${SERVER_NAME}:443:127.0.0.1" "https://${SERVER_NAME}/healthz" >/dev/null && \
     verify_proxy_environment; then
    echo "部署完成："
    echo "  登入頁：https://${SERVER_NAME}/login"
    echo "  HTTP 會自動導向 HTTPS"
    echo "  初始帳密：sudo cat /var/lib/kernel-cve-radar/initial-credentials.txt"
    echo "  應用日誌：sudo ls -l ${LOG_DIR}"
    echo "  自簽憑證：/etc/pki/tls/certs/kernel-cve-radar.crt"
    echo "  版本確認：curl -ks https://${SERVER_NAME}/healthz"
    echo "  瀏覽器首次連線會顯示自簽憑證警告，POC 可手動接受。"
    exit 0
  fi
  sleep 2
done

echo "健康檢查失敗，請查看：${LOG_DIR}/error.log 與 /var/log/httpd/error_log"
exit 1
