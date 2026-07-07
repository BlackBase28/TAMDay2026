#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "請使用 sudo 執行。"
  exit 1
fi

CONF=/etc/httpd/conf.d/01-kernel-cve-radar-remoteip.conf
INPUT="${1:-}"

if [[ -z "${INPUT}" ]]; then
  echo "用法：sudo ./deploy/configure-trusted-proxy.sh '<LB CIDR[,LB CIDR...]>'"
  echo "停用：sudo ./deploy/configure-trusted-proxy.sh --disable"
  exit 1
fi

if [[ "${INPUT}" == "--disable" ]]; then
  rm -f "${CONF}"
  apachectl configtest
  systemctl restart httpd
  echo "已停用 cloud load balancer real-IP 解析。"
  exit 0
fi

mapfile -t CIDRS < <(printf '%s' "${INPUT}" | tr ',;' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed '/^$/d')
if (( ${#CIDRS[@]} == 0 )); then
  echo "沒有提供有效的 CIDR。"
  exit 1
fi

python3 - "${CIDRS[@]}" <<'PY'
import ipaddress
import sys
for value in sys.argv[1:]:
    ipaddress.ip_network(value, strict=False)
PY

{
  echo '# Managed by Kernel CVE Radar. Trust only the exact cloud LB/proxy subnet.'
  echo 'RemoteIPHeader X-Forwarded-For'
  echo 'RemoteIPProxiesHeader X-Forwarded-By'
  for cidr in "${CIDRS[@]}"; do
    printf 'RemoteIPInternalProxy %s\n' "${cidr}"
  done
} > "${CONF}"

chmod 0644 "${CONF}"
restorecon -v "${CONF}" 2>/dev/null || true
httpd -M | grep -q 'remoteip_module' || { echo 'httpd 未載入 remoteip_module'; exit 1; }
apachectl configtest
systemctl restart httpd

echo "已啟用 real client IP 解析："
printf '  %s\n' "${CIDRS[@]}"
echo "設定檔：${CONF}"
echo "請測試登入後查看 /var/log/kernel-cve-radar/auth-events.jsonl 的 source_ip。"
