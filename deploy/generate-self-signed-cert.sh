#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "請使用 sudo 執行此腳本。" >&2
  exit 1
fi

SERVER_NAME="${1:?用法：$0 <FQDN或VM-IP> [--force]}"
FORCE="${2:-}"
CERT_FILE=/etc/pki/tls/certs/kernel-cve-radar.crt
KEY_FILE=/etc/pki/tls/private/kernel-cve-radar.key
CERT_DAYS="${CERT_DAYS:-825}"

if [[ -f "${CERT_FILE}" && -f "${KEY_FILE}" && "${FORCE}" != "--force" ]]; then
  echo "沿用既有自簽憑證：${CERT_FILE}"
  exit 0
fi

install -d -m 0755 /etc/pki/tls/certs
install -d -m 0700 /etc/pki/tls/private

if [[ "${SERVER_NAME}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  SUBJECT_ALT_NAME="IP:${SERVER_NAME},IP:127.0.0.1,DNS:localhost"
else
  SUBJECT_ALT_NAME="DNS:${SERVER_NAME},DNS:localhost,IP:127.0.0.1"
fi

TMP_CERT="$(mktemp)"
TMP_KEY="$(mktemp)"
trap 'rm -f "${TMP_CERT}" "${TMP_KEY}"' EXIT

openssl req \
  -x509 \
  -newkey rsa:3072 \
  -sha256 \
  -nodes \
  -days "${CERT_DAYS}" \
  -subj "/CN=${SERVER_NAME}/O=Kernel CVE Radar/OU=POC" \
  -addext "subjectAltName=${SUBJECT_ALT_NAME}" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "${TMP_KEY}" \
  -out "${TMP_CERT}" \
  >/dev/null 2>&1

install -o root -g root -m 0600 "${TMP_KEY}" "${KEY_FILE}"
install -o root -g root -m 0644 "${TMP_CERT}" "${CERT_FILE}"
restorecon -F "${KEY_FILE}" "${CERT_FILE}" 2>/dev/null || true

echo "已產生自簽憑證："
echo "  Certificate: ${CERT_FILE}"
echo "  Private key: ${KEY_FILE}"
echo "  Subject/SAN: ${SERVER_NAME}"
