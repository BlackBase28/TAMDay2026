# Kernel CVE Radar

TAM Day 2026 展示用站台。

## 目錄

```text
start/      修復前版本：user1 登入後可以存取 /admin
solution/   修復後版本：只有 admin 可以存取 /admin，頁尾標示 Fixed version
```

## 展示帳號

```text
admin / TAMDay@2026
user1 / User1@tday
```

## 部署重點

部署修復後版本時，AAP 的 build context 必須指向 `solution/`，不可只同步 Git 後重啟舊容器。

```yaml
cve_radar_repo_subdir: "kernel-CVE-radar/solution"   # 複製後的 Repository
cve_radar_containerfile: "Containerfile"
cve_radar_force_rebuild: true
```

若直接使用原 Repository，`cve_radar_repo_subdir` 改為 `solution`。為相容既有設定，本版本也提供 `solution/deploy/Containerfile`。

部署流程必須停止並移除既有容器、重新 build image，再啟動 Quadlet service。舊 `/etc/kernel-cve-radar.env` 中的 `APP_VERSION` 已不再覆蓋套件版本。

## 部署後驗證

```bash
curl -ks https://<VM-IP-or-FQDN>/healthz
```

修復後版本必須回傳：

```json
{"status":"ok","version":"2.8.2","mode":"solution","fixed_version":true}
```

另可直接確認執行中容器：

```bash
sudo podman exec kernel-cve-radar cat /opt/app-root/src/VERSION
sudo podman exec kernel-cve-radar grep -F "Fixed version" /opt/app-root/src/app/templates/base.html
sudo podman exec kernel-cve-radar grep -F 'role != "admin"' /opt/app-root/src/app/public.py
```

## Log

```text
/var/log/kernel-cve-radar/auth-events.jsonl
/var/log/kernel-cve-radar/access.log
/var/log/kernel-cve-radar/error.log
/var/log/httpd/access_log
/var/log/httpd/error_log
```
