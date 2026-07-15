# Kernel CVE Radar

TAM Day 2026 展示用簡化站台。本 Repository 只保留展示與修復流程需要的內容。

## 目錄

```text
start/      修復前版本：user1 登入後可以存取 /admin
solution/   修復後版本：只有 admin 可以存取 /admin，首頁下方標示 Fixed version
```

## 展示帳號

```text
admin / TAMDay@2026
user1 / User1@tday
```

## Log

```text
/var/log/kernel-cve-radar/auth-events.jsonl
/var/log/kernel-cve-radar/access.log
/var/log/kernel-cve-radar/error.log
/var/log/httpd/access_log
/var/log/httpd/error_log
```

## 使用方式

部署修復前版本時，部署 Playbook 使用：

```text
start/
```

部署修復後版本時，部署 Playbook 使用：

```text
solution/
```

兩個資料夾都保留相同部署檔案與容器入口，差異只在 `/admin` 權限檢查與首頁 `Fixed version` 標示。

## 三個展示情境

1. `start/` 中，`user1` 可以存取 `/admin`，並寫入 `admin_access` 事件。
2. `solution/` 中，`user1` 存取 `/admin` 會被拒絕，並寫入 `admin_access` denied 事件。
3. 站台隔離時，AAP Playbook 可將 httpd 設定切成 `deploy/httpd-kernel-cve-maintenance.conf`。
4. 撞庫偵測後，AAP Playbook 可執行 `python manage.py disable-user user1` 鎖定帳號。

## 部署後確認

確認目前實際部署的是哪個版本：

```bash
curl -ks https://<VM-IP-or-FQDN>/healthz
```

修復前版本應回傳：

```json
{"status":"ok","version":"2.8.1","mode":"start"}
```

修復後版本應回傳：

```json
{"status":"ok","version":"2.8.1","mode":"solution","fixed_version":true}
```

若重新部署後仍看不到 `Fixed version`，或 `user1` 仍可存取 `/admin`，通常代表實際執行的容器仍是 `start/` 或舊 image，需要確認 Playbook 的 build context 與是否有重新建立容器。
