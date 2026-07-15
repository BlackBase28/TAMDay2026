# Kernel CVE Radar

TAM Day 2026 展示用簡化站台。本 Repository 只保留展示與修復流程需要的內容。

## 目錄

```text
start/      修復前版本：user1 登入後可以存取 /admin
solution/   修復後版本：只有 admin 可以存取 /admin，首頁下方標示 Fixed version
```

## Git 分支備份

將此架構更新到 `main` 前，先備份目前 main：

```bash
git switch main
git pull origin main
git branch backup_v2_0705
git push origin backup_v2_0705
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

## 三個展示情境

1. `start/` 中，`user1` 可以存取 `/admin`，並寫入 `admin_access` 事件。
2. 站台隔離時，AAP Playbook 可將 httpd 設定切成 `deploy/httpd-kernel-cve-maintenance.conf`。
3. 撞庫偵測後，AAP Playbook 可執行 `python manage.py disable-user user1` 鎖定帳號。

## 使用方式

部署修復前版本時，部署 Playbook 使用：

```text
start/
```

AI 修復或示範修復後，改為部署：

```text
solution/
```

兩個資料夾都保留相同部署檔案與容器入口，差異只在 `/admin` 權限檢查與首頁 `Fixed version` 標示。
