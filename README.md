# Kernel CVE Radar

TAM Day 2026 展示用網站。此版本是簡化版，只保留登入、CVE 資訊展示、精簡事件輸出與 httpd 維護頁切換，方便後續 AI／AAP Playbook 修改與修復。

## 展示情境

1. **身分管理缺陷**：`user1` 登入後可存取 `/admin` 內容，這是刻意保留的修復前狀態。
2. **站台隔離／維護頁切換**：外部 Playbook 可透過 httpd 設定將所有 request 導向維護頁，避免流量進入 Flask。
3. **撞庫攻擊**：登入事件會寫入精簡 `auth-events.jsonl`，後續 Playbook 可依事件鎖定帳號。

## 建議的維護頁 Demo 場景

DDoS 需要同時考慮短時間 request 數與系統負載，在 Demo 環境不一定容易穩定重現。建議優先採用以下兩種情境來展示維護頁切換：

- **未授權管理頁存取後的暫時隔離**：當 `auth-events.jsonl` 出現 `user1` 的 `admin_access` 且 `result=allowed`，代表一般使用者已看到 Admin 內容。後續 AI／AAP 可先切換維護頁，再修正 `/admin` 的角色檢查。
- **後端異常或疑似被濫用**：當 `/healthz` 失敗、httpd `access_log` 出現大量 `502/503/504`，或應用 `error.log` 出現連續錯誤時，Playbook 可切到靜態維護頁，讓 httpd 直接回應使用者，避免 request 繼續進入 Flask。

這兩種情境都不需要 API，也不需要真的產生高負載，比較適合 TAM Day 現場展示。

## 快速安裝

```bash
sudo dnf install -y git
sudo git clone https://github.com/<your-org>/kernel-cve-radar.git /opt/kernel-cve-radar
cd /opt/kernel-cve-radar
sudo ./deploy/install.sh <VM-IP-or-FQDN>
```

查看初始帳密：

```bash
sudo cat /var/lib/kernel-cve-radar/initial-credentials.txt
```

預設會建立：

- `admin`：管理者
- `user1`：一般使用者，但目前仍可看到 `/admin`，用於身分管理修復展示

## 更新

```bash
cd /opt/kernel-cve-radar
git pull origin main
sudo ./deploy/update.sh <VM-IP-or-FQDN>
```

確認版本：

```bash
curl -ks https://<VM-IP-or-FQDN>/healthz
```

## Log

為了讓後續 AI Playbook 比較容易判讀，httpd 使用 RHEL 預設 Log 路徑：

```text
/var/log/httpd/access_log
/var/log/httpd/error_log

> v2.7.5 之後，部署腳本會自動停用舊版 `/etc/httpd/conf.d/cve-radar.conf`，統一使用 `/etc/httpd/conf.d/kernel-cve-radar.conf`，避免 httpd 繼續寫入舊的 `cve-radar_access.log` / `cve-radar_error.log`。
```

應用程式仍保留三種 Log：

```text
/var/log/kernel-cve-radar/auth-events.jsonl
/var/log/kernel-cve-radar/access.log
/var/log/kernel-cve-radar/error.log
```

`auth-events.jsonl` 已精簡為單行小 JSON。登入失敗範例：

```json
{"ts":"2026-06-25T07:09:21Z","outcome":"fail","user":"admin","ip":"1.171.129.203","path":"/login","reason":"bad_password"}
```

一般使用者成功存取 Admin 頁時，會額外產生：

```json
{"ts":"2026-06-25T07:15:10Z","event":"admin_access","user":"user1","role":"user","ip":"1.171.129.203","path":"/admin","result":"allowed"}
```

## 維護頁切換

啟用維護頁時，由外部 Playbook 將 httpd 設定換成：

```bash
sudo cp deploy/httpd-kernel-cve-maintenance.conf /etc/httpd/conf.d/kernel-cve-radar.conf
sudo sed -i 's/kernel-cve.example.com/<VM-IP-or-FQDN>/g' /etc/httpd/conf.d/kernel-cve-radar.conf
sudo apachectl configtest
sudo systemctl reload httpd
```

恢復正常站台：

```bash
sudo cp deploy/httpd-kernel-cve.conf /etc/httpd/conf.d/kernel-cve-radar.conf
sudo sed -i 's/kernel-cve.example.com/<VM-IP-or-FQDN>/g' /etc/httpd/conf.d/kernel-cve-radar.conf
sudo apachectl configtest
sudo systemctl reload httpd
```

## 雲端來源 IP

若放在 Load Balancer 後方，確認：

```bash
sudo podman exec kernel-cve-radar env | grep -E '^(TRUST_PROXY_HEADERS|PROXY_FIX_X_FOR)='
```

預設：

```ini
TRUST_PROXY_HEADERS=true
PROXY_FIX_X_FOR=1
```

若有多層可信任 proxy，再調整 `/etc/kernel-cve-radar.env` 的 `PROXY_FIX_X_FOR`。

## 撞庫後鎖定帳號的簡單指令

後續 Playbook 可以先用以下方式模擬鎖定 `user1`：

```bash
sudo podman exec kernel-cve-radar python manage.py disable-user user1
```

恢復：

```bash
sudo podman exec kernel-cve-radar python manage.py enable-user user1
```
