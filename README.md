# Kernel CVE Radar

TAM Day 2026 展示用網站。此版本是「修復前」簡化版，主要目的是讓後續 AI／AAP Playbook 有容易修改的網頁碼。

## 展示情境

1. **身分管理缺陷**：`user1` 登入後可存取 `/admin` 內容，這是刻意保留的修復前狀態。
2. **DDoS 攻擊**：專案提供 httpd 維護頁設定，後續 Playbook 可將所有 request 導向維護頁。
3. **撞庫攻擊**：登入事件會寫入精簡 `auth-events.jsonl`，後續 Playbook 可依事件鎖定帳號。

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

保留三種 Log：

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

EDA 或 AI 後續建議只讀取 `auth-events.jsonl`。

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
