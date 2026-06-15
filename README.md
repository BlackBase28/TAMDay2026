# Kernel CVE Radar

一個不串接 AI、不呼叫外部 API 的 Linux Kernel CVE 展示與情境挑戰站台。

前台提供 CVE 卡片、詳細說明與固定題庫；後台提供管理者登入、CVE／題目維護，以及 IP、時間、輸入內容與作答結果查詢。資料儲存在 SQLite，適合部署在單台 RHEL 測試 VM，並由 Apache httpd 反向代理至 Flask/Gunicorn 容器。

## 功能

### 前台

- Kernel CVE 卡片與條件篩選
- CVE 詳細頁面
- 隨機情境挑戰與固定解答
- 無 AI、無外部 API，斷網環境仍可使用

### 管理後台

- `/admin` 帳號密碼登入
- CVE 新增、修改、停用與刪除
- 情境題目與答案維護
- 管理者密碼變更
- 使用者來源 IP、時間、瀏覽頁面、輸入內容、答案與結果紀錄
- 日期、IP、事件與結果篩選
- CSV 匯出

## 專案結構

```text
kernel-cve-radar/
├── app/
│   ├── templates/             HTML 頁面
│   ├── static/css/            前端樣式
│   ├── admin.py               管理後台
│   ├── public.py              前台與挑戰
│   ├── db.py                  SQLite 存取
│   ├── seed.py                初始 CVE 與題庫
│   └── security.py            Session、CSRF 與登入保護
├── deploy/
│   ├── httpd-kernel-cve.conf
│   └── kernel-cve-radar.container
├── scripts/backup-db.sh
├── Containerfile
├── compose.yaml
├── schema.sql
└── wsgi.py
```

## 本機快速啟動

需要 Python 3.11 以上。

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export SECRET_KEY="$(openssl rand -hex 32)"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="請替換為至少12字元的強密碼"
export TRUST_PROXY_HEADERS=false

flask --app wsgi:app run --host 0.0.0.0 --port 8000
```

開啟：

- 前台：`http://VM-IP:8000/`
- 後台：`http://VM-IP:8000/admin`

第一次啟動且資料庫內沒有管理者時，程式會使用 `ADMIN_USERNAME` 與 `ADMIN_PASSWORD` 建立管理帳號。帳號建立後，即使環境變數仍存在也不會覆寫後台已變更的密碼。

## RHEL：Podman + Apache httpd 部署

以下架構讓 httpd 對外提供 80/443，Flask 容器只監聽 `127.0.0.1:8000`。

```text
Client → Apache httpd → 127.0.0.1:8000 → Gunicorn/Flask → SQLite
```

### 1. 安裝套件

```bash
sudo dnf install -y podman httpd mod_ssl
sudo systemctl enable --now httpd
```

### 2. 建置映像

```bash
git clone <your-github-repository-url>
cd kernel-cve-radar
sudo podman build -t localhost/kernel-cve-radar:latest .
```

### 3. 建立資料目錄與環境檔

```bash
sudo install -d -m 0750 /var/lib/kernel-cve-radar
sudo cp deploy/kernel-cve-radar.env.example /etc/kernel-cve-radar.env
sudo chmod 0600 /etc/kernel-cve-radar.env
sudo vi /etc/kernel-cve-radar.env
```

至少修改：

```ini
SECRET_KEY=使用 openssl rand -hex 32 產生
ADMIN_USERNAME=admin
ADMIN_PASSWORD=至少12字元的強密碼
DATABASE_PATH=/data/kernel_cve.db
TRUST_PROXY_HEADERS=true
SESSION_COOKIE_SECURE=false
```

啟用 HTTPS 後，請把 `SESSION_COOKIE_SECURE` 改成 `true`。

### 4. 使用 Podman Quadlet 啟動

RHEL 9 建議使用 Quadlet：

```bash
sudo install -d /etc/containers/systemd
sudo cp deploy/kernel-cve-radar.container /etc/containers/systemd/
sudo systemctl daemon-reload
sudo systemctl enable --now kernel-cve-radar.service
sudo systemctl status kernel-cve-radar.service
curl http://127.0.0.1:8000/healthz
```

不使用 Quadlet時，可直接執行：

```bash
sudo podman run -d \
  --name kernel-cve-radar \
  --restart=always \
  --env-file /etc/kernel-cve-radar.env \
  -p 127.0.0.1:8000:8000 \
  -v /var/lib/kernel-cve-radar:/data:Z \
  localhost/kernel-cve-radar:latest
```

### 5. 設定 Apache httpd

```bash
sudo cp deploy/httpd-kernel-cve.conf /etc/httpd/conf.d/kernel-cve-radar.conf
sudo vi /etc/httpd/conf.d/kernel-cve-radar.conf
```

將 `ServerName kernel-cve.example.com` 改為實際 FQDN。接著允許 httpd 連線到本機後端：

```bash
sudo setsebool -P httpd_can_network_connect 1
sudo apachectl configtest
sudo systemctl restart httpd
```

需要開放防火牆時：

```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --reload
```

HTTPS 範例位於 `deploy/httpd-kernel-cve-https.conf.example`。

## 使用 compose.yaml

適合測試環境：

```bash
cp .env.example .env
vi .env
mkdir -p data
podman compose up -d --build
```

`data/` 會保存 SQLite 資料庫。請勿提交 `.env` 與資料庫至 GitHub。

## 管理者帳號重設

Python 環境：

```bash
python manage.py create-admin admin
```

容器環境：

```bash
sudo podman exec -it kernel-cve-radar python manage.py create-admin admin
```

## 資料庫備份

SQLite 使用 WAL 模式，不建議直接在站台運作時用 `cp` 複製主資料庫。專案提供 SQLite backup API 腳本：

```bash
sudo ./scripts/backup-db.sh \
  /var/lib/kernel-cve-radar/kernel_cve.db \
  /var/backups/kernel-cve-radar
```

腳本預設保留 30 天，可搭配 systemd timer 或 cron。

## 操作紀錄

`activity_logs` 會記錄：

- 時間
- 來源 IP
- HTTP Method 與路徑
- 事件類型
- 使用者輸入摘要
- 作答結果
- User-Agent
- 執行操作的管理者帳號

密碼不會寫入操作紀錄。

`TRUST_PROXY_HEADERS=true` 僅適用於應用程式前方確實只有一層可信任反向代理的情境。不要把 Gunicorn 的 8000 port 直接對外開放，否則客戶端可能偽造 `X-Forwarded-For`。

## 測試

```bash
python -m unittest discover -s tests -p '*_test.py' -v
```

## 初始展示資料

專案內建以下 CVE：

- CVE-2026-31431 — Copy Fail
- CVE-2026-43284 — Dirty Frag
- CVE-2026-46300 — Fragnesia
- CVE-2026-46333 — Process Exit Race Condition
- CVE-2026-46243 — CIFSwitch

內容是展示用摘要。安全公告狀態與修補版本可能持續更新，正式判斷請以 Red Hat Product Security 資料為準。

## 安全注意事項

- 正式環境必須更換 `SECRET_KEY` 與預設管理者密碼。
- 建議使用 HTTPS，並設定 `SESSION_COOKIE_SECURE=true`。
- 不要直接將 8000 port 開放到外部網路。
- 定期備份 SQLite，並限制資料目錄與環境檔權限。
- 此站台不是漏洞掃描器，不會判斷某台主機是否實際受影響。
