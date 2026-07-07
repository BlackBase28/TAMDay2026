# Changelog

## 2.7.3

- Added compact `admin_access` event logging when any logged-in user opens `/admin`.
- This makes the intentional pre-fix condition directly visible to EDA/AI: `user1` with role `user` can access `/admin`.

## 2.7.2

- 移除登入後首頁的展示情境說明卡片。
- 移除 Admin 頁面的修復前狀態提示文字，僅保留資訊表格。

## 2.7.1

- 移除登入首頁「修復前展示站台」說明文字，保留簡化登入畫面。

## 2.7.0

- 大幅簡化網站功能，只保留登入、CVE 資訊展示、Admin 資訊展示與健康檢查。
- 移除 CVE CRUD、情境挑戰互動、個人紀錄、密碼修改與複雜管理功能。
- 保留修復前狀態：`user1` 可存取 `/admin`。
- `auth-events.jsonl` 改為精簡 JSON，降低 EDA 與 AI context 長度。
- 保留 httpd 前端維護頁切換設定。
