from __future__ import annotations

import secrets
import string
from pathlib import Path
from flask import current_app
from werkzeug.security import generate_password_hash

from .db import get_db


CVES = [
    {
        "cve_id": "CVE-2026-31431",
        "name": "CopyFail",
        "severity": "Important",
        "status": "Tracking",
        "affected_versions": "RHEL 8 / 9 / 10 展示資料",
        "attack_vector": "Local",
        "subsystem": "Crypto / AF_ALG",
        "summary": "本機使用者可能透過 kernel copy 操作相關缺陷提升權限。",
        "impact": "若攻擊者已取得一般帳號，可能進一步取得較高權限。",
        "recommendation": "確認 Red Hat 官方說明與對應 RHSA，安排測試、更新與重開機。",
        "reference_url": "https://access.redhat.com/security/cve/",
    },
    {
        "cve_id": "CVE-2026-43284",
        "name": "Dirty Frag",
        "severity": "Important",
        "status": "Tracking",
        "affected_versions": "RHEL 9 / 10 展示資料",
        "attack_vector": "Network adjacent / packet path",
        "subsystem": "Networking",
        "summary": "網路封包處理路徑中的記憶體處理問題。",
        "impact": "對外或高流量服務需要優先追蹤。",
        "recommendation": "確認服務暴露面、套件狀態與修補公告。",
        "reference_url": "https://access.redhat.com/security/cve/",
    },
    {
        "cve_id": "CVE-2026-46300",
        "name": "Fragnesia",
        "severity": "Moderate",
        "status": "Tracking",
        "affected_versions": "RHEL 9 / 10 展示資料",
        "attack_vector": "Network",
        "subsystem": "Networking",
        "summary": "與網路 fragment 或封包處理相關的展示用 CVE。",
        "impact": "可能影響特定網路工作負載。",
        "recommendation": "確認實際服務使用情境，再安排更新。",
        "reference_url": "https://access.redhat.com/security/cve/",
    },
    {
        "cve_id": "CVE-2026-46333",
        "name": "ssh-keysign-pwn",
        "severity": "Important",
        "status": "Tracking",
        "affected_versions": "RHEL 展示資料",
        "attack_vector": "Local",
        "subsystem": "Process / Authentication helper",
        "summary": "與本機 helper 或 process exit race 相關的展示用 CVE。",
        "impact": "有本機帳號時風險較高。",
        "recommendation": "確認登入帳號控管與官方更新狀態。",
        "reference_url": "https://access.redhat.com/security/cve/",
    },
    {
        "cve_id": "CVE-2026-46243",
        "name": "CIFSwitch",
        "severity": "Important",
        "status": "Tracking",
        "affected_versions": "RHEL 展示資料",
        "attack_vector": "Network / module dependent",
        "subsystem": "CIFS / SMB client",
        "summary": "與 CIFS/SMB client 路徑相關的展示用 CVE。",
        "impact": "若主機有掛載不可信 SMB/CIFS 資源，風險需提高。",
        "recommendation": "確認 CIFS 模組及掛載情境。",
        "reference_url": "https://access.redhat.com/security/cve/",
    },
    {
        "cve_id": "CVE-2026-46331",
        "name": "Traffic Control Privilege Escalation",
        "severity": "Pending",
        "status": "New",
        "affected_versions": "待 Red Hat 官方確認",
        "attack_vector": "Local / capability dependent",
        "subsystem": "net/sched traffic control",
        "summary": "與 Linux Kernel Traffic Control pedit action 相關的展示用 CVE。",
        "impact": "具有特定本機權限或 capability 的使用者可能影響 kernel memory handling。",
        "recommendation": "以 Red Hat 官方說明為準，確認實際影響與修補建議。",
        "reference_url": "https://access.redhat.com/security/cve/",
    },
]


def random_password(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value):
            return value


def seed_database() -> None:
    db = get_db()
    for cve in CVES:
        db.execute(
            """
            INSERT INTO cves
              (cve_id, name, severity, status, affected_versions, attack_vector,
               subsystem, summary, impact, recommendation, reference_url)
            VALUES
              (:cve_id, :name, :severity, :status, :affected_versions, :attack_vector,
               :subsystem, :summary, :impact, :recommendation, :reference_url)
            ON CONFLICT(cve_id) DO NOTHING
            """,
            cve,
        )
    db.commit()


def ensure_initial_users() -> None:
    db = get_db()
    credentials: list[tuple[str, str, str]] = []

    defaults = [
        ("ADMIN_USERNAME", "ADMIN_PASSWORD", "admin", "admin", "系統管理員"),
        ("INITIAL_USER_USERNAME", "INITIAL_USER_PASSWORD", "user1", "user", "一般使用者"),
    ]
    for user_key, pass_key, default_username, role, display_name in defaults:
        username = current_app.config.get(user_key) or __import__("os").getenv(user_key, default_username)
        password = __import__("os").getenv(pass_key) or ""
        if not db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            if not password:
                password = random_password()
                credentials.append((username, password, role))
            db.execute(
                "INSERT INTO users (username, password_hash, display_name, role, enabled) VALUES (?, ?, ?, ?, 1)",
                (username, generate_password_hash(password), display_name, role),
            )
    db.commit()

    if credentials:
        path = Path(current_app.config["INITIAL_CREDENTIALS_FILE"])
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = ["Kernel CVE Radar initial credentials", ""]
        for username, password, role in credentials:
            lines.extend([f"Username: {username}", f"Password: {password}", f"Role: {role}", ""])
        path.write_text("\n".join(lines), encoding="utf-8")
        path.chmod(0o600)
