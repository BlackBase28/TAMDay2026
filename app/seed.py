from __future__ import annotations

from flask import current_app
from werkzeug.security import generate_password_hash

from .db import get_db


CVE_SEED = [
    {
        "cve_id": "CVE-2026-31431",
        "name": "Copy Fail",
        "severity": "Important",
        "status": "Resolved",
        "affected_versions": "RHEL 8 / 9 / 10",
        "attack_vector": "Local",
        "subsystem": "Cryptographic Interface",
        "summary": "Linux Kernel 密碼學介面的本機權限提升漏洞。具有本機低權限帳號的使用者可能觸發漏洞並取得 root 權限。",
        "impact": "多使用者主機、開發環境或允許互動式登入的系統風險較高。",
        "recommendation": "依 Red Hat CVE/RHSA 狀態安裝適用的 Kernel 更新；修補前可評估限制本機登入與相關介面，但需先確認業務影響。",
        "reboot_required": 1,
        "reference_url": "https://access.redhat.com/security/vulnerabilities/RHSB-2026-002",
        "published_date": "2026-04-30",
    },
    {
        "cve_id": "CVE-2026-43284",
        "name": "Dirty Frag",
        "severity": "Important",
        "status": "Ongoing",
        "affected_versions": "RHEL 8 / 9 / 10",
        "attack_vector": "Local",
        "subsystem": "IPsec ESP / Networking",
        "summary": "Linux Kernel IPsec ESP 網路子系統的本機權限提升漏洞，低權限本機使用者可能藉此取得 root 權限。",
        "impact": "使用 IPsec/VPN，或允許不受信任使用者在主機上執行程式的環境，應優先評估。",
        "recommendation": "確認 IPsec 模組與功能是否使用中，依 Red Hat 公告套用 Kernel 修補；任何模組停用措施都需先驗證 VPN 與站台互連影響。",
        "reboot_required": 1,
        "reference_url": "https://access.redhat.com/security/vulnerabilities/RHSB-2026-003",
        "published_date": "2026-05-07",
    },
    {
        "cve_id": "CVE-2026-46300",
        "name": "Fragnesia",
        "severity": "Important",
        "status": "Ongoing",
        "affected_versions": "RHEL 8 / 9 / 10",
        "attack_vector": "Local",
        "subsystem": "XFRM ESP-in-TCP",
        "summary": "Dirty Frag 相關變形，影響 Linux Kernel XFRM ESP-in-TCP，可能造成低權限本機使用者取得 root 權限。",
        "impact": "使用 IPsec/XFRM ESP-in-TCP 或具有不受信任本機使用者的主機需進一步確認。",
        "recommendation": "依 Red Hat 公告確認適用產品及修補，更新 Kernel 並安排重新開機；暫時緩解前先確認 IPsec 與 rootless container 相依性。",
        "reboot_required": 1,
        "reference_url": "https://access.redhat.com/security/vulnerabilities/RHSB-2026-003",
        "published_date": "2026-05-21",
    },
    {
        "cve_id": "CVE-2026-46333",
        "name": "Process Exit Race Condition",
        "severity": "Important",
        "status": "Ongoing",
        "affected_versions": "RHEL 8 / 9 / 10",
        "attack_vector": "Local",
        "subsystem": "Process / ptrace",
        "summary": "Linux Kernel 在程序結束期間的權限檢查競態問題，低權限使用者可能竊取特權程序的檔案描述符。",
        "impact": "可能接觸 root 擁有的敏感檔案、SSH 主機私鑰、/etc/shadow 或已驗證的 IPC 連線。",
        "recommendation": "套用適用的 Kernel 更新；若無法立即修補，可評估提高 kernel.yama.ptrace_scope，但需測試除錯及監控工具影響。",
        "reboot_required": 1,
        "reference_url": "https://access.redhat.com/security/vulnerabilities/RHSB-2026-004",
        "published_date": "2026-05-16",
    },
    {
        "cve_id": "CVE-2026-46243",
        "name": "CIFSwitch",
        "severity": "Important",
        "status": "Ongoing",
        "affected_versions": "RHEL 6 / 7 / 8 / 9 / 10",
        "attack_vector": "Local",
        "subsystem": "CIFS / SMB Client",
        "summary": "Linux Kernel CIFS/SMB client 與 cifs.upcall 攻擊鏈中的本機權限提升漏洞，低權限使用者可能執行 root 指令。",
        "impact": "同時具備 CIFS 模組、cifs-utils 與 cifs.spnego request-key 規則的系統需要優先檢查。",
        "recommendation": "依 Red Hat 公告套用 Kernel 修補；不使用 SMB/CIFS client 的主機可評估停用 cifs 模組或移除相關元件，但會中斷 SMB 掛載。",
        "reboot_required": 1,
        "reference_url": "https://access.redhat.com/security/vulnerabilities/RHSB-2026-005",
        "published_date": "2026-05-29",
    },
]


SCENARIO_SEED = [
    {
        "title": "對外 Web Server 的本機風險",
        "description": "RHEL 9 對外提供 HTTP/HTTPS；不使用 CIFS，也沒有 IPsec VPN；僅少數維運人員可 SSH 登入。哪一項資訊最值得優先確認？",
        "options": ["CVE-2026-46333", "CVE-2026-46243", "CVE-2026-43284", "CVE-2026-46300"],
        "correct": "CVE-2026-46333",
        "explanation": "題目中沒有 CIFS 或 IPsec 使用情境；程序結束競態漏洞仍可能由具低權限本機登入能力的帳號觸發，因此應先確認 Kernel 修補狀態與 ptrace 限制。",
    },
    {
        "title": "檔案伺服器使用 Windows 分享",
        "description": "RHEL 8 主機掛載多個 AD 環境的 SMB 分享，已安裝 cifs-utils 並載入 cifs 模組，也允許維運帳號登入。哪一個 CVE 最直接符合此情境？",
        "options": ["CVE-2026-31431", "CVE-2026-46243", "CVE-2026-46333", "CVE-2026-43284"],
        "correct": "CVE-2026-46243",
        "explanation": "CIFSwitch 的攻擊鏈與 CIFS 模組、cifs-utils 及 cifs.spnego 規則有關。本機仍需依 Red Hat 公告確認實際套件與 Kernel 修補狀態。",
    },
    {
        "title": "IPsec Site-to-Site VPN Gateway",
        "description": "RHEL 9 主機使用 IPsec 建立站台對站台 VPN，esp4/esp6 模組載入中，且主機有多位維運使用者。哪一個 CVE 最符合 IPsec ESP 風險？",
        "options": ["CVE-2026-43284", "CVE-2026-46243", "CVE-2026-31431", "CVE-2026-46333"],
        "correct": "CVE-2026-43284",
        "explanation": "Dirty Frag CVE-2026-43284 影響 IPsec ESP。此環境不能直接封鎖 esp4/esp6，應優先評估 Kernel 更新並安排維護時段。",
    },
    {
        "title": "不使用 SMB 的批次運算節點",
        "description": "RHEL 10 運算節點不掛載 SMB 分享，也未安裝 cifs-utils。對 CIFSwitch 的合理初步處理為何？",
        "options": ["CVE-2026-31431", "CVE-2026-46243", "CVE-2026-46333", "CVE-2026-43284"],
        "correct": "CVE-2026-46243",
        "explanation": "沒有 Windows file server/CIFS 使用需求時，攻擊鏈可能不完整，但仍應確認元件與 Red Hat 修補狀態。此題正確選項是『確認 cifs 攻擊鏈元件不存在並持續追蹤修補』。",
        "custom_labels": {
            "CVE-2026-31431": "立即停用 HTTP",
            "CVE-2026-46243": "確認 cifs 攻擊鏈元件不存在並持續追蹤修補",
            "CVE-2026-46333": "更換主機 IP",
            "CVE-2026-43284": "停用所有使用者帳號",
        },
    },
]


def seed_database() -> None:
    db = get_db()
    if db.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 0:
        for item in CVE_SEED:
            db.execute(
                """
                INSERT INTO cves
                (cve_id, name, severity, status, affected_versions, attack_vector,
                 subsystem, summary, impact, recommendation, reboot_required,
                 reference_url, published_date)
                VALUES (:cve_id, :name, :severity, :status, :affected_versions,
                        :attack_vector, :subsystem, :summary, :impact,
                        :recommendation, :reboot_required, :reference_url,
                        :published_date)
                """,
                item,
            )
        db.commit()

    if db.execute("SELECT COUNT(*) FROM scenarios").fetchone()[0] == 0:
        cve_map = {row["cve_id"]: row["id"] for row in db.execute("SELECT id, cve_id FROM cves")}
        for scenario in SCENARIO_SEED:
            cur = db.execute(
                "INSERT INTO scenarios (title, description, explanation) VALUES (?, ?, ?)",
                (scenario["title"], scenario["description"], scenario["explanation"]),
            )
            scenario_id = cur.lastrowid
            custom = scenario.get("custom_labels", {})
            for order, cve_id in enumerate(scenario["options"]):
                db.execute(
                    """
                    INSERT INTO scenario_options
                    (scenario_id, cve_id, label, is_correct, sort_order)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        scenario_id,
                        cve_map[cve_id],
                        custom.get(cve_id, cve_id),
                        1 if cve_id == scenario["correct"] else 0,
                        order,
                    ),
                )
        db.commit()


def ensure_admin() -> None:
    import os

    db = get_db()
    if db.execute("SELECT COUNT(*) FROM admins").fetchone()[0] > 0:
        return
    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")
    if username and password:
        db.execute(
            "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
            (username.strip(), generate_password_hash(password)),
        )
        db.commit()
        current_app.logger.warning("Initial administrator '%s' created from environment.", username)
    else:
        current_app.logger.warning(
            "No administrator exists. Set ADMIN_USERNAME and ADMIN_PASSWORD, then restart once."
        )
