from __future__ import annotations

import csv
import io
from datetime import datetime

from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .db import execute, get_db, query_all, query_one
from .logging_utils import log_activity
from .security import admin_required, is_safe_redirect

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _checkbox(name: str) -> int:
    return 1 if request.form.get(name) == "on" else 0


def _cve_form_values() -> dict:
    return {
        "cve_id": request.form.get("cve_id", "").strip().upper(),
        "name": request.form.get("name", "").strip(),
        "severity": request.form.get("severity", "Important").strip(),
        "status": request.form.get("status", "Ongoing").strip(),
        "affected_versions": request.form.get("affected_versions", "").strip(),
        "attack_vector": request.form.get("attack_vector", "Local").strip(),
        "subsystem": request.form.get("subsystem", "").strip(),
        "summary": request.form.get("summary", "").strip(),
        "impact": request.form.get("impact", "").strip(),
        "recommendation": request.form.get("recommendation", "").strip(),
        "reboot_required": _checkbox("reboot_required"),
        "reference_url": request.form.get("reference_url", "").strip(),
        "published_date": request.form.get("published_date", "").strip(),
        "enabled": _checkbox("enabled"),
    }


def _validate_cve(values: dict) -> list[str]:
    errors = []
    required = ["cve_id", "name", "affected_versions", "subsystem", "summary", "impact", "recommendation"]
    for field in required:
        if not values[field]:
            errors.append(f"欄位 {field} 不可空白。")
    if values["cve_id"] and not values["cve_id"].startswith("CVE-"):
        errors.append("CVE ID 格式應以 CVE- 開頭。")
    if values["reference_url"] and not values["reference_url"].startswith(("https://", "http://")):
        errors.append("參考網址必須以 http:// 或 https:// 開頭。")
    return errors


@bp.route("/", methods=["GET", "POST"])
def login():
    if session.get("admin_id"):
        return redirect(url_for("admin.dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        admin = query_one("SELECT * FROM admins WHERE username=?", (username,))
        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]
            session.permanent = True
            execute(
                "UPDATE admins SET last_login_at=datetime('now', 'localtime') WHERE id=?",
                (admin["id"],),
            )
            log_activity("admin_login", {"username": username}, "success")
            next_url = request.args.get("next")
            if is_safe_redirect(next_url):
                return redirect(next_url)
            return redirect(url_for("admin.dashboard"))
        log_activity("admin_login", {"username": username}, "failed")
        flash("帳號或密碼錯誤。", "danger")
    return render_template("admin/login.html")


@bp.post("/logout")
@admin_required
def logout():
    log_activity("admin_logout", None, "success")
    session.clear()
    flash("已登出管理者介面。", "success")
    return redirect(url_for("admin.login"))


@bp.get("/dashboard")
@admin_required
def dashboard():
    stats = query_one(
        """
        SELECT
          (SELECT COUNT(*) FROM cves) AS cves,
          (SELECT COUNT(*) FROM scenarios) AS scenarios,
          (SELECT COUNT(*) FROM activity_logs WHERE date(created_at)=date('now','localtime')) AS today_logs,
          (SELECT COUNT(DISTINCT ip_address) FROM activity_logs WHERE date(created_at)=date('now','localtime')) AS today_ips,
          (SELECT COUNT(*) FROM activity_logs WHERE action='submit_challenge' AND result='correct') AS correct,
          (SELECT COUNT(*) FROM activity_logs WHERE action='submit_challenge') AS attempts
        """
    )
    recent = query_all("SELECT * FROM activity_logs ORDER BY id DESC LIMIT 10")
    return render_template("admin/dashboard.html", stats=stats, recent=recent)


@bp.get("/cves")
@admin_required
def cves():
    rows = query_all("SELECT * FROM cves ORDER BY published_date DESC, id DESC")
    return render_template("admin/cves.html", cves=rows)


@bp.route("/cves/new", methods=["GET", "POST"])
@admin_required
def cve_new():
    values = {"severity": "Important", "status": "Ongoing", "attack_vector": "Local", "enabled": 1, "reboot_required": 1}
    if request.method == "POST":
        values = _cve_form_values()
        errors = _validate_cve(values)
        if not errors:
            try:
                db = get_db()
                cur = db.execute(
                    """
                    INSERT INTO cves
                    (cve_id,name,severity,status,affected_versions,attack_vector,subsystem,
                     summary,impact,recommendation,reboot_required,reference_url,published_date,enabled)
                    VALUES (:cve_id,:name,:severity,:status,:affected_versions,:attack_vector,:subsystem,
                            :summary,:impact,:recommendation,:reboot_required,:reference_url,:published_date,:enabled)
                    """,
                    values,
                )
                db.commit()
                pk = cur.lastrowid
            except Exception:
                db.rollback()
                errors.append("無法新增，請確認 CVE ID 是否重複。")
            else:
                log_activity("admin_create_cve", values["cve_id"], f"id={pk}")
                flash("CVE 已新增。", "success")
                return redirect(url_for("admin.cves"))
        for error in errors:
            flash(error, "danger")
    return render_template("admin/cve_form.html", cve=values, title="新增 CVE")


@bp.route("/cves/<int:cve_pk>/edit", methods=["GET", "POST"])
@admin_required
def cve_edit(cve_pk: int):
    cve = query_one("SELECT * FROM cves WHERE id=?", (cve_pk,))
    if not cve:
        abort(404)
    values = dict(cve)
    if request.method == "POST":
        values = _cve_form_values()
        errors = _validate_cve(values)
        if not errors:
            db = get_db()
            try:
                db.execute(
                    """
                    UPDATE cves SET
                    cve_id=:cve_id,name=:name,severity=:severity,status=:status,
                    affected_versions=:affected_versions,attack_vector=:attack_vector,
                    subsystem=:subsystem,summary=:summary,impact=:impact,
                    recommendation=:recommendation,reboot_required=:reboot_required,
                    reference_url=:reference_url,published_date=:published_date,enabled=:enabled,
                    updated_at=datetime('now','localtime')
                    WHERE id=:id
                    """,
                    {**values, "id": cve_pk},
                )
                db.commit()
            except Exception:
                db.rollback()
                errors.append("無法儲存，請確認 CVE ID 是否重複。")
            else:
                log_activity("admin_edit_cve", values["cve_id"], f"id={cve_pk}")
                flash("CVE 已更新。", "success")
                return redirect(url_for("admin.cves"))
        for error in errors:
            flash(error, "danger")
    return render_template("admin/cve_form.html", cve=values, title="編輯 CVE")


@bp.post("/cves/<int:cve_pk>/delete")
@admin_required
def cve_delete(cve_pk: int):
    cve = query_one("SELECT * FROM cves WHERE id=?", (cve_pk,))
    if not cve:
        abort(404)
    linked = query_one("SELECT COUNT(*) AS n FROM scenario_options WHERE cve_id=?", (cve_pk,))["n"]
    if linked:
        flash("此 CVE 已被情境題目使用，請先停用或移除相關題目。", "warning")
    else:
        execute("DELETE FROM cves WHERE id=?", (cve_pk,))
        log_activity("admin_delete_cve", cve["cve_id"], "deleted")
        flash("CVE 已刪除。", "success")
    return redirect(url_for("admin.cves"))


@bp.get("/scenarios")
@admin_required
def scenarios():
    rows = query_all(
        """
        SELECT s.*, COUNT(so.id) AS option_count
        FROM scenarios s LEFT JOIN scenario_options so ON so.scenario_id=s.id
        GROUP BY s.id ORDER BY s.id DESC
        """
    )
    return render_template("admin/scenarios.html", scenarios=rows)


def _scenario_editor(scenario_id: int | None = None):
    cves = query_all("SELECT id,cve_id,name FROM cves ORDER BY cve_id")
    scenario = query_one("SELECT * FROM scenarios WHERE id=?", (scenario_id,)) if scenario_id else None
    options = query_all("SELECT * FROM scenario_options WHERE scenario_id=? ORDER BY sort_order", (scenario_id,)) if scenario_id else []

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        explanation = request.form.get("explanation", "").strip()
        enabled = _checkbox("enabled")
        selected_cves = request.form.getlist("option_cve_id")
        labels = request.form.getlist("option_label")
        correct_index = request.form.get("correct_index", type=int)
        errors = []
        if not title or not description or not explanation:
            errors.append("標題、情境與解答說明不可空白。")
        if len(selected_cves) < 2 or len(selected_cves) != len(labels) or not all(selected_cves):
            errors.append("至少需要兩個有效選項。")
        if len(set(selected_cves)) != len(selected_cves):
            errors.append("同一題不可重複選擇相同 CVE。")
        if correct_index is None or correct_index < 0 or correct_index >= len(selected_cves):
            errors.append("請設定正確答案。")
        if not all(label.strip() for label in labels):
            errors.append("選項顯示文字不可空白。")
        if not errors:
            db = get_db()
            if scenario_id:
                db.execute(
                    """UPDATE scenarios SET title=?,description=?,explanation=?,enabled=?,
                       updated_at=datetime('now','localtime') WHERE id=?""",
                    (title, description, explanation, enabled, scenario_id),
                )
                db.execute("DELETE FROM scenario_options WHERE scenario_id=?", (scenario_id,))
                saved_id = scenario_id
                action = "admin_edit_scenario"
            else:
                cur = db.execute(
                    "INSERT INTO scenarios (title,description,explanation,enabled) VALUES (?,?,?,?)",
                    (title, description, explanation, enabled),
                )
                saved_id = cur.lastrowid
                action = "admin_create_scenario"
            for index, (cve_id, label) in enumerate(zip(selected_cves, labels)):
                db.execute(
                    """INSERT INTO scenario_options
                       (scenario_id,cve_id,label,is_correct,sort_order) VALUES (?,?,?,?,?)""",
                    (saved_id, int(cve_id), label.strip(), 1 if index == correct_index else 0, index),
                )
            db.commit()
            log_activity(action, {"title": title}, f"id={saved_id}")
            flash("情境題目已儲存。", "success")
            return redirect(url_for("admin.scenarios"))
        for error in errors:
            flash(error, "danger")
        scenario = {"title": title, "description": description, "explanation": explanation, "enabled": enabled}
        options = [
            {"cve_id": int(cve_id), "label": label, "is_correct": 1 if i == correct_index else 0}
            for i, (cve_id, label) in enumerate(zip(selected_cves, labels))
        ]
    return render_template("admin/scenario_form.html", scenario=scenario or {"enabled": 1}, options=options, cves=cves)


@bp.route("/scenarios/new", methods=["GET", "POST"])
@admin_required
def scenario_new():
    return _scenario_editor()


@bp.route("/scenarios/<int:scenario_id>/edit", methods=["GET", "POST"])
@admin_required
def scenario_edit(scenario_id: int):
    if not query_one("SELECT id FROM scenarios WHERE id=?", (scenario_id,)):
        abort(404)
    return _scenario_editor(scenario_id)


@bp.post("/scenarios/<int:scenario_id>/delete")
@admin_required
def scenario_delete(scenario_id: int):
    scenario = query_one("SELECT * FROM scenarios WHERE id=?", (scenario_id,))
    if not scenario:
        abort(404)
    execute("DELETE FROM scenarios WHERE id=?", (scenario_id,))
    log_activity("admin_delete_scenario", scenario["title"], "deleted")
    flash("情境題目已刪除。", "success")
    return redirect(url_for("admin.scenarios"))


@bp.get("/logs")
@admin_required
def logs():
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()
    ip = request.args.get("ip", "").strip()
    action = request.args.get("action", "").strip()
    result = request.args.get("result", "").strip()
    clauses = ["1=1"]
    params: list[str] = []
    if date_from:
        clauses.append("date(created_at) >= date(?)")
        params.append(date_from)
    if date_to:
        clauses.append("date(created_at) <= date(?)")
        params.append(date_to)
    if ip:
        clauses.append("ip_address LIKE ?")
        params.append(f"%{ip}%")
    if action:
        clauses.append("action = ?")
        params.append(action)
    if result:
        clauses.append("result LIKE ?")
        params.append(f"%{result}%")
    rows = query_all(
        f"SELECT * FROM activity_logs WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT 1000",
        params,
    )
    actions = query_all("SELECT DISTINCT action FROM activity_logs ORDER BY action")
    return render_template("admin/logs.html", logs=rows, actions=actions)


@bp.get("/logs/export.csv")
@admin_required
def logs_export():
    rows = query_all("SELECT * FROM activity_logs ORDER BY id DESC LIMIT 10000")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["時間", "IP", "Method", "Path", "Action", "Input", "Result", "User-Agent", "Admin"])
    for row in rows:
        writer.writerow([
            row["created_at"], row["ip_address"], row["method"], row["path"], row["action"],
            row["input_data"], row["result"], row["user_agent"], row["admin_username"],
        ])
    log_activity("admin_export_logs", None, f"{len(rows)} rows")
    filename = f"kernel-cve-logs-{datetime.now():%Y%m%d-%H%M%S}.csv"
    return Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@bp.route("/password", methods=["GET", "POST"])
@admin_required
def password():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        admin = query_one("SELECT * FROM admins WHERE id=?", (session["admin_id"],))
        if not admin or not check_password_hash(admin["password_hash"], current):
            flash("目前密碼不正確。", "danger")
        elif len(new) < 12:
            flash("新密碼至少需要 12 個字元。", "danger")
        elif new != confirm:
            flash("兩次輸入的新密碼不一致。", "danger")
        else:
            execute("UPDATE admins SET password_hash=? WHERE id=?", (generate_password_hash(new), admin["id"]))
            log_activity("admin_change_password", None, "success")
            flash("密碼已更新。", "success")
            return redirect(url_for("admin.dashboard"))
    return render_template("admin/password.html")
