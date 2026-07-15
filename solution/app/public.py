from __future__ import annotations

from flask import Blueprint, abort, current_app, redirect, render_template, session, url_for

from .auth_events import write_admin_access_event
from .db import query_all, query_one

bp = Blueprint("public", __name__)


def login_required():
    if not session.get("user_id"):
        return redirect(url_for("auth.login_form"))
    return None


@bp.get("/healthz")
def healthz():
    return {"status": "ok", "version": current_app.config["APP_VERSION"]}


@bp.get("/")
def index():
    guard = login_required()
    if guard:
        return guard
    cves = query_all(
        "SELECT cve_id, name, severity, status, attack_vector, subsystem, summary FROM cves WHERE enabled = 1 ORDER BY cve_id DESC"
    )
    return render_template("index.html", cves=cves)


@bp.get("/cve/<cve_id>")
def cve_detail(cve_id: str):
    guard = login_required()
    if guard:
        return guard
    cve = query_one("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
    if not cve:
        return render_template("error.html", code=404, message="找不到指定 CVE。"), 404
    return render_template("cve_detail.html", cve=cve)


@bp.get("/admin")
def admin_info():
    guard = login_required()
    if guard:
        return guard

    username = session.get("username", "-")
    role = session.get("role", "-")
    if role != "admin":
        write_admin_access_event(username, role, "denied")
        abort(403)

    write_admin_access_event(username, role, "allowed")
    users = query_all("SELECT username, display_name, role, enabled, last_login_at FROM users ORDER BY username")
    events = query_all("SELECT occurred_at, event_outcome, failure_reason, username_attempted, source_ip FROM auth_events ORDER BY id DESC LIMIT 30")
    return render_template("admin.html", users=users, events=events)
