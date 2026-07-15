from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from .auth_events import write_auth_event
from .db import get_db

bp = Blueprint("auth", __name__)


@bp.get("/login")
def login_form():
    if session.get("user_id"):
        return redirect(url_for("public.index"))
    return render_template("login.html")


@bp.post("/login")
def login_submit():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        write_auth_event("fail", username, "unknown_user")
        flash("帳號或密碼錯誤。", "error")
        return render_template("login.html"), 401

    if int(user["enabled"]) != 1:
        write_auth_event("fail", username, "disabled")
        flash("帳號或密碼錯誤。", "error")
        return render_template("login.html"), 401

    if not check_password_hash(user["password_hash"], password):
        write_auth_event("fail", username, "bad_password")
        flash("帳號或密碼錯誤。", "error")
        return render_template("login.html"), 401

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    get_db().execute("UPDATE users SET last_login_at = datetime('now', 'localtime') WHERE id = ?", (user["id"],))
    get_db().commit()
    write_auth_event("success", username)
    return redirect(url_for("public.index"))


@bp.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login_form"))
