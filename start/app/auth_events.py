from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from flask import current_app, request

from .client_ip import first_forwarded_for, source_ip
from .db import get_db


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_auth_event(outcome: str, username: str, reason: str | None = None) -> None:
    ts = now_utc()
    ip = source_ip()
    path = request.path
    event = {
        "ts": ts,
        "outcome": outcome,
        "user": username or "-",
        "ip": ip,
        "path": path,
    }
    if reason:
        event["reason"] = reason

    # Keep JSONL intentionally short for EDA and AI context limits.
    log_path = Path(current_app.config["AUTH_EVENT_LOG_FILE"])
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fileobj:
        fileobj.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")

    if current_app.config.get("AUTH_EVENT_STDOUT", True):
        print("AUTH_EVENT " + json.dumps(event, ensure_ascii=False, separators=(",", ":")), file=sys.stdout, flush=True)

    try:
        get_db().execute(
            """
            INSERT INTO auth_events
              (occurred_at, event_outcome, failure_reason, username_attempted, source_ip, http_path)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (ts, outcome, reason, username or "-", ip, path),
        )
        get_db().commit()
    except Exception:
        # JSONL is the primary signal path; do not break login if the DB is old.
        current_app.logger.exception("failed to store auth event")



def write_admin_access_event(username: str, role: str, result: str = "allowed") -> None:
    ts = now_utc()
    ip = source_ip()
    path = request.path
    event = {
        "ts": ts,
        "event": "admin_access",
        "user": username or "-",
        "role": role or "-",
        "ip": ip,
        "path": path,
        "result": result,
    }

    # Keep JSONL intentionally short for EDA and AI context limits.
    log_path = Path(current_app.config["AUTH_EVENT_LOG_FILE"])
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fileobj:
        fileobj.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")

    if current_app.config.get("AUTH_EVENT_STDOUT", True):
        print("AUTH_EVENT " + json.dumps(event, ensure_ascii=False, separators=(",", ":")), file=sys.stdout, flush=True)

    try:
        get_db().execute(
            """
            INSERT INTO auth_events
              (occurred_at, event_outcome, failure_reason, username_attempted, source_ip, http_path)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (ts, "admin_access", result, username or "-", ip, path),
        )
        get_db().commit()
    except Exception:
        current_app.logger.exception("failed to store admin access event")


def forwarded_for_value() -> str:
    return first_forwarded_for() or ""
