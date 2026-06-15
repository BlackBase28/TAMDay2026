from __future__ import annotations

import json
from typing import Any

from flask import request, session

from .db import execute


def _clean(value: Any, limit: int = 1500) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, default=str)
    value = value.replace("\x00", "")
    return value[:limit]


def log_activity(action: str, input_data: Any = None, result: Any = None) -> None:
    execute(
        """
        INSERT INTO activity_logs
        (ip_address, method, path, action, input_data, result, user_agent, admin_username)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request.remote_addr or "unknown",
            request.method,
            request.path[:300],
            action[:100],
            _clean(input_data),
            _clean(result),
            (request.user_agent.string or "")[:500],
            session.get("admin_username"),
        ),
    )
