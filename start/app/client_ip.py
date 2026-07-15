from __future__ import annotations

from flask import request


def first_forwarded_for() -> str | None:
    value = request.headers.get("X-Forwarded-For", "")
    if not value:
        return None
    for part in value.split(","):
        ip = part.strip()
        if ip:
            return ip
    return None


def source_ip() -> str:
    # ProxyFix should normally set request.remote_addr to the client IP.  The
    # fallback keeps the demo useful in cloud environments where the old runtime
    # has not yet picked up proxy settings.
    if request.remote_addr and not request.remote_addr.startswith("10.88."):
        return request.remote_addr
    return first_forwarded_for() or request.remote_addr or "unknown"
