import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError:
        return default


class Config:
    APP_VERSION = os.getenv(
        "APP_VERSION",
        (BASE_DIR / "VERSION").read_text(encoding="utf-8").strip()
        if (BASE_DIR / "VERSION").exists()
        else "unknown",
    )
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
    DATABASE = os.getenv("DATABASE_PATH", str(BASE_DIR / "instance" / "kernel_cve.db"))
    INITIAL_CREDENTIALS_FILE = os.getenv(
        "INITIAL_CREDENTIALS_FILE", str(BASE_DIR / "instance" / "initial-credentials.txt")
    )
    AUTH_EVENT_LOG_FILE = os.getenv(
        "AUTH_EVENT_LOG_FILE", str(BASE_DIR / "instance" / "auth-events.jsonl")
    )
    AUTH_EVENT_STDOUT = env_bool("AUTH_EVENT_STDOUT", True)
    TRUST_PROXY_HEADERS = env_bool("TRUST_PROXY_HEADERS", True)
    PROXY_FIX_X_FOR = max(1, env_int("PROXY_FIX_X_FOR", 1))
    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 8
