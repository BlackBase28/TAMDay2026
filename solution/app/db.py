from __future__ import annotations

import sqlite3
from pathlib import Path
from flask import current_app, g


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        db_path = Path(current_app.config["DATABASE"])
        db_path.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA busy_timeout=5000")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


def close_db(_error=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    schema = Path(current_app.root_path).parent / "schema.sql"
    get_db().executescript(schema.read_text(encoding="utf-8"))
    get_db().commit()


def query_one(sql: str, args: tuple = ()):
    return get_db().execute(sql, args).fetchone()


def query_all(sql: str, args: tuple = ()):
    return get_db().execute(sql, args).fetchall()
