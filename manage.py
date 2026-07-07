from __future__ import annotations

import argparse
import getpass
from werkzeug.security import generate_password_hash

from app import create_app
from app.db import get_db, query_one


def main() -> None:
    parser = argparse.ArgumentParser(description="Kernel CVE Radar account helper")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create-user", help="create or reset a user")
    create.add_argument("username")
    create.add_argument("--role", choices=["user", "admin"], default="user")
    create.add_argument("--display-name", default="")
    create.add_argument("--disabled", action="store_true")

    disable = sub.add_parser("disable-user", help="disable a user login")
    disable.add_argument("username")

    enable = sub.add_parser("enable-user", help="enable a user login")
    enable.add_argument("username")

    args = parser.parse_args()
    app = create_app()
    with app.app_context():
        if args.command in {"disable-user", "enable-user"}:
            enabled = 0 if args.command == "disable-user" else 1
            get_db().execute("UPDATE users SET enabled = ? WHERE username = ?", (enabled, args.username))
            get_db().commit()
            print(f"{args.username} enabled={enabled}")
            return

        password = getpass.getpass("Password (minimum 12 characters): ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm or len(password) < 12:
            raise SystemExit("密碼不一致或少於 12 個字元。")

        display_name = args.display_name or args.username
        enabled = 0 if args.disabled else 1
        existing = query_one("SELECT id FROM users WHERE username = ?", (args.username,))
        if existing:
            get_db().execute(
                "UPDATE users SET password_hash=?, role=?, display_name=?, enabled=? WHERE id=?",
                (generate_password_hash(password), args.role, display_name, enabled, existing["id"]),
            )
            print(f"updated {args.username} as {args.role}")
        else:
            get_db().execute(
                "INSERT INTO users (username, password_hash, display_name, role, enabled) VALUES (?, ?, ?, ?, ?)",
                (args.username, generate_password_hash(password), display_name, args.role, enabled),
            )
            print(f"created {args.username} as {args.role}")
        get_db().commit()


if __name__ == "__main__":
    main()
