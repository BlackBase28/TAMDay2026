from __future__ import annotations

import argparse
import getpass

from werkzeug.security import generate_password_hash

from app import create_app
from app.db import execute, query_one


def main() -> None:
    parser = argparse.ArgumentParser(description="Kernel CVE Radar 管理工具")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-admin", help="新增或重設管理者")
    create.add_argument("username")
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        password = getpass.getpass("Password (minimum 12 characters): ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm or len(password) < 12:
            raise SystemExit("密碼不一致或少於 12 個字元。")
        existing = query_one("SELECT id FROM admins WHERE username=?", (args.username,))
        if existing:
            execute(
                "UPDATE admins SET password_hash=? WHERE id=?",
                (generate_password_hash(password), existing["id"]),
            )
            print(f"Administrator '{args.username}' updated.")
        else:
            execute(
                "INSERT INTO admins (username,password_hash) VALUES (?,?)",
                (args.username, generate_password_hash(password)),
            )
            print(f"Administrator '{args.username}' created.")


if __name__ == "__main__":
    main()
