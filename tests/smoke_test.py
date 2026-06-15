from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "StrongTestPassword123!"

from app import create_app


class AppSmokeTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        db_path = str(Path(self.tempdir.name) / "test.db")
        self.app = create_app({
            "TESTING": True,
            "DATABASE": db_path,
            "SECRET_KEY": "test-secret",
            "TRUST_PROXY_HEADERS": False,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def csrf(self):
        with self.client.session_transaction() as sess:
            token = sess.get("csrf_token", "test-csrf-token")
            sess["csrf_token"] = token
            return token

    def test_public_pages_and_admin_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CVE-2026-31431", response.data)

        response = self.client.get("/challenge")
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            "/admin/",
            data={
                "csrf_token": self.csrf(),
                "username": "admin",
                "password": "StrongTestPassword123!",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("管理後台".encode(), response.data)

        response = self.client.get("/admin/logs")
        self.assertEqual(response.status_code, 200)
        self.assertIn("操作紀錄".encode(), response.data)

    def test_health(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")


if __name__ == "__main__":
    unittest.main()
