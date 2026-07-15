from __future__ import annotations

from flask import Flask, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from . import db
from .seed import ensure_initial_users, seed_database


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    if app.config.get("TRUST_PROXY_HEADERS"):
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=int(app.config.get("PROXY_FIX_X_FOR", 1)),
            x_proto=1,
            x_host=1,
            x_port=1,
        )

    app.teardown_appcontext(db.close_db)

    from .auth import bp as auth_bp
    from .public import bp as public_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(public_bp)

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="權限不足，無法存取此頁面。"), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="找不到指定頁面。"), 404

    @app.errorhandler(500)
    def server_error(_error):
        return render_template("error.html", code=500, message="系統發生錯誤，請稍後再試。"), 500

    with app.app_context():
        db.init_db()
        seed_database()
        ensure_initial_users()

    return app
