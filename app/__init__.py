from __future__ import annotations

from flask import Flask, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from . import db
from .security import csrf_token, validate_csrf
from .seed import ensure_admin, seed_database


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    if app.config.get("TRUST_PROXY_HEADERS"):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    app.teardown_appcontext(db.close_db)
    app.jinja_env.globals["csrf_token"] = csrf_token

    from .public import bp as public_bp
    from .admin import bp as admin_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp)

    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            validate_csrf()

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
        )
        return response

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", code=400, message=str(error)), 400

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="找不到指定頁面。"), 404

    @app.errorhandler(500)
    def server_error(_error):
        return render_template("error.html", code=500, message="系統發生錯誤，請稍後再試。"), 500

    with app.app_context():
        db.init_db()
        seed_database()
        ensure_admin()

    return app
