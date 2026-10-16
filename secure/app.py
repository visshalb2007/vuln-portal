"""
SECURE VERSION - College Club Portal
Fixes the vulnerabilities present in vulnerable/:
  1. IDOR on /profile/<id>        -> ownership + role check
  2. SQL Injection on /login      -> parameterized queries
  3. Broken access control /admin -> server-side role check (decorator)
"""
from flask import Flask, request, session, redirect, url_for, render_template, g, abort, current_app
from functools import wraps
from datetime import datetime, timedelta, timezone
import sqlite3, os, logging
from werkzeug.security import check_password_hash, generate_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

from secure.config import Config, TestingConfig
from secure.db import get_db, close_db, init_db, DB_FALLBACK as DB

audit_logger = logging.getLogger("secure.audit")

DUMMY_PASSWORD_HASH = generate_password_hash("timing_equalization_secret")

csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
    strategy="fixed-window",
)


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        db = get_db()
        user = db.execute("SELECT id, username, role FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not user:
            session.clear()
            return redirect(url_for("login"))
        session["role"] = user["role"]
        g.user = user
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        db = get_db()
        user = db.execute("SELECT id, username, role FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not user:
            session.clear()
            return redirect(url_for("login"))
        session["role"] = user["role"]
        g.user = user
        if user["role"] != "admin":
            abort(403)
        return f(*a, **kw)
    return wrapper


def create_app(config=None):
    app = Flask(__name__)

    if config is None:
        is_testing = os.environ.get("TESTING", "").lower() in ("true", "1") or os.environ.get("FLASK_ENV") == "testing"
        config = TestingConfig if is_testing else Config

    if isinstance(config, (type, str)):
        app.config.from_object(config)
    elif isinstance(config, dict):
        app.config.from_mapping(config)
    else:
        app.config.from_object(config)

    Config.check_valid(app.config)

    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")

    csrf.init_app(app)
    limiter.init_app(app)
    app.teardown_appcontext(close_db)

    @app.before_request
    def check_idle_timeout():
        if "user_id" in session:
            now = datetime.now(timezone.utc).timestamp()
            last_active = session.get("_last_active")
            max_idle = app.permanent_session_lifetime.total_seconds()
            if last_active and (now - last_active > max_idle):
                session.clear()
                if request.endpoint and request.endpoint not in ("login", "static"):
                    return redirect(url_for("login"))
            else:
                session["_last_active"] = now

    # ---------- FIX #2: parameterized query + hashed password check ----------
    # BONUS: Rate limiting on login attempts (5 per minute per IP)
    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def login():
        if request.method == "POST":
            username = request.form["username"]
            password = request.form["password"]
            ip_addr = request.remote_addr or "127.0.0.1"
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

            attempt_row = db.execute(
                "SELECT * FROM login_attempts WHERE username = ? AND ip_address = ?",
                (username, ip_addr)
            ).fetchone()

            is_locked = False
            if attempt_row and attempt_row["locked_until"]:
                try:
                    locked_until = datetime.fromisoformat(attempt_row["locked_until"])
                    if locked_until.tzinfo is None:
                        locked_until = locked_until.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) < locked_until:
                        is_locked = True
                    else:
                        db.execute("UPDATE login_attempts SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                                   (attempt_row["id"],))
                        db.commit()
                        attempt_row = db.execute("SELECT * FROM login_attempts WHERE id = ?",
                                                 (attempt_row["id"],)).fetchone()
                except (ValueError, TypeError):
                    pass

            if user and not is_locked:
                if check_password_hash(user["password"], password):
                    if attempt_row:
                        db.execute("UPDATE login_attempts SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                                   (attempt_row["id"],))
                        db.commit()
                    session.clear()
                    session.permanent = True
                    session["user_id"] = user["id"]
                    session["role"] = user["role"]
                    session["username"] = user["username"]
                    session["_last_active"] = datetime.now(timezone.utc).timestamp()
                    audit_logger.info("SECURITY AUDIT: event=login_success username=%s user_id=%s ip=%s", user["username"], user["id"], ip_addr)
                    return redirect(url_for("dashboard"))
                else:
                    failed = ((attempt_row["failed_attempts"] if attempt_row else 0) or 0) + 1
                    if failed >= 5:
                        backoff_mins = min(60, 5 * (2 ** (failed - 5)))
                        lock_until = (datetime.now(timezone.utc) + timedelta(minutes=backoff_mins)).isoformat()
                        if attempt_row:
                            db.execute("UPDATE login_attempts SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                                       (failed, lock_until, attempt_row["id"]))
                        else:
                            db.execute(
                                "INSERT INTO login_attempts (username, ip_address, failed_attempts, locked_until) "
                                "VALUES (?, ?, ?, ?)",
                                (username, ip_addr, failed, lock_until)
                            )
                        audit_logger.warning("SECURITY AUDIT: event=lockout username=%s ip=%s", username, ip_addr)
                    else:
                        if attempt_row:
                            db.execute("UPDATE login_attempts SET failed_attempts = ? WHERE id = ?",
                                       (failed, attempt_row["id"]))
                        else:
                            db.execute(
                                "INSERT INTO login_attempts (username, ip_address, failed_attempts) VALUES (?, ?, ?)",
                                (username, ip_addr, failed)
                            )
                        audit_logger.warning("SECURITY AUDIT: event=login_failure username=%s ip=%s", username, ip_addr)
                    db.commit()
                    return render_template("login.html", error="Invalid credentials")
            elif user and is_locked:
                check_password_hash(user["password"], password)
                audit_logger.warning("SECURITY AUDIT: event=lockout username=%s ip=%s", username, ip_addr)
                return render_template("login.html", error="Invalid credentials")
            else:
                check_password_hash(DUMMY_PASSWORD_HASH, password)
                audit_logger.warning("SECURITY AUDIT: event=login_failure username=%s ip=%s", username, ip_addr)
                return render_template("login.html", error="Invalid credentials")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        user_id = session.get("user_id")
        username = session.get("username")
        ip_addr = request.remote_addr or "127.0.0.1"
        audit_logger.info("SECURITY AUDIT: event=logout username=%s user_id=%s ip=%s", username, user_id, ip_addr)
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def dashboard():
        db = get_db()
        events = db.execute("SELECT * FROM events").fetchall()
        return render_template("dashboard.html", events=events, role=session.get("role"), my_id=session.get("user_id"))

    # ---------- FIX #1: ownership/role check stops IDOR ----------
    @app.route("/profile/<int:user_id>")
    @login_required
    def profile(user_id):
        if session.get("role") != "admin" and session.get("user_id") != user_id:
            abort(403)  # FIXED: can only view own profile unless admin
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return "User not found", 404
        return render_template("profile.html", user=user)

    # ---------- FIX #3: server-side role check via decorator ----------
    @app.route("/admin/users")
    @admin_required
    def admin_users():
        db = get_db()
        # FIXED: never expose password hashes to the view
        users = db.execute("SELECT id, username, role, email FROM users").fetchall()
        return render_template("admin_users.html", users=users)

    @app.errorhandler(403)
    def forbidden(e):
        user_id = session.get("user_id")
        ip_addr = request.remote_addr or "127.0.0.1"
        audit_logger.warning("SECURITY AUDIT: event=403_forbidden user_id=%s path=%s ip=%s", user_id, request.path, ip_addr)
        return render_template("403.html"), 403

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return render_template("login.html", error="Too many requests. Rate limit exceeded, try again later."), 429

    # ---------- Bonus hardening: Security Headers ----------
    @app.after_request
    def set_security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        if "user_id" in session:
            resp.headers["Cache-Control"] = "no-store"
            resp.headers["Pragma"] = "no-cache"
        return resp

    return app


# Maintain backward compatibility for `from secure.app import app`
app = create_app()


if __name__ == "__main__":
    db_path = app.config.get("DATABASE", DB)
    if not os.path.exists(db_path):
        init_db(db_path)
    app.run(debug=False, port=5001)
