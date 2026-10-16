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
import sqlite3, os
from werkzeug.security import check_password_hash, generate_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

from secure.config import Config, TestingConfig
from secure.db import get_db, close_db, init_db, DB_FALLBACK as DB

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
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
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
                    session["user_id"] = user["id"]
                    session["role"] = user["role"]
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
                    else:
                        if attempt_row:
                            db.execute("UPDATE login_attempts SET failed_attempts = ? WHERE id = ?",
                                       (failed, attempt_row["id"]))
                        else:
                            db.execute(
                                "INSERT INTO login_attempts (username, ip_address, failed_attempts) VALUES (?, ?, ?)",
                                (username, ip_addr, failed)
                            )
                    db.commit()
                    return render_template("login.html", error="Invalid credentials")
            elif user and is_locked:
                check_password_hash(user["password"], password)
                return render_template("login.html", error="Invalid credentials")
            else:
                check_password_hash(DUMMY_PASSWORD_HASH, password)
                return render_template("login.html", error="Invalid credentials")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
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
        return render_template("403.html"), 403

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return render_template("login.html", error="Too many requests. Rate limit exceeded, try again later."), 429

    # ---------- Bonus hardening ----------
    @app.after_request
    def set_security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        return resp

    return app


# Maintain backward compatibility for `from secure.app import app`
app = create_app()


if __name__ == "__main__":
    db_path = app.config.get("DATABASE", DB)
    if not os.path.exists(db_path):
        init_db(db_path)
    app.run(debug=False, port=5001)
