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
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from secure.config import Config, TestingConfig

DB = os.path.join(os.path.dirname(__file__), "club.db")

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
    strategy="fixed-window",
)


def ensure_schema(db):
    cursor = db.execute("PRAGMA table_info(users)")
    cols = [row["name"] for row in cursor.fetchall()]
    if cols and "failed_attempts" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
    if cols and "locked_until" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
    db.commit()


def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        try:
            db_path = current_app.config.get("DATABASE", DB)
        except RuntimeError:
            db_path = DB
        db = g._db = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row
        ensure_schema(db)
    return db


def init_db(db_path=None):
    if db_path is None:
        try:
            db_path = current_app.config.get("DATABASE", DB)
        except RuntimeError:
            db_path = DB
    db = sqlite3.connect(db_path)
    db.executescript("""
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS events;
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        full_name TEXT,
        email TEXT,
        phone TEXT,
        failed_attempts INTEGER DEFAULT 0,
        locked_until TEXT
    );
    CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        created_by INTEGER
    );
    """)
    # FIX: passwords hashed, not plaintext
    from werkzeug.security import generate_password_hash
    db.execute("INSERT INTO users (username,password,role,full_name,email,phone) VALUES (?,?,?,?,?,?)",
               ("admin", generate_password_hash("admin123"), "admin", "Club Admin", "admin@club.edu", "9999999999"))
    db.execute("INSERT INTO users (username,password,role,full_name,email,phone) VALUES (?,?,?,?,?,?)",
               ("alice", generate_password_hash("alicepw"), "member", "Alice Member", "alice@club.edu", "9000000001"))
    db.execute("INSERT INTO users (username,password,role,full_name,email,phone) VALUES (?,?,?,?,?,?)",
               ("bob", generate_password_hash("bobpw"), "member", "Bob Member", "bob@club.edu", "9000000002"))
    db.execute("INSERT INTO events (title,description,created_by) VALUES (?,?,?)",
               ("Hackathon 2026", "24hr coding event", 1))
    db.commit()
    db.close()


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

    limiter.init_app(app)

    @app.teardown_appcontext
    def close_db(exc):
        db = getattr(g, "_db", None)
        if db is not None:
            db.close()

    # ---------- FIX #2: parameterized query + hashed password check ----------
    # BONUS: Rate limiting on login attempts (5 per minute per IP)
    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def login():
        if request.method == "POST":
            from werkzeug.security import check_password_hash
            username = request.form["username"]
            password = request.form["password"]
            db = get_db()
            # FIXED: parameterized query, no string concatenation
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if user:
                # Check if account is currently locked
                locked_until_str = user["locked_until"]
                if locked_until_str:
                    try:
                        locked_until = datetime.fromisoformat(locked_until_str)
                        if locked_until.tzinfo is None:
                            locked_until = locked_until.replace(tzinfo=timezone.utc)
                        if datetime.now(timezone.utc) < locked_until:
                            return render_template("login.html", error="Account locked, try again later.")
                    except (ValueError, TypeError):
                        pass

                if check_password_hash(user["password"], password):
                    db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
                    db.commit()
                    session.clear()
                    session["user_id"] = user["id"]
                    session["role"] = user["role"]
                    return redirect(url_for("dashboard"))
                else:
                    failed = (user["failed_attempts"] or 0) + 1
                    if failed >= 5:
                        lock_until = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
                        db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                                   (failed, lock_until, user["id"]))
                        db.commit()
                        return render_template("login.html", error="Account locked, try again later.")
                    else:
                        db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (failed, user["id"]))
                        db.commit()
                        return render_template("login.html", error="Invalid credentials")
            return render_template("login.html", error="Invalid credentials")
        return render_template("login.html")

    @app.route("/logout")
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
