"""
SECURE VERSION - College Club Portal
Fixes the 3 vulnerabilities present in the vulnerable/ version:
  1. IDOR on /profile/<id>        -> ownership + role check
  2. SQL Injection on /login      -> parameterized queries
  3. Broken access control /admin -> server-side role check (decorator)
"""
from flask import Flask, request, session, redirect, url_for, render_template, g, abort
from functools import wraps
import sqlite3, os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-prod-use-env-var")
DB = os.path.join(os.path.dirname(__file__), "club.db")


def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db_path = app.config.get("DATABASE", DB)
        db = g._db = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def init_db(db_path=None):
    target_db = db_path or app.config.get("DATABASE", DB)
    db = sqlite3.connect(target_db)
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
        phone TEXT
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


# ---------- FIX #2: parameterized query + hashed password check ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        from werkzeug.security import check_password_hash
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        # FIXED: parameterized query, no string concatenation
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
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


# ---------- Bonus hardening ----------
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    return resp


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # SESSION_COOKIE_SECURE=True,  # enable when served over HTTPS
)


if __name__ == "__main__":
    if not os.path.exists(DB):
        init_db()
    app.run(debug=False, port=5001)
