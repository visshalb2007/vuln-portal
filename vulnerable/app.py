"""
VULNERABLE VERSION - College Club Portal
Intentionally contains 3 vulnerabilities for security coursework.
DO NOT deploy. Local/educational use only.
"""
import os
import sqlite3

from flask import Flask, g, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = "supersecretkey123"  # also weak, but not a graded vuln
DB = os.path.join(os.path.dirname(__file__), "club.db")


def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB)
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
    db.execute("INSERT INTO users (username,password,role,full_name,email,phone) VALUES (?,?,?,?,?,?)",
               ("admin", "admin123", "admin", "Club Admin", "admin@club.edu", "9999999999"))
    db.execute("INSERT INTO users (username,password,role,full_name,email,phone) VALUES (?,?,?,?,?,?)",
               ("alice", "alicepw", "member", "Alice Member", "alice@club.edu", "9000000001"))
    db.execute("INSERT INTO users (username,password,role,full_name,email,phone) VALUES (?,?,?,?,?,?)",
               ("bob", "bobpw", "member", "Bob Member", "bob@club.edu", "9000000002"))
    db.execute("INSERT INTO events (title,description,created_by) VALUES (?,?,?)",
               ("Hackathon 2026", "24hr coding event", 1))
    db.commit()
    db.close()


# ---------- VULN #2: SQL INJECTION (login uses string concatenation) ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        # VULNERABLE: raw string concatenation into SQL query
        query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
        cur = db.execute(query)
        user = cur.fetchone()
        if user:
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
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    events = db.execute("SELECT * FROM events").fetchall()
    return render_template("dashboard.html", events=events, role=session.get("role"))


# ---------- VULN #1: BROKEN ACCESS CONTROL / IDOR on profile ----------
@app.route("/profile/<int:user_id>")
def profile(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    # VULNERABLE: no check that session user_id == user_id or is admin
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return "User not found", 404
    return render_template("profile.html", user=user)


# ---------- VULN #3: BROKEN ACCESS CONTROL on admin route ----------
@app.route("/admin/users")
def admin_users():
    if "user_id" not in session:
        return redirect(url_for("login"))
    # VULNERABLE: only checks login, not role. "Security by hiding the link."
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    return render_template("admin_users.html", users=users)


if __name__ == "__main__":
    if not os.path.exists(DB):
        init_db()
    app.run(debug=True, port=5000)
