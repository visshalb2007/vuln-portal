import os
import sqlite3
from flask import g, current_app

DB_FALLBACK = os.path.join(os.path.dirname(__file__), "club.db")


def connect_db(db_path):
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        try:
            db_path = current_app.config.get("DATABASE", DB_FALLBACK)
        except RuntimeError:
            db_path = DB_FALLBACK
        db = g._db = connect_db(db_path)
    return db


def close_db(exc=None):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def ensure_schema(db):
    cursor = db.execute("PRAGMA table_info(users)")
    cols = [row["name"] for row in cursor.fetchall()]
    if cols and "failed_attempts" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
    if cols and "locked_until" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
    db.commit()


import secrets


def get_seed_passwords():
    seed_cfg = {}
    try:
        seed_cfg = current_app.config.get("SEED_PASSWORDS") or {}
    except RuntimeError:
        pass

    admin_pw = os.environ.get("ADMIN_PASSWORD") or seed_cfg.get("admin") or secrets.token_urlsafe(16)
    alice_pw = os.environ.get("ALICE_PASSWORD") or seed_cfg.get("alice") or secrets.token_urlsafe(16)
    bob_pw = os.environ.get("BOB_PASSWORD") or seed_cfg.get("bob") or secrets.token_urlsafe(16)

    generated = []
    if not os.environ.get("ADMIN_PASSWORD") and not seed_cfg.get("admin"):
        generated.append(f"  admin: {admin_pw}")
    if not os.environ.get("ALICE_PASSWORD") and not seed_cfg.get("alice"):
        generated.append(f"  alice: {alice_pw}")
    if not os.environ.get("BOB_PASSWORD") and not seed_cfg.get("bob"):
        generated.append(f"  bob:   {bob_pw}")

    if generated:
        print("[INIT] Generated random seed credentials for initial setup:")
        for line in generated:
            print(line)

    return {"admin": admin_pw, "alice": alice_pw, "bob": bob_pw}


def init_db(db_path=None):
    if db_path is None:
        try:
            db_path = current_app.config.get("DATABASE", DB_FALLBACK)
        except RuntimeError:
            db_path = DB_FALLBACK

    db = connect_db(db_path)
    db.executescript("""
    DROP TABLE IF EXISTS events;
    DROP TABLE IF EXISTS users;
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
        created_by INTEGER,
        FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE
    );
    """)

    passwords = get_seed_passwords()
    from werkzeug.security import generate_password_hash
    db.execute("INSERT INTO users (username,password,role,full_name,email,phone) VALUES (?,?,?,?,?,?)",
               ("admin", generate_password_hash(passwords["admin"]), "admin", "Club Admin", "admin@club.edu", "9999999999"))
    db.execute("INSERT INTO users (username,password,role,full_name,email,phone) VALUES (?,?,?,?,?,?)",
               ("alice", generate_password_hash(passwords["alice"]), "member", "Alice Member", "alice@club.edu", "9000000001"))
    db.execute("INSERT INTO users (username,password,role,full_name,email,phone) VALUES (?,?,?,?,?,?)",
               ("bob", generate_password_hash(passwords["bob"]), "member", "Bob Member", "bob@club.edu", "9000000002"))
    db.execute("INSERT INTO events (title,description,created_by) VALUES (?,?,?)",
               ("Hackathon 2026", "24hr coding event", 1))
    ensure_schema(db)
    db.commit()
    db.close()
