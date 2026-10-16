import os
from datetime import timedelta


class Config:
    TESTING = False
    DEBUG = False
    SECRET_KEY = os.environ.get("SECRET_KEY")
    DATABASE = os.environ.get("DATABASE", os.path.join(os.path.dirname(__file__), "club.db"))
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    SEED_PASSWORDS = None
    WTF_CSRF_ENABLED = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() in ("true", "1")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_NAME = "__Host-session" if os.environ.get("SESSION_COOKIE_SECURE", "true").lower() in ("true", "1") else "session"

    @classmethod
    def check_valid(cls, config_dict):
        if not config_dict.get("TESTING") and not config_dict.get("SECRET_KEY"):
            raise RuntimeError("SECRET_KEY environment variable is required in production/non-testing mode.")


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SECRET_KEY = "test-secret-key-32-bytes-long!"
    DATABASE = os.path.join(os.path.dirname(__file__), "test_club.db")
    RATELIMIT_STORAGE_URI = "memory://"
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_NAME = "session"
    SEED_PASSWORDS = {
        "admin": "admin123",
        "alice": "alicepw",
        "bob": "bobpw",
    }

