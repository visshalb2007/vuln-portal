import os


class Config:
    TESTING = False
    DEBUG = False
    SECRET_KEY = os.environ.get("SECRET_KEY")
    DATABASE = os.environ.get("DATABASE", os.path.join(os.path.dirname(__file__), "club.db"))
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    SEED_PASSWORDS = None
    WTF_CSRF_ENABLED = True

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
    SEED_PASSWORDS = {
        "admin": "admin123",
        "alice": "alicepw",
        "bob": "bobpw",
    }
