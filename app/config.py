"""Configuration.

Everything secret comes from the environment (or a git-ignored .env file).
Nothing secret is hard-coded here. Production refuses to start without the
required keys; development generates throwaway keys and says so loudly.
"""
import base64
import os
import secrets
import warnings


class BaseConfig:
    # --- secrets (environment only) ---
    SECRET_KEY = os.environ.get("SECRET_KEY")
    JWT_SECRET = os.environ.get("JWT_SECRET")
    FILE_ENCRYPTION_KEY = os.environ.get("FILE_ENCRYPTION_KEY")  # base64, 32 bytes
    CEREBRAS_API_KEY = os.environ.get("CEREBRAS_API_KEY")

    # --- database ---
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///clinic.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- tokens ---
    ACCESS_TOKEN_TTL = 15 * 60          # 15 minutes
    REFRESH_TOKEN_TTL = 7 * 24 * 3600   # 7 days
    RESET_TOKEN_TTL = 30 * 60           # 30 minutes

    # --- password hashing (Argon2id) ---
    ARGON2_TIME_COST = 3
    ARGON2_MEMORY_COST = 64 * 1024      # KiB -> 64 MiB
    ARGON2_PARALLELISM = 4

    # --- files ---
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024   # 10 MiB request limit
    UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(os.getcwd(), "instance", "uploads"))
    ALLOWED_EXTENSIONS = frozenset({"pdf", "png", "jpg", "jpeg"})

    # --- chatbot ---
    CEREBRAS_API_URL = "https://api.cerebras.ai/v1/chat/completions"
    CEREBRAS_MODEL = os.environ.get("CEREBRAS_MODEL", "llama3.1-8b")
    CEREBRAS_TIMEOUT = 20
    CHAT_MAX_MESSAGE_CHARS = 1000
    CHAT_MAX_HISTORY = 10

    # --- cookies (HTML interface) ---
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = True
    AUTH_COOKIE_NAME = "access_token"
    AUTH_COOKIE_SECURE = True

    # set by create_app after validation
    HSTS_ENABLED = True


class ProductionConfig(BaseConfig):
    ENV_NAME = "production"


class DevelopmentConfig(BaseConfig):
    ENV_NAME = "development"
    SESSION_COOKIE_SECURE = False   # plain http://localhost
    AUTH_COOKIE_SECURE = False
    HSTS_ENABLED = False


class TestingConfig(BaseConfig):
    ENV_NAME = "testing"
    TESTING = True
    SESSION_COOKIE_SECURE = False
    AUTH_COOKIE_SECURE = False
    HSTS_ENABLED = False
    # cheap hashing so the suite runs fast; production uses the values above
    ARGON2_TIME_COST = 1
    ARGON2_MEMORY_COST = 8 * 1024
    ARGON2_PARALLELISM = 1
    MAX_CONTENT_LENGTH = 1024 * 1024    # 1 MiB, so the "too large" test is quick
    SECRET_KEY = "test-secret-key-not-for-production"
    JWT_SECRET = "test-jwt-secret-not-for-production"
    FILE_ENCRYPTION_KEY = base64.b64encode(b"\x01" * 32).decode()
    CEREBRAS_API_KEY = "csk-test-key-0000000000000000"


CONFIGS = {
    "production": ProductionConfig,
    "development": DevelopmentConfig,
    "testing": TestingConfig,
}


def get_config(name: str | None):
    name = name or os.environ.get("FLASK_CONFIG", "development")
    try:
        return CONFIGS[name]
    except KeyError:
        raise RuntimeError(f"Unknown FLASK_CONFIG '{name}'") from None


def validate_secrets(app) -> None:
    """Refuse to run production with missing keys; fill in ephemeral ones for dev."""
    required = ("SECRET_KEY", "JWT_SECRET", "FILE_ENCRYPTION_KEY")
    missing = [k for k in required if not app.config.get(k) or app.config[k] == "change-me"]
    env_name = app.config.get("ENV_NAME")

    if env_name == "production" and missing:
        raise RuntimeError(f"Refusing to start: missing secrets {missing}. See .env.example.")

    for key in missing:
        if key == "FILE_ENCRYPTION_KEY":
            app.config[key] = base64.b64encode(os.urandom(32)).decode()
        else:
            app.config[key] = secrets.token_urlsafe(48)
        warnings.warn(
            f"{key} not set; using a throwaway value for this process only "
            "(sessions, tokens and encrypted files will not survive a restart).",
            stacklevel=2,
        )

    raw = base64.b64decode(app.config["FILE_ENCRYPTION_KEY"])
    if len(raw) != 32:
        raise RuntimeError("FILE_ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256).")
