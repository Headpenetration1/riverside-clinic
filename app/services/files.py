"""Upload validation and encrypted storage.

Validation is allowlist-only: the extension must be one we serve, and the
first bytes must match that type. A .pdf that starts with <html> is rejected,
so nothing we later serve can be sniffed into something executable.

Storage: each file is encrypted with AES-256-GCM under a key from the
environment, written under a random hex name outside the web root. The
nonce is stored as the first 12 bytes of the file. GCM gives us integrity
too, so a tampered file fails to decrypt instead of being served.
"""
import base64
import hashlib
import os
import re
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app
from werkzeug.utils import secure_filename

MAGIC = {
    "pdf": (b"%PDF-",),
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpg": (b"\xff\xd8\xff",),
    "jpeg": (b"\xff\xd8\xff",),
}
MIME = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
}
STORED_NAME_RE = re.compile(r"^[0-9a-f]{32}$")
NONCE_LEN = 12


class FileValidationError(ValueError):
    pass


def validate_upload(filename: str | None, data: bytes) -> tuple[str, str]:
    """Return (safe_display_name, mime_type) or raise FileValidationError."""
    safe = secure_filename(filename or "")
    if not safe or "." not in safe:
        raise FileValidationError("Filename must have an allowed extension")
    ext = safe.rsplit(".", 1)[1].lower()
    if ext not in current_app.config["ALLOWED_EXTENSIONS"]:
        raise FileValidationError(f"File type .{ext} is not allowed")
    if not data:
        raise FileValidationError("File is empty")
    if not any(data.startswith(magic) for magic in MAGIC[ext]):
        raise FileValidationError("File content does not match its extension")
    return safe[:255], MIME[ext]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _key() -> bytes:
    key = base64.b64decode(current_app.config["FILE_ENCRYPTION_KEY"])
    if len(key) != 32:
        raise RuntimeError("FILE_ENCRYPTION_KEY must be 32 bytes")
    return key


def _path(stored_name: str) -> str:
    # belt and braces: the name comes from our own DB, but check it anyway
    if not STORED_NAME_RE.match(stored_name):
        raise ValueError("invalid stored name")
    return os.path.join(current_app.config["UPLOAD_DIR"], stored_name)


def store_encrypted(data: bytes) -> str:
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(_key()).encrypt(nonce, data, None)
    stored_name = uuid.uuid4().hex
    path = _path(stored_name)
    with open(path, "wb") as fh:
        fh.write(nonce + ciphertext)
    os.chmod(path, 0o600)
    return stored_name


def load_decrypted(stored_name: str) -> bytes:
    with open(_path(stored_name), "rb") as fh:
        blob = fh.read()
    nonce, ciphertext = blob[:NONCE_LEN], blob[NONCE_LEN:]
    try:
        return AESGCM(_key()).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise RuntimeError("stored file failed integrity check") from None


def remove_stored(stored_name: str) -> None:
    try:
        os.remove(_path(stored_name))
    except FileNotFoundError:
        pass
