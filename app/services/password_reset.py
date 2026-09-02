"""Account recovery rules (Task A.3.3), shared by the JSON API and the HTML pages.

request_reset(email): a random token is generated, only its SHA-256 is
stored, and the raw token is mailed as a link. Nothing is revealed about
whether the address is registered: unknown or inactive accounts are ignored
silently and the caller answers the same way in every case.

reset_password(token, new_password): the token must exist, be unused and
unexpired and belong to an active account; the password policy is enforced;
the password is re-hashed, the token is burned and every refresh token of
the account is revoked, so old sessions die with the old password.

Both functions commit, because mailing a link for a token that was never
stored (or not burning a token that was used) would be a security bug.
"""
from datetime import timedelta

from flask import current_app, request, url_for

from ..extensions import db
from ..models import PasswordResetToken, User
from ..utils import utcnow
from .audit import record
from .security import (
    check_password_policy,
    hash_password,
    hash_token,
    new_opaque_token,
    revoke_all_refresh_tokens,
)

GENERIC_MESSAGE = "If that address is registered, a reset link has been sent."
INVALID_TOKEN = "Invalid or expired reset token"


class ResetTokenError(ValueError):
    pass


def reset_link(raw_token: str) -> str:
    """Absolute link for the email. PUBLIC_BASE_URL wins over the Host header,
    so a request with a forged Host cannot point the link at an attacker's server."""
    base = current_app.config.get("PUBLIC_BASE_URL") or request.host_url
    return base.rstrip("/") + url_for("pages.reset_password", token=raw_token)


def request_reset(email: str) -> None:
    user = db.session.scalar(db.select(User).where(User.email == email))
    if user is None or not user.is_active:
        return
    raw = new_opaque_token()
    ttl = current_app.config["RESET_TOKEN_TTL"]
    db.session.add(PasswordResetToken(
        user_id=user.id,
        token_hash=hash_token(raw),
        expires_at=utcnow() + timedelta(seconds=ttl),
    ))
    record("auth.reset_requested", user=user)
    db.session.commit()
    current_app.extensions["mailer"].send(
        to=user.email,
        subject="Riverside Clinic - reset your password",
        body=f"Use this link within {ttl // 60} minutes to choose a new password:\n{reset_link(raw)}\n"
             "If you did not ask for this, you can ignore this email.",
    )


def find_valid_token(raw) -> PasswordResetToken | None:
    if not isinstance(raw, str) or not raw:
        return None
    prt = db.session.scalar(
        db.select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(raw))
    )
    if prt is None or not prt.is_valid or not prt.user.is_active:
        return None
    return prt


def reset_password(raw, new_password) -> User:
    """Raises ResetTokenError for a bad token, PasswordPolicyError for a weak password."""
    prt = find_valid_token(raw)
    if prt is None:
        raise ResetTokenError(INVALID_TOKEN)
    check_password_policy(new_password, prt.user.email)
    prt.used_at = utcnow()
    prt.user.password_hash = hash_password(new_password)
    revoke_all_refresh_tokens(prt.user)
    record("auth.password_reset", user=prt.user)
    db.session.commit()
    return prt.user
