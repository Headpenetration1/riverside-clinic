"""Account recovery (Task A.3.3).

Flow: POST /forgot-password with an email -> a random token is generated,
only its SHA-256 is stored, and the raw token is mailed as a link.
POST /reset-password with the token and a new password -> token must exist,
be unused and unexpired; the password is re-hashed, the token is burned and
every refresh token of the account is revoked.
The forgot-password response is identical whether or not the email exists.
"""
from datetime import timedelta

from flask import Blueprint, current_app, jsonify, request

from ..extensions import db
from ..models import PasswordResetToken, User
from ..services.audit import record
from ..services.ratelimit import rate_limited
from ..services.security import (
    PasswordPolicyError,
    check_password_policy,
    hash_password,
    hash_token,
    new_opaque_token,
    revoke_all_refresh_tokens,
)
from ..utils import json_error, normalise_email, require_json, utcnow

bp = Blueprint("password_reset", __name__, url_prefix="/api/auth")

FORGOT_RESPONSE = {"message": "If that address is registered, a reset link has been sent."}


@bp.post("/forgot-password")
@rate_limited(5, 300)
def forgot_password():
    data = require_json()
    email = normalise_email(data.get("email"))
    if email is None:
        return jsonify(FORGOT_RESPONSE), 200         # same answer, no enumeration
    user = db.session.scalar(db.select(User).where(User.email == email))
    if user is not None and user.is_active:
        raw = new_opaque_token()
        db.session.add(PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token(raw),
            expires_at=utcnow() + timedelta(seconds=current_app.config["RESET_TOKEN_TTL"]),
        ))
        record("auth.reset_requested", user=user)
        db.session.commit()
        link = f"{request.host_url.rstrip('/')}/reset-password?token={raw}"
        current_app.extensions["mailer"].send(
            to=user.email,
            subject="Riverside Clinic - reset your password",
            body=f"Use this link within 30 minutes to choose a new password:\n{link}\n"
                 "If you did not ask for this, you can ignore this email.",
        )
    return jsonify(FORGOT_RESPONSE), 200


@bp.post("/reset-password")
@rate_limited(10, 300)
def reset_password():
    data = require_json()
    raw = data.get("token")
    if not isinstance(raw, str) or not raw:
        return json_error("Invalid or expired reset token", 400)
    prt = db.session.scalar(
        db.select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(raw))
    )
    if prt is None or not prt.is_valid or not prt.user.is_active:
        return json_error("Invalid or expired reset token", 400)
    try:
        check_password_policy(data.get("new_password"), prt.user.email)
    except PasswordPolicyError as exc:
        return json_error(str(exc), 400)

    prt.used_at = utcnow()
    prt.user.password_hash = hash_password(data["new_password"])
    revoke_all_refresh_tokens(prt.user)          # every existing session dies with the old password
    record("auth.password_reset", user=prt.user)
    db.session.commit()
    return jsonify({"message": "Password updated. Please log in again."}), 200
