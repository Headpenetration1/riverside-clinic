from flask import g

from ..extensions import db
from ..models import AuditEvent
from ..utils import client_ip


def record(action: str, target: str | None = None, user=None) -> None:
    """Add an audit row to the current session (the caller commits)."""
    if user is None:
        user = g.get("current_user")
    db.session.add(AuditEvent(
        user_id=user.id if user is not None else None,
        action=action,
        target=(target or "")[:255] or None,
        ip=client_ip(),
    ))
