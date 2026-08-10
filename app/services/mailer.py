"""Outgoing mail.

There is no SMTP in this project on purpose: messages are collected in an
outbox and logged. The password-reset flow only depends on `send()`, so an
SMTP or API-based mailer can be dropped in without touching the controllers.
"""
import logging


class Mailer:
    def __init__(self, logger: logging.Logger | None = None):
        self.outbox: list[dict] = []
        self.log = logger or logging.getLogger(__name__)

    def send(self, to: str, subject: str, body: str) -> None:
        self.outbox.append({"to": to, "subject": subject, "body": body})
        # log that a mail went out, never its body (the body carries the reset token)
        self.log.info("mail queued to=%s subject=%r", to, subject)
