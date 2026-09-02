# Password reset: end-to-end user flow (Task A.3.3)

Date: 2026-09-02. Status: implemented in the same session, test-first.

## Problem

The JSON endpoints `POST /api/auth/forgot-password` and
`POST /api/auth/reset-password` are secure, but a patient cannot complete a
reset on their own:

- the emailed link points at `GET /reset-password`, which does not exist;
- there is no page to ask for a reset from the login screen;
- the mailer only appends to an in-memory outbox, so nothing ever reaches
  the patient.

## Assumptions (made without a live user; easy to reverse)

- Keep the existing API contract untouched; the tests in
  `tests/test_password_reset.py` must keep passing unchanged.
- No new dependencies. SMTP delivery uses the standard library.
- The pages follow the existing HTML interface: server-rendered Jinja,
  CSRF token on every form, flash messages, `form.stack` styling.

## Design

### 1. Service layer: `app/services/password_reset.py`

Both controllers become thin wrappers around two functions, so the security
rules live in one place (same pattern as `services/auth.py`):

- `request_reset(email: str) -> None`: looks up an active user; if found,
  issues a token (hash stored, 30-minute TTL), records the audit event and
  hands the raw token link to the mailer. Never raises for unknown emails and
  never reveals whether one existed.
- `reset_password(raw_token, new_password) -> User`: validates the token
  (exists, unused, unexpired, active user), enforces the password policy,
  re-hashes, burns the token, revokes every refresh token. Raises
  `ResetTokenError` for a bad token and `PasswordPolicyError` for a weak
  password.
- `reset_link(raw_token) -> str`: builds the absolute link. When
  `PUBLIC_BASE_URL` is configured it is used as the origin; otherwise the
  request host is used (development). This stops Host-header poisoning of
  reset links in production.

### 2. HTML pages: `app/controllers/pages.py`

| Method | Path | Behaviour |
|---|---|---|
| GET | `/forgot-password` | email form |
| POST | `/forgot-password` | CSRF check, `request_reset`, flash the same generic message for every input, redirect to `/login`. Rate limited per IP (5 per 5 min), same as the API. |
| GET | `/reset-password?token=…` | if the token is valid, show the new-password form with the token in a hidden field; otherwise a 400 page saying the link is invalid or expired, with a link to ask for a new one. `Cache-Control: no-store`. |
| POST | `/reset-password` | CSRF check, confirm-password match, `reset_password`. Success: flash, clear the auth cookie, redirect to `/login`. Failure: re-render with the error (400). Rate limited per IP (10 per 5 min). |

The login page gains a "Forgot your password?" link.

The rate limiter currently always answers with JSON. For non-`/api/` paths
it raises `TooManyRequests` instead, so the existing error page renders.

### 3. Mailer: `app/services/mailer.py`

- `Mailer` keeps the outbox (tests read it) and calls `_deliver(message)`.
  Delivery errors are logged (subject and recipient only, never the body)
  and swallowed, so an SMTP outage cannot turn the forgot-password endpoint
  into an account-enumeration oracle (500 for known users, 200 for unknown).
- `SmtpMailer(Mailer)` delivers with `smtplib` (STARTTLS, optional login).
- `ConsoleMailer(Mailer)` logs the full message. Selected only for the
  development config, so a developer can click the link locally.
- `build_mailer(app)` chooses: `SMTP_HOST` set → SMTP; development →
  console; otherwise outbox. Production without `SMTP_HOST` warns at
  start-up that reset mail will not be delivered.

New settings, all optional: `SMTP_HOST`, `SMTP_PORT` (587), `SMTP_USERNAME`,
`SMTP_PASSWORD`, `SMTP_USE_TLS` (true), `MAIL_FROM`, `PUBLIC_BASE_URL`.

### 4. Tests (written first)

`tests/test_password_reset_pages.py`: forgot-password page and link from
login; identical answer for known and unknown email; CSRF required on both
forms; reset page for valid, garbage and missing tokens; successful reset via
the form then login with the new password and replay rejected; weak password
and mismatch re-render with 400; `PUBLIC_BASE_URL` wins over the Host header;
per-IP rate limit on the forgot-password form.

`tests/test_mailer.py`: SMTP mailer talks to a fake `smtplib.SMTP`; a
delivery failure still yields the generic 200; backend selection by config.

### 5. Documentation

README (running, tests, page list), `.env.example`, and
`docs/architecture-and-security.md` (reset flow, limitations) are updated.

## Out of scope

Email verification at registration, MFA, a queue or retry for outgoing mail,
and browser end-to-end tests.
