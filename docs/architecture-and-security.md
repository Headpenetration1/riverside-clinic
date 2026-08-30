# Architecture and security rationale

This document explains the main design choices, request flows and known
limitations of Riverside Clinic. It is intended to make the implementation
easy to review and to connect the code to the security requirements.

## Architecture

The application uses a practical MVC structure:

- `app/models/` contains the SQLAlchemy data model.
- `app/views/` contains server-rendered Jinja templates and static CSS.
- `app/controllers/` contains Flask blueprints for HTTP request handling.
- `app/services/` contains authentication, tokens, document rules, file
  encryption, CSRF, rate limiting, auditing and the Cerebras client.

`create_app()` loads and validates configuration, initializes the database and
services, registers blueprints, and installs security headers and error
handlers. Keeping business and security rules in services means the HTML
interface and JSON API reuse the same authorization and document logic.

The roles follow least privilege and separation of duties. Patients manage
their own documents, clinicians can read patient documents, and administrators
manage accounts without access to clinical data.

## Authentication flows

Passwords are hashed with Argon2id. Authentication deliberately returns the
same error for an unknown account and a wrong password, and performs a dummy
hash for unknown accounts to reduce timing differences.

The API uses a short-lived, 15-minute HS256 access token in an explicit
`Authorization: Bearer` header. Refresh tokens are high-entropy random values;
only a SHA-256 hash is stored. Refreshing rotates the token and revokes the old
one. Protected requests also load the user from the database, so a deactivated
account is rejected even if its access token has not expired.

The HTML interface stores the same short-lived access token in an `HttpOnly`,
`SameSite=Lax` cookie. Because browsers attach cookies automatically, every
state-changing HTML form also requires a CSRF token. `Secure` cookies and HSTS
are enabled in production.

## Document flow

An upload is accepted only when all of these checks pass:

1. Flask's request-size limit is not exceeded.
2. The filename is normalized with `secure_filename`.
3. The extension and magic bytes both identify an allowed PDF, PNG or JPEG.
4. The current role is allowed to upload.

File contents are encrypted with AES-256-GCM before storage. GCM provides both
confidentiality and integrity, so modified ciphertext cannot be decrypted.
Files receive random storage names outside the static web directory and mode
`0600`. The database stores metadata and a SHA-256 digest, not plaintext.

Downloads repeat role and ownership checks. An unauthorized document ID is
reported as not found so the application does not confirm that another
patient's document exists. Download responses use attachment disposition,
`no-store`, `nosniff` and a restrictive sandbox policy.

## Input and output security

SQLAlchemy produces bound parameters rather than concatenating user input into
SQL. Patient search also escapes `%` and `_` before using `LIKE`. Jinja
autoescaping handles untrusted values in HTML, while CSP, clickjacking
protection, `nosniff` and a strict referrer policy provide additional layers.

Unexpected API errors return a generic response. The server log retains the
details for diagnosis, but a logging filter redacts bearer tokens and Cerebras
keys. Audit events record who performed an action and when, without storing
passwords, tokens, document contents or chat messages.

## Password reset and privacy

The forgot-password endpoint gives the same response whether an account
exists or not. Reset tokens are random, time-limited and single-use, and only
their hashes are stored. A successful reset revokes existing refresh sessions.

The data-export endpoint returns only the authenticated user's information.
Account deletion removes the user, related database records and encrypted
files. These flows support the data access and erasure requirements represented
in the assignment.

## Chatbot boundary

Only patients and clinicians may call the assistant. Input length, history
length and allowed history roles are validated, and the server always inserts
its own system prompt first. The model receives no patient documents or patient
records. Requests have a timeout and per-user rate limit; upstream failures are
returned as a generic unavailable response. The assistant is limited to
practical clinic questions and general information, not diagnosis or treatment.

These controls reduce risk but do not make a language model a trusted medical
system. Prompt injection and incorrect answers cannot be eliminated completely.

## Tests and CI

The 85-test pytest suite covers authentication, token rotation, password reset,
role and ownership checks, file validation and encryption, SQL injection, XSS,
CSRF, security headers, chatbot boundaries, HTML flows, and data export and
deletion. Each test uses an isolated SQLite database and upload directory.
External chatbot calls are replaced with deterministic fakes.

CI runs the tests plus Bandit static analysis, `pip-audit` dependency scanning,
Gitleaks history scanning, and a check that `.env` is not committed.

## Known limitations

- SQLite and `db.create_all()` are suitable for this demonstration; a real
  deployment needs a managed database and migration tooling such as Alembic.
- Rate limiting is in process memory. Multiple workers need a shared store such
  as Redis.
- The mailer is a test outbox rather than an SMTP or transactional-email
  integration.
- The breached-password list is intentionally small; production should use a
  maintained service such as the HIBP k-anonymity API.
- File checks are not antivirus or full content scanning.
- File encryption uses one key without rotation or key versioning.
- Access tokens cannot be individually revoked before expiry, although their
  lifetime is short and active-user status is checked on each request.
- The audit table is not append-only or tamper-proof and has no retention or
  monitoring policy.
- There is no MFA, email verification, browser E2E suite, load test or
  production reverse-proxy test.

## Review questions

**Why use a service layer?** The API and HTML controllers stay thin and reuse
the same authorization, validation and document rules instead of implementing
slightly different security checks in two places.

**Why Argon2id for passwords but SHA-256 for refresh tokens?** Passwords have
low, human-chosen entropy and need deliberately slow hashing. Refresh tokens
contain 384 random bits, so a fast one-way hash is sufficient and supports an
indexed database lookup.

**Why AES-GCM?** It authenticates as well as encrypts. A changed file fails its
integrity check instead of producing corrupted plaintext that could be served.

**Why return 404 for another patient's document?** A 403 response would reveal
that the guessed document ID exists. Returning 404 reduces ID enumeration.

**Why does the API not use CSRF tokens?** API authentication requires an
explicit bearer header, which a cross-site form cannot add automatically. The
HTML interface uses automatically attached cookies and therefore needs CSRF.

**Is the role in the JWT sufficient?** No. Protected requests load the user
from the database, check that the account is active, enforce route-level role
requirements, and then apply resource ownership rules in the service layer.

**Can an administrator read clinical documents?** No. Account administration
and clinical access are deliberately separated according to least privilege.

**Is the chatbot safe?** It has a narrow purpose, no patient-record access,
strict input boundaries, a server-controlled prompt, rate limits and generic
failures. It is still probabilistic software and must not be treated as medical
decision support.
