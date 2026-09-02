# Riverside Clinic – secure patient document portal

A small Flask application built for a DevSecOps assignment. The case study
behind it is the 2018–2020 Vastaamo breach, in which a Finnish psychotherapy
provider's patient database was stolen and its patients extorted; the portal
is a reference implementation of the controls that were missing there, for a
psychotherapy clinic of similar size. Patients register, log in, upload
documents (referral letters, questionnaires, earlier assessments) and ask a
Cerebras-backed assistant practical questions. Clinicians can read patient
documents. Administrators manage accounts and deliberately have no access to
clinical data.

Everything interesting from a security point of view is covered by tests in
`tests/`; run them before reading the code.

## Layout (MVC)

```
app/
  models/        SQLAlchemy models              (Model)
  views/         Jinja2 templates + static CSS  (View)
  controllers/   Flask blueprints               (Controller)
  services/      hashing, tokens, file crypto, rate limiting, Cerebras client, audit
  config.py      settings; all secrets from the environment
tests/           pytest suite (auth, reset, documents, SQLi, XSS, chatbot, pages/GDPR)
scripts/seed.py  demo accounts (password from SEED_PASSWORD)
.github/workflows/ci.yml   tests + bandit + pip-audit + gitleaks on every push
docs/architecture-and-security.md   design rationale, request flows and limitations
```

## Running it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then fill in the secrets as described in the file
flask --app run run --debug   # http://127.0.0.1:5000
```

Without a `.env` the development config generates throwaway keys and warns you.
Production (`FLASK_CONFIG=production`) refuses to start without them.

To try the assistant, put a key from https://cloud.cerebras.ai in
`CEREBRAS_API_KEY`. Without one the endpoint answers 502 "unavailable" and
everything else keeps working.

## Tests and scans

```bash
python -m pytest -q             # 85 tests
bandit -r app -ll               # static analysis
pip-audit -r requirements.txt   # known-vulnerable dependencies
```

The design and security choices are explained in
[`docs/architecture-and-security.md`](docs/architecture-and-security.md).

To create a clean submission archive containing only committed files:

```bash
git archive --format=zip --output=riverside-clinic-submission.zip HEAD
```

## API summary

| Method | Path | Who |
|---|---|---|
| POST | /api/auth/register, /login, /refresh, /forgot-password, /reset-password | anyone |
| POST | /api/auth/logout | any logged-in user |
| GET  | /api/auth/me, /api/me/export · DELETE /api/me | any logged-in user |
| POST/GET | /api/documents · GET /api/documents/{id}[/download] · DELETE /api/documents/{id} | patient (own), clinician (read all) |
| GET  | /api/patients?q= | clinician |
| GET/POST | /api/messages | any logged-in user |
| POST | /api/chat | patient, clinician |
| GET  | /api/admin/users · POST /api/admin/users/{id}/deactivate | admin |

All API calls use `Authorization: Bearer <access token>`. Access tokens live
15 minutes; refresh tokens rotate on every use and can be revoked.
The HTML pages under `/` use an HttpOnly cookie plus CSRF tokens instead.
