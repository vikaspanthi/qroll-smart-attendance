# QRoll — Smart Attendance Management (backend starter)

Independent project inspired by the supplied QRoll Attendance Register. It is not the original source application and is not an official VIT Bhopal deployment. The companion `qroll_smart_attendance.html` is a local browser demo; this API is a separate backend foundation.

## Current implementation status

Implemented in `qroll_api.py`: SQLAlchemy relational entities, password hashing with Argon2, JWT login, admin bootstrap, admin/faculty roles, students, subjects, enrolments, sessions, unmarked/present/absent records, server-side HMAC-signed short-lived QR payloads, authenticated check-in mapped to a student's roster email, duplicate prevention, scan-attempt and audit records, CSV/XLSX/PDF export, XLSX roster preview/confirmation endpoints, health endpoint, and QR tamper/signature tests.

Not yet implemented or production-verified: database migration files/Alembic, a complete frontend integration, student-account provisioning and identity-provider integration, mobile camera QR decoding, true QR image generation endpoint, transaction-safe concurrent replay/nonces, configurable late policy enforcement, rate limiting, import preview UI and import history, PDF layouts beyond basic report, full test coverage, monitoring, backup automation, CI execution, production deployment, or penetration testing. Do not use real student data until these are completed and reviewed.

## Run locally

Requires Python 3.11+.

```sh
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
cp .env.example .env
# Set unique JWT_SECRET, QR_SECRET and bootstrap admin values in .env
set -a; . ./.env; set +a       # Windows PowerShell: load values manually
uvicorn qroll_api:app --reload
```

Open `http://127.0.0.1:8000/docs` for interactive OpenAPI documentation. The default development database is a local SQLite file; set PostgreSQL `DATABASE_URL` for a shared environment. `Base.metadata.create_all` is convenient for local evaluation only; use Alembic migrations before production.

Bootstrap the first administrator once, matching `BOOTSTRAP_ADMIN_EMAIL` exactly:

```sh
curl -X POST http://127.0.0.1:8000/auth/bootstrap \
 -H 'Content-Type: application/json' \
 -d '{"email":"admin@example.edu","password":"use-a-long-unique-password","role":"admin"}'
```

Login using OAuth2 form fields `username` (email) and `password` at `/auth/token`; use its bearer token for protected endpoints. Close bootstrap by removing that endpoint or guarding it with a controlled one-time deployment procedure after provisioning.

## Main API workflow

1. Admin creates a faculty account (`POST /auth/users`).
2. Faculty/admin creates students and a subject (`POST /students`, `/subjects`).
3. Enrol students (`POST /subjects/{subject_id}/enrolments/{student_id}`).
4. Open a class date (`POST /subjects/{subject_id}/sessions`, date format `DD/MM/YYYY`). Each enrollee begins as unmarked.
5. Fetch rotating server-signed payload (`GET /sessions/{id}/qr`) and deliver it through a trusted client. Use `/pause` and `/end` to control session lifecycle.
6. A signed-in student calls `/sessions/{id}/checkin` with `X-QRoll-Payload`. Current identity mapping requires the signed-in user's email to match a roster student's email. Student account provisioning is not included in this starter.
7. Faculty may record P/A manually via `/sessions/{id}/mark`.
8. Read `/subjects/{id}/register`; export `/export.csv`, `/export.xlsx`, or `/export.pdf`.

XLSX import currently separates validation preview (`POST /subjects/{id}/import.xlsx`) from commit (`POST /subjects/{id}/import-confirm`). The confirm endpoint accepts validated student JSON rows; a production client should hold the preview, show conflicts, and require explicit confirmation. Import does not overwrite attendance records.

## Environment variables

See `.env.example`. Secrets must be generated independently and stored in a secrets manager in production, never committed. Use HTTPS, managed PostgreSQL, a reverse proxy/API gateway, network restrictions, logging redaction, and a tested backup/restore process.

## Tests

```sh
pytest -q qroll_api.py
```

The included tests cover QR signature acceptance, wrong-session binding, and tampering only. They are smoke tests, not a complete security or regression suite.

## GitHub checklist

- Commit `.env.example`, never `.env`, credentials, database files, or real student data.
- Enable branch protection and secret scanning.
- Add CI for linting, migrations, and full tests before merge.
- Require institutional security/privacy review and deployment approval.
- Configure retention, access controls, audit review, incident response, and encrypted off-site backups.
- Do not describe this starter as production-ready until the outstanding items above are delivered and tested.
