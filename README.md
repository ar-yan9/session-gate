# Session Gate

A small, local-first login and registration app with a real SQL backend.
Dark green responsive UI, FastAPI, SQLite and Argon2id. Free to run locally.
No third-party scripts, analytics, cloud database or paid service.

**Learning project, not a production identity provider or a security certification.**
Use fake lab accounts and a unique test passphrase. It does not send email, verify
address ownership, reset passwords or support MFA. GitHub hosts the source,
not a live Python backend. Do not enter your real email-service password.

## Run on Windows

Install Python 3.11+ and Git. In a new terminal:

```powershell
git clone https://github.com/ar-yan 9/session-gate.git
cd session-gate
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run.py
```

Open **http://127.0.0.1:8000**. Keep that exact address, not `localhost`, so the
configured origin and browser cookie match. No Node, Docker, MySQL install or
virtual machine is needed. On an 8 GB laptop, close heavy apps; this has not been
benchmarked on your machine. Stop the server with Ctrl+C.

1. Choose **Create account**. Enter a fake lab email, name and 12-128 character
   unique passphrase. Example address: `learner@example.com`. No seeded account.
2. Registration deliberately gives the same message for a new or existing email.
3. Sign in with the account you created. Protected `/api/me` reads your identity.
4. Refresh: the cookie still works until the 8-hour absolute server expiry.
5. Sign out: the server deletes this session, so replaying that cookie fails.

Database tables are created on first start in `local-data/auth.sqlite3`.
They persist across restarts. To reset **your disposable lab data**, stop the
server and delete `local-data`. This deletes accounts, sessions and counters.
Never commit the folder. Keep local disk access restricted to your OS account.

Linux/macOS: use `python3 -m venv .venv`, `.venv/bin/python -m pip install -r requirements.txt`
and `.venv/bin/python run.py`.

## Check the project

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
```

CI runs tests on Windows + Ubuntu, Python 3.11/3.12, and checks JavaScript syntax.
The UI is plain HTML/CSS/JavaScript, not a framework build. Screenshots and manual
browser tests supplement API tests; CI does not claim full browser coverage.

## What it demonstrates

- SQL parameter binding with `?`, not concatenated input; unique email constraint
  and transactions. SQLite is a relational SQL database, not MySQL.
- Argon2id password hashing with per-password salt. Passwords aren't encrypted
  for later recovery. Rehash-on-login when parameters change.
- Random opaque session cookie. Only its SHA-256 digest is stored in SQL.
  Login rotates the anonymous session ID and CSRF token; logout revokes it.
- HttpOnly, SameSite=Strict cookie. Local HTTP deliberately has Secure **off**;
  HTTPS configuration requires Secure **on**, with HSTS. No localStorage tokens.
- Session-bound CSRF header on **every POST**, including login/registration;
  same-origin checks, no CORS allowlist and restrictive script policy.
- Persistent, atomic, fixed 10-minute limits: five login attempts per normalized
  email,20 per client IP,10 registrations per IP;60 new anonymous sessions per IP.
  All admitted login attempts count, including successful ones.429 includes
  Retry-After. Wait for the window; there is no permanent lockout.
- Two simultaneous memory-hard password operations at most, to bound this
  part of RAM use; excess concurrent requests return 503. Each Argon2 operation
  uses 64 MiB configured memory. Total app RAM has not been measured here.
- Name/email/password validation;4 KiB POST body cap; no password reflection in
  validation errors. Names are rendered with textContent, not HTML.

This is defense in depth, not proof against every attack. Rate limits can be
abused to temporarily block a known account; distributed abuse needs a different
strategy. Unknown-user login uses a dummy hash, not a constant-time guarantee.

## Files and learning

- [From zero, Hinglish](docs/FROM_ZERO.md): file map and request/SQL/session flow.
- [Security model and limits](docs/SECURITY.md): exact assumptions and deploy gaps.
- `app.py`: API, validation, CSRF, cookie policy, password verification.
- `database.py` / `schema.sql`: SQL persistence and atomic limit counters.
- `static/`: accessible labels, keyboard focus, responsive form and protected view.
- `run.py`: loopback-only server, `.env` settings, no proxy-header trust.
- `test_auth.py`: isolated temporary SQL databases and API regressions.
- `.env.example`: optional non-secret configuration. Copy to `.env` only if needed.

## SQLite vs MySQL/PostgreSQL

SQLite is the working backend in this project. MySQL/PostgreSQL are **not wired
up**. Moving requires a new database adapter/driver, schema migrations, placeholder
and upsert changes, concurrency review, credentials via environment/vault, and
rerunning the auth/limiter tests. It is not a connection-string-only swap.

No claim of audit, production readiness, email ownership verification or security
against a compromised browser/OS. Read the limits before exposing any auth app.
