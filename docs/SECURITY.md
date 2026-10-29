# Security model, not a security guarantee

## Assumptions

The default app is a single local Python process on 127.0.0.1:8000, used by the
owner with fake accounts. It trusts the OS account and filesystem. Anyone who
can read/modify the SQLite file can access password hashes, CSRF values and
account data. Restrict file permissions; backups can contain sensitive data.
Sessions use random 256-bit opaque identifiers, stored as SHA-256 digests.
CSRF tokens are random and session-bound, stored in SQL and returned only to
same-origin JavaScript. This does not defeat XSS or a compromised browser.

## Implemented boundaries

- Every user-controlled query value uses SQLite parameter binding. No dynamic
  SQL identifiers. Schema SQL is static project text, not user input.
- Argon2id:64 MiB memory,time_cost 2,parallelism 1. Two hash operations admitted
  concurrently. No passwords in logs, API responses or validation errors.
- Eight-hour absolute authenticated expiry,30 min anonymous expiry, session
  rotation on login and SQL deletion on logout. No refresh tokens/JWT/localStorage.
- HttpOnly,SameSite=Strict,Path=/ cookies. Secure is intentionally off for local
  HTTP; HTTPS requires Secure=true and adds HSTS. Config rejects remote HTTP.
- All POSTs require JSON (4 KiB maximum actually read), matching session/CSRF,
  origin if supplied, and reject cross-site Fetch Metadata. Missing Origin from
  a nonbrowser client is allowed only with a valid cookie + CSRF pair.
- Exact configured hostname check. No permissive CORS. Browser code uses safe
  text insertion and external same-origin scripts only; CSP forbids inline
  scripts, objects, framing and foreign connections. Permissions-Policy disables
  camera, microphone and geolocation because this app does not use them.
- Persistent fixed-window account/IP attempt counters use BEGIN IMMEDIATE,
  so concurrent requests share one admission decision. Expired counters and
  sessions are pruned on writes. This bounds lifetime, not total disk at scale.
- Client IP comes from the direct socket. run.py disables proxy header trust.
  Never trust arbitrary X-Forwarded-For sent by clients.

## Deliberate limits

Not independently audited. No password reset/change, verified email, MFA,
passkeys, breached-password screening, global logout, admin panel, distributed
rate limiting, bot defense, TLS termination, deployment monitoring or database
encryption. Email format validation does not prove address ownership. Duplicate
registration uses a neutral response and login uses a dummy hash for unknown
accounts; neither establishes constant-time behavior or perfect enumeration
resistance. Errors/rate behavior can still leak information.

Limits count all admitted attempts, even successful logins. A known email can
be temporarily denied service by an attacker until its 10 min window expires.
Per-IP limits also affect shared networks. This is a small learning tradeoff,
not an account-recovery design. Upstream request timeouts/concurrency/global
traffic controls are needed for a public deployment; the Argon2 semaphore alone
is not DoS protection. Database data is unencrypted at rest.

## Before any real deployment

Use HTTPS, trusted proxy configuration, an HTTPS APP_ORIGIN and Secure cookies.
Change the serving/binding topology deliberately; default run.py stays loopback
only. Review Host validation, forwarded headers, domain cookies, rate-limit IP
mapping, timeouts, monitoring, dependency versions, migrations, privacy and
backup/retention rules. Add verified email, recovery and MFA. Test on the actual
platform. Do not expose this demo and assume a cookie flag makes it production.
SQLite fits local use. PostgreSQL/MySQL need code and schema work, not a simple
URL change. Do not use production secrets or real credentials in demos/issues.

## Responsible issue reports

For this local learning repo, file a minimal reproduction using fake data.
Never include passwords, cookies, live account data or private database files.
