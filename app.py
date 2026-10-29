"""Session Gate: small local-first SQL authentication learning app."""

import hashlib
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware
from database import Database

ROOT = Path(__file__).parent
COOKIE = "session_gate"
SESSION_SECONDS = 8 * 3600
ANON_SECONDS = 1800
hasher = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=1)
# Unknown-account login also verifies an Argon2id hash. Not a constant-time claim.
DUMMY_HASH = hasher.hash(secrets.token_urlsafe(32))


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value):
        value = value.strip().lower()
        if not re.fullmatch(
            r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}",
            value,
        ):
            raise ValueError("Enter a valid email address")
        return value

    @field_validator("password")
    @classmethod
    def valid_password(cls, value):
        if "\x00" in value:
            raise ValueError("Password cannot contain a null character")
        return value  # Never trim or silently truncate passwords.


class Registration(Credentials):
    name: str = Field(min_length=1, max_length=60)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value):
        value = value.strip()
        if not value or any(ord(c) < 32 for c in value):
            raise ValueError("Enter a display name")
        return value


def create_app(
    db_path="local-data/auth.sqlite3",
    origin="http://127.0.0.1:8000",
    secure=False,
    clock=time.time,
):
    site = urlsplit(origin)
    if (
        site.scheme not in ("http", "https")
        or not site.hostname
        or site.path
        or site.query
        or site.fragment
        or site.username
    ):
        raise ValueError(
            "APP_ORIGIN must be one exact http(s) origin, with no trailing slash"
        )
    if site.scheme == "https" and not secure:
        raise ValueError("HTTPS requires COOKIE_SECURE=true")
    if site.scheme == "http" and (
        secure or site.hostname not in ("127.0.0.1", "localhost", "testserver")
    ):
        raise ValueError(
            "HTTP is allowed only for local development with COOKIE_SECURE=false"
        )
    db = Database(db_path)
    app = FastAPI(title="Session Gate", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.db = db
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[site.hostname])
    # Bound simultaneous memory-hard work: two Argon2 operations, about128MiB.
    slots = threading.BoundedSemaphore(2)

    @app.middleware("http")
    async def boundary(request, call_next):
        if request.method == "POST":
            if request.headers.get("origin") not in (None, origin):
                return JSONResponse({"detail": "Same-origin requests only"}, 403)
            if request.headers.get("sec-fetch-site") == "cross-site":
                return JSONResponse({"detail": "Same-origin requests only"}, 403)
            if (
                request.headers.get("content-type", "").split(";")[0].strip().lower()
                != "application/json"
            ):
                return JSONResponse({"detail": "JSON required"}, 415)
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 4096:
                    return JSONResponse({"detail": "Maximum body is 4 KiB"}, 413)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            }
        )
        if secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    # Do not echo passwords from Pydantic validation error input/context.
    from fastapi.exceptions import RequestValidationError

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse(
            {
                "detail": "Check your fields: valid email, 12-128 character password, name 1-60 characters."
            },
            422,
        )

    def session(request):
        token = request.cookies.get(COOKIE, "")
        if not token or len(token) > 128:
            return None
        with db.connect() as conn:
            return conn.execute(
                "SELECT s.*, u.email, u.name FROM sessions s LEFT JOIN users u ON u.id=s.user_id "
                "WHERE token_hash=? AND expires_at>?",
                (digest(token), int(clock())),
            ).fetchone()

    def csrf(request):
        current = session(request)
        value = request.headers.get("x-csrf-token", "")
        if not current or not secrets.compare_digest(
            current["csrf"].encode(), value.encode()
        ):
            raise HTTPException(
                403, "Session expired or CSRF token missing. Reload and retry."
            )
        return current

    def issue(response, user_id=None, old=None):
        token, csrf_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        ttl = SESSION_SECONDS if user_id else ANON_SECONDS
        with db.connect() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at<=?", (int(clock()),))
            if old:
                conn.execute("DELETE FROM sessions WHERE token_hash=?", (old,))
            conn.execute(
                "INSERT INTO sessions VALUES(?,?,?,?)",
                (digest(token), user_id, csrf_token, int(clock()) + ttl),
            )
        response.set_cookie(
            COOKIE,
            token,
            max_age=ttl,
            httponly=True,
            secure=secure,
            samesite="strict",
            path="/",
        )
        return csrf_token

    def rate(request, email=None, register=False):
        ip = request.client.host if request.client else "unknown"
        # Ignore X-Forwarded-For. run.py disables proxy-header trust.
        keys = (
            [("register-ip:" + digest(ip), 10)]
            if register
            else [("login-ip:" + digest(ip), 20), ("login-account:" + digest(email), 5)]
        )
        retry = db.consume(keys, int(clock()))
        if retry:
            raise HTTPException(
                429,
                "Too many attempts. Try again later.",
                headers={"Retry-After": str(retry)},
            )

    @app.get("/api/session")
    def bootstrap(request: Request, response: Response):
        current = session(request)
        if current:
            return {
                "csrf": current["csrf"],
                "user": (
                    {"name": current["name"], "email": current["email"]}
                    if current["user_id"]
                    else None
                ),
            }
        # Bound anonymous session creation from repeated clients.
        ip = request.client.host if request.client else "unknown"
        retry = db.consume([("bootstrap:" + digest(ip), 60)], int(clock()))
        if retry:
            raise HTTPException(
                429, "Too many new sessions", headers={"Retry-After": str(retry)}
            )
        return {"csrf": issue(response), "user": None}

    @app.post("/api/register")
    def register(body: Registration, request: Request):
        csrf(request)
        rate(request, register=True)
        if not slots.acquire(blocking=False):
            raise HTTPException(503, "Server busy. Try again shortly.")
        try:
            hashed = hasher.hash(body.password)
            with db.connect() as conn:
                # User-controlled values are data, never SQL source text.
                conn.execute(
                    "INSERT OR IGNORE INTO users(email,name,password_hash,created_at) VALUES(?,?,?,?)",
                    (body.email, body.name, hashed, int(clock())),
                )
        finally:
            slots.release()
        return {
            "message": "If this address is available, your account is ready. Sign in to continue."
        }

    @app.post("/api/login")
    def login(body: Credentials, request: Request, response: Response):
        current = csrf(request)
        rate(request, email=body.email)
        if not slots.acquire(blocking=False):
            raise HTTPException(503, "Server busy. Try again shortly.")
        try:
            with db.connect() as conn:
                user = conn.execute(
                    "SELECT * FROM users WHERE email=?", (body.email,)
                ).fetchone()
            try:
                verified = hasher.verify(
                    user["password_hash"] if user else DUMMY_HASH, body.password
                )
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                verified = False
            if not user or not verified:
                raise HTTPException(401, "Email or password is incorrect.")
            if hasher.check_needs_rehash(user["password_hash"]):
                with db.connect() as conn:
                    conn.execute(
                        "UPDATE users SET password_hash=? WHERE id=?",
                        (hasher.hash(body.password), user["id"]),
                    )
        finally:
            slots.release()
        token = issue(response, user["id"], old=current["token_hash"])
        return {"csrf": token, "user": {"name": user["name"], "email": user["email"]}}

    @app.get("/api/me")
    def me(request: Request):
        current = session(request)
        if not current or not current["user_id"]:
            raise HTTPException(401, "Sign in required.")
        return {"name": current["name"], "email": current["email"]}

    @app.post("/api/logout")
    def logout(request: Request, response: Response):
        current = csrf(request)
        with db.connect() as conn:
            conn.execute(
                "DELETE FROM sessions WHERE token_hash=?", (current["token_hash"],)
            )
        response.delete_cookie(
            COOKIE, httponly=True, secure=secure, samesite="strict", path="/"
        )
        return {"message": "Signed out. This server-side session is revoked."}

    @app.get("/")
    def home():
        return FileResponse(ROOT / "static" / "index.html")

    app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
    return app
