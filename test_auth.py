import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient
from app import create_app, COOKIE, hasher
from database import Database

PASSWORD = "synthetic test passphrase 47!"


@pytest.fixture
def env(tmp_path):
    now = [1000000]
    app = create_app(
        tmp_path / "test.sqlite3", origin="http://testserver", clock=lambda: now[0]
    )
    with TestClient(app) as client:
        yield client, app.state.db, now, app


def boot(client):
    return client.get("/api/session").json()["csrf"]


def post(client, route, body, csrf):
    return client.post("/api/" + route, json=body, headers={"X-CSRF-Token": csrf})


def register(client, csrf, email="learner@example.com", name="Lab Learner"):
    return post(
        client, "register", {"email": email, "name": name, "password": PASSWORD}, csrf
    )


def login(client, csrf, email="learner@example.com", password=PASSWORD):
    return post(client, "login", {"email": email, "password": password}, csrf)


def test_register_login_logout_and_no_plaintext(env):
    c, db, _, _ = env
    assert c.get("/api/me").status_code == 401
    csrf = boot(c)
    preauth = c.cookies[COOKIE]
    assert register(c, csrf).status_code == 200
    response = login(c, csrf)
    assert response.status_code == 200
    token = c.cookies[COOKIE]
    assert token != preauth and response.json()["csrf"] != csrf
    assert c.get("/api/me").json()["name"] == "Lab Learner"
    with db.connect() as conn:
        user = conn.execute("SELECT * FROM users").fetchone()
        assert user["password_hash"].startswith("$argon2id$")
        assert hasher.verify(user["password_hash"], PASSWORD)
        rows = [dict(r) for r in conn.execute("SELECT * FROM sessions")]
        assert (
            len(rows) == 1
            and rows[0]["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
        )
        assert token not in json.dumps(rows) and PASSWORD not in json.dumps(dict(user))
    assert post(c, "logout", {}, response.json()["csrf"]).status_code == 200
    c.cookies.set(COOKIE, token)
    assert c.get("/api/me").status_code == 401


def test_csrf_origin_host_and_cookie(env):
    c, _, _, _ = env
    response = c.get("/api/session")
    cookie = response.headers["set-cookie"].lower()
    assert (
        "httponly" in cookie and "samesite=strict" in cookie and "secure" not in cookie
    )
    csrf = response.json()["csrf"]
    body = {"email": "a@example.com", "name": "Learner", "password": PASSWORD}
    assert c.post("/api/register", json=body).status_code == 403
    assert post(c, "register", body, "wrong").status_code == 403
    assert (
        c.post(
            "/api/register",
            json=body,
            headers={"Origin": "https://evil.invalid", "X-CSRF-Token": csrf},
        ).status_code
        == 403
    )
    assert (
        c.post(
            "/api/register",
            json=body,
            headers={"Sec-Fetch-Site": "cross-site", "X-CSRF-Token": csrf},
        ).status_code
        == 403
    )
    assert c.get("/api/session", headers={"Host": "evil.invalid"}).status_code == 400
    assert c.get("/").headers["x-frame-options"] == "DENY"
    assert "script-src 'self'" in c.get("/").headers["content-security-policy"]


def test_secure_cookie(tmp_path):
    with TestClient(
        create_app(tmp_path / "secure.db", origin="https://testserver", secure=True),
        base_url="https://testserver",
    ) as c:
        r = c.get("/api/session")
        assert "; Secure" in r.headers["set-cookie"]
        assert "max-age" in r.headers["strict-transport-security"]


@pytest.mark.parametrize(
    "origin,secure",
    [
        ("https://example.com", False),
        ("http://example.com", False),
        ("http://localhost", True),
        ("http://localhost/", False),
        ("https://user@example.com", True),
    ],
)
def test_unsafe_config_rejected(tmp_path, origin, secure):
    with pytest.raises(ValueError):
        create_app(tmp_path / "bad.db", origin=origin, secure=secure)


def test_generic_duplicate_and_unknown_account(env):
    c, db, _, _ = env
    csrf = boot(c)
    first = register(c, csrf)
    second = register(c, csrf)
    assert first.json() == second.json() and second.status_code == 200
    assert (
        login(c, csrf, password="wrong password 123").json()
        == login(c, csrf, email="absent@example.com").json()
    )
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


def test_sql_injection_strings_do_not_change_query(env):
    c, db, _, _ = env
    csrf = boot(c)
    name = "Robert'); DROP TABLE users;--"
    assert register(c, csrf, name=name).status_code == 200
    assert login(c, csrf, password="' OR '1'='1 --").status_code == 401
    assert login(c, csrf, email="x' OR 1=1--@example.com").status_code == 422
    assert login(c, csrf).status_code == 200
    assert c.get("/api/me").json()["name"] == name
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


def test_account_rate_limit_persists_and_expires(env):
    c, db, now, _ = env
    csrf = boot(c)
    register(c, csrf)
    for _ in range(5):
        assert login(c, csrf, password="wrong password 123").status_code == 401
    blocked = login(c, csrf)
    assert blocked.status_code == 429 and int(blocked.headers["retry-after"]) == 600
    other = create_app(db.path, origin="http://testserver", clock=lambda: now[0])
    with TestClient(other) as second:
        assert login(second, boot(second)).status_code == 429
    now[0] += 601
    assert login(c, csrf).status_code == 200


def test_ip_limit_across_accounts(env):
    c, _, _, _ = env
    csrf = boot(c)
    for n in range(20):
        assert login(c, csrf, email=f"missing{n}@example.com").status_code == 401
    assert login(c, csrf, email="another@example.com").status_code == 429


def test_registration_rate_limit(env):
    c, _, _, _ = env
    csrf = boot(c)
    for _ in range(10):
        assert register(c, csrf).status_code == 200
    assert register(c, csrf).status_code == 429


def test_atomic_limiter(tmp_path):
    db = Database(tmp_path / "limits.db")
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: db.consume([("test", 5)], 1000), range(20)))
    assert results.count(0) == 5 and results.count(600) == 15


def test_expired_and_forged_sessions(env):
    c, _, now, _ = env
    csrf = boot(c)
    register(c, csrf)
    assert login(c, csrf).status_code == 200
    now[0] += 8 * 3600
    assert c.get("/api/me").status_code == 401
    c.cookies.clear()
    c.cookies.set(COOKIE, "not-a-real-session")
    assert c.get("/api/me").status_code == 401


def test_session_survives_restart(env):
    c, db, now, _ = env
    csrf = boot(c)
    register(c, csrf)
    login(c, csrf)
    token = c.cookies[COOKIE]
    with TestClient(
        create_app(db.path, origin="http://testserver", clock=lambda: now[0])
    ) as second:
        second.cookies.set(COOKIE, token)
        assert second.get("/api/me").status_code == 200


@pytest.mark.parametrize("password", ["short", "x" * 129, "invalid\x00password"])
def test_password_validation_does_not_echo_secret(env, password):
    c, _, _, _ = env
    r = login(c, boot(c), password=password)
    assert r.status_code == 422 and password not in r.text


def test_input_transport_and_static_boundary(env):
    c, _, _, _ = env
    assert (
        c.post(
            "/api/login",
            content="x" * 4097,
            headers={"Content-Type": "application/json"},
        ).status_code
        == 413
    )
    assert (
        c.post(
            "/api/login", content="{}", headers={"Content-Type": "application/jsonp"}
        ).status_code
        == 415
    )
    assert c.get("/local-data/auth.sqlite3").status_code == 404
    assert c.get("/schema.sql").status_code == 404
    assert c.get("/static/app.js").status_code == 200
    assert (
        c.post(
            "/api/login", content="{", headers={"Content-Type": "application/json"}
        ).status_code
        == 422
    )


def test_html_names_are_data_not_markup(env):
    c, _, _, _ = env
    csrf = boot(c)
    register(c, csrf, name="<img src=x onerror=alert(1)>")
    login(c, csrf)
    assert c.get("/api/me").json()["name"].startswith("<img")
    script = c.get("/static/app.js").text
    assert ".textContent = verified.name" in script and "innerHTML" not in script


def test_old_csrf_and_anonymous_cookie_revoked_after_login(env):
    c, _, _, _ = env
    csrf = boot(c)
    old_cookie = c.cookies[COOKIE]
    register(c, csrf)
    result = login(c, csrf)
    assert post(c, "logout", {}, csrf).status_code == 403
    assert c.get("/api/me").status_code == 200
    c.cookies.clear()
    c.cookies.set(COOKIE, old_cookie)
    assert c.get("/api/me").status_code == 401
    assert post(c, "logout", {}, result.json()["csrf"]).status_code == 403


def test_bootstrap_limit_and_expired_anonymous_csrf(env):
    c, _, now, _ = env
    csrf = boot(c)
    now[0] += 1801
    assert register(c, csrf).status_code == 403
    for _ in range(60):
        c.cookies.clear()
        assert c.get("/api/session").status_code == 200
    c.cookies.clear()
    assert c.get("/api/session").status_code == 429


def test_forwarded_headers_do_not_split_rate_bucket(env):
    c, _, _, _ = env
    csrf = boot(c)
    for n in range(5):
        r = c.post(
            "/api/login",
            json={"email": "missing@example.com", "password": PASSWORD},
            headers={"X-CSRF-Token": csrf, "X-Forwarded-For": f"192.0.2.{n}"},
        )
        assert r.status_code == 401
    assert login(c, csrf, email="missing@example.com").status_code == 429
