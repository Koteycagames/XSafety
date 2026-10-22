"""HTTP-сценарии: аккаунт, CSRF, сканирование, лимиты, покупки, отчёты."""

from __future__ import annotations

import io
import zipfile
from datetime import datetime, timedelta

from tests.conftest import csrf, csrf_headers, register, scan


def test_index_and_security_headers(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "XSafety" in response.text
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"


def test_plans_catalog_api(client):
    response = client.get("/api/plans")
    assert response.status_code == 200
    payload = response.json()
    assert payload["currency"] == "грн"
    assert payload["refill_hours"] == 24
    assert {model["id"] for model in payload["models"]} == {"m1", "m2", "m3_lite", "m3_pro"}
    pro = next(plan for plan in payload["plans"] if plan["id"] == "pro")
    assert [offer["price"] for offer in pro["offers"]] == [89, 249, 1299]
    assert pro["offers"][1]["discount_label"] == "40,7"


def test_csrf_required_for_state_change(client):
    response = client.post("/api/auth/register", json={"email": "x@example.com", "password": "password123"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"


def test_register_login_logout(client):
    response = client.post(
        "/api/auth/register",
        json={"email": "Person@Example.com", "password": "password123"},
        headers=csrf_headers(client),
    )
    assert response.status_code == 201
    set_cookie = " ".join(response.headers.get_list("set-cookie"))
    assert "HttpOnly" in set_cookie
    assert response.json()["user"]["email"] == "person@example.com"

    me = client.get("/api/me").json()
    assert me["user"]["email"] == "person@example.com"
    assert me["quota"]["plan"] == "default"

    response = client.post("/api/auth/logout", headers=csrf_headers(client))
    assert response.status_code == 200
    assert client.get("/api/me").json()["user"] is None

    response = client.post(
        "/api/auth/login",
        json={"email": "person@example.com", "password": "password123"},
        headers=csrf_headers(client),
    )
    assert response.status_code == 200
    assert client.get("/api/me").json()["user"]["email"] == "person@example.com"


def test_register_validation(client):
    response = client.post(
        "/api/auth/register",
        json={"email": "bad-email", "password": "password123"},
        headers=csrf_headers(client),
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_email"

    response = client.post(
        "/api/auth/register",
        json={"email": "ok@example.com", "password": "short"},
        headers=csrf_headers(client),
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "weak_password"


def test_duplicate_email(client):
    register(client, "dup@example.com")
    response = client.post(
        "/api/auth/register",
        json={"email": "dup@example.com", "password": "password123"},
        headers=csrf_headers(client),
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "email_taken"


def test_login_throttle(client):
    register(client, "throttle@example.com", "password123")
    for _ in range(5):
        response = client.post(
            "/api/auth/login",
            json={"email": "throttle@example.com", "password": "wrong-password"},
            headers=csrf_headers(client),
        )
        assert response.status_code == 401
    response = client.post(
        "/api/auth/login",
        json={"email": "throttle@example.com", "password": "password123"},
        headers=csrf_headers(client),
    )
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "too_many_attempts"


def test_scan_default_plan_and_blocked_model(client):
    register(client)
    response = scan(client, "evil.bat", b"vssadmin delete shadows /all /quiet\r\n", "m1")
    assert response.status_code == 200
    payload = response.json()
    assert payload["result"]["verdict"] == "malicious"
    assert payload["result"]["filename"] == "evil.bat"
    assert payload["quota"]["models"][0]["requests_used"] == 1

    blocked = scan(client, "tool.py", b"print(1)", "m2")
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "model_not_in_plan"
    assert blocked.json()["error"]["details"]["refill_scheduled"] is False


def test_scan_rejects_wrong_extension_for_model(client):
    register(client, "ext@example.com")
    response = scan(client, "tool.py", b"print(1)", "m1")
    assert response.status_code == 200

    response = scan(client, "tool.exe", b"MZ" + b"\x00" * 32, "m1")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "extension_not_allowed"


def test_scan_requires_auth(client):
    response = scan(client, "a.bat", b"echo hi", "m1")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_scan_daily_limit_returns_details(client):
    register(client, "limit@example.com")
    for index in range(10):
        response = scan(client, f"file{index}.bat", b"echo ok", "m1")
        assert response.status_code == 200, response.text
    response = scan(client, "eleventh.bat", b"echo ok", "m1")
    assert response.status_code == 429
    error = response.json()["error"]
    assert error["code"] == "daily_limit"
    assert error["details"]["refill_scheduled"] is True
    assert error["details"]["requests_limit"] == 10
    assert error["details"]["requests_used"] == 10


def test_scan_file_size_limit(client):
    register(client, "big@example.com")
    response = scan(client, "big.bat", b"A" * (10 * 1024 * 1024 + 1), "m1")
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "file_too_large"


def test_purchase_pro_and_premium(client):
    register(client, "buyer@example.com")

    response = client.post(
        "/api/billing/purchase",
        json={"plan": "pro", "offer": "7d"},
        headers=csrf_headers(client),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["demo"] is True
    assert body["user"]["plan"] == "pro"
    until = datetime.fromisoformat(body["user"]["plan_until"])
    assert timedelta(days=6, hours=23) < until - datetime.now(until.tzinfo) <= timedelta(days=7)

    quota_state = {model["model_id"]: model for model in body["quota"]["models"]}
    assert quota_state["m1"]["requests_limit"] == 20
    assert quota_state["m2"]["requests_limit"] == 10
    assert quota_state["m3_lite"]["requests_limit"] == 1
    assert quota_state["m3_pro"]["available"] is False

    # 3 Lite даёт ровно один запрос в сутки.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", "hello")
    first = scan(client, "one.zip", buffer.getvalue(), "m3_lite")
    assert first.status_code == 200, first.text
    second = scan(client, "two.zip", buffer.getvalue(), "m3_lite")
    assert second.status_code == 429

    response = client.post(
        "/api/billing/purchase",
        json={"plan": "premium", "offer": "forever"},
        headers=csrf_headers(client),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["user"]["plan"] == "premium"
    assert body["user"]["plan_until"] is None
    quota_state = {model["model_id"]: model for model in body["quota"]["models"]}
    assert all(model["available"] for model in quota_state.values())
    assert quota_state["m3_pro"]["requests_limit"] == 10


def test_purchase_rejects_invalid_offer(client):
    register(client, "bad@example.com")
    response = client.post(
        "/api/billing/purchase",
        json={"plan": "pro", "offer": "2y"},
        headers=csrf_headers(client),
    )
    assert response.status_code == 422


def test_history_report_and_idor(client):
    register(client, "owner@example.com")
    response = scan(client, "evil.bat", b"del /f /s /q C:\\Windows\\System32\r\n", "m1")
    assert response.status_code == 200
    scan_id = response.json()["scan_id"]

    history = client.get("/api/scans").json()["scans"]
    assert len(history) == 1
    assert history[0]["id"] == scan_id

    report = client.get(f"/api/scans/{scan_id}/report.html")
    assert report.status_code == 200
    assert "del /f /s /q" in report.text
    assert "Content-Disposition" in report.headers

    download = client.get(f"/api/scans/{scan_id}/report.html?download=1")
    assert download.headers["content-disposition"].startswith("attachment")

    client.post("/api/auth/logout", headers=csrf_headers(client))
    register(client, "intruder@example.com")
    assert client.get(f"/api/scans/{scan_id}").status_code == 404
    assert client.get(f"/api/scans/{scan_id}/report.html").status_code == 404
    assert client.delete(f"/api/scans/{scan_id}", headers=csrf_headers(client)).status_code == 404


def test_report_escapes_filename(client):
    register(client, "xss@example.com")
    response = scan(client, '<img src=x onerror=alert(1)>.bat', b"echo ok", "m1")
    assert response.status_code == 200
    report = client.get(f"/api/scans/{response.json()['scan_id']}/report.html")
    assert "<img src=x" not in report.text
    assert "&lt;img" in report.text


def test_delete_scan(client):
    register(client, "delete@example.com")
    scan_id = scan(client, "x.bat", b"echo hi", "m1").json()["scan_id"]
    response = client.delete(f"/api/scans/{scan_id}", headers=csrf_headers(client))
    assert response.status_code == 200
    assert client.get("/api/scans").json()["scans"] == []


def test_admin_endpoint_hidden_without_token(client):
    assert client.post("/api/admin/reset-usage").status_code == 404
    assert client.get("/api/admin/usage").status_code == 404


def test_health(client):
    assert client.get("/api/health").json()["ok"] is True
