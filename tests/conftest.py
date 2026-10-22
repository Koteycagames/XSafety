"""Общие фикстуры тестов.

Важно: модуль ``xsafety.api`` создаёт приложение на импорте, поэтому
``XSAFETY_DB`` подставляется до импорта — тесты не должны трогать
рабочую базу в ``var/``.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("XSAFETY_DB", str(Path(tempfile.mkdtemp(prefix="xsafety-test-")) / "main.db"))
os.environ.pop("XSAFETY_ADMIN_TOKEN", None)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from xsafety.api import create_app  # noqa: E402
from xsafety.storage import Storage  # noqa: E402


@pytest.fixture()
def storage(tmp_path: Path) -> Storage:
    return Storage(tmp_path / "test.db")


@pytest.fixture()
def app(storage: Storage):
    return create_app(storage)


@pytest.fixture()
def client(app):
    with TestClient(app) as test_client:
        test_client.get("/")
        yield test_client


def csrf(client: TestClient) -> str:
    return client.cookies.get("xsafety_xsrf") or ""


def csrf_headers(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": csrf(client)}


def register(client: TestClient, email: str = "user@example.com", password: str = "password123"):
    client.get("/")
    response = client.post(
        "/api/auth/register",
        json={"email": email, "password": password},
        headers=csrf_headers(client),
    )
    assert response.status_code == 201, response.text
    return response.json()


def scan(client: TestClient, filename: str, data: bytes, model: str = "m1"):
    return client.post(
        "/api/scan",
        files={"file": (filename, data, "application/octet-stream")},
        data={"model": model},
        headers=csrf_headers(client),
    )
