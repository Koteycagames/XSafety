"""Безопасность: LDR, пароли, экранирование отчёта, устойчивость разбора."""

from __future__ import annotations

from pathlib import Path

import pytest

from xsafety.auth import (
    burn_password_check,
    csrf_equal,
    hash_password,
    normalize_email,
    token_fingerprint,
    valid_email,
    validate_password,
    verify_password,
)
from xsafety.report import build_html_report, result_from_dict
from xsafety.scan.ldr import B, L, encode_bytes, encode_text
from xsafety.scan.signatures import RULES
from xsafety.scan.types import Finding, ScanResult, Severity
from xsafety.storage import MAX_HISTORY, Storage

ROOT = Path(__file__).resolve().parent.parent
SIGNATURE_DIR = ROOT / "xsafety" / "scan" / "signatures"


def test_ldr_roundtrip():
    values = [
        "powershell -enc",
        r"\b(vssadmin|wbadmin)\s+delete",
        "Привет, мир",
        "-----BEGIN PRIVATE KEY-----",
        "🎯 emoji",
    ]
    for value in values:
        token = encode_text(value)
        assert L(token) == value
    binary = b"\x00\x01MZ\xff"
    assert B(encode_bytes(binary)) == binary


def test_signature_modules_have_encoded_rules():
    modules = ["common.py", "bat.py", "py.py", "js.py", "ps1.py", "vbs.py", "hta.py", "dll.py", "exe.py", "jar.py", "zip.py"]
    for name in modules:
        source = (SIGNATURE_DIR / name).read_text()
        assert 'L("' in source, f"{name}: LDR-маркеры не найдены"
        assert "from ..ldr import" in source


def test_plain_patterns_are_not_in_source():
    sources = "\n".join(path.read_text() for path in SIGNATURE_DIR.glob("*.py"))
    forbidden = [
        r"\bformat\s+",
        r"\bvssadmin(?:\.exe)?\s+delete\s+shadows",
        r"AKIA[0-9A-Z]{16}",
        r"eval\s*\(\s*(?:atob",
        r'"VirtualAllocEx", "WriteProcessMemory"',
        r"Add-MpPreference[^\r\n]*-Exclusion",
    ]
    for pattern in forbidden:
        assert pattern not in sources, f"паттерн остался в исходниках: {pattern}"


def test_rules_are_unique_and_compile():
    ids = [rule.sig_id for rule in RULES]
    assert len(ids) == len(set(ids))
    assert len(RULES) >= 120
    for rule in RULES:
        assert rule.sig_id
        assert rule.title
        assert rule.description
        for compiled in rule.compiled:
            assert compiled.pattern


def test_each_extension_has_rules():
    for extension in ("bat", "py", "js", "ps1", "vbs", "hta", "dll", "exe"):
        assert any(rule.extensions and extension in rule.extensions for rule in RULES), extension


def test_password_hashing():
    first = hash_password("password123")
    second = hash_password("password123")
    assert first != second  # соль уникальна
    assert first.startswith("pbkdf2_sha256$")
    assert verify_password("password123", first)
    assert not verify_password("password124", first)
    assert not verify_password("", first)
    assert not verify_password("x", "broken-hash")


def test_burn_password_check_runs():
    burn_password_check("password")  # не должно бросать исключений


def test_email_and_password_validation():
    assert valid_email("user@example.com")
    assert valid_email(normalize_email(" USER@Example.COM "))
    assert not valid_email("user@")
    assert not valid_email("a" * 300 + "@example.com")
    assert validate_password("short") is not None
    assert validate_password("long-enough") is None


def test_token_fingerprint_and_csrf():
    token = "abc" * 20
    assert len(token_fingerprint(token)) == 64
    assert token_fingerprint(token) != token
    assert csrf_equal("same-value", "same-value")
    assert not csrf_equal("same-value", "other-value")


def test_report_escapes_evidence_and_filename():
    result = ScanResult(
        filename='<script>alert("x")</script>.bat',
        extension="bat",
        model="m1",
        size=10,
        sha256="0" * 64,
        verdict="malicious",
        findings=[
            Finding(
                sig_id="bat.test",
                title="<b>Опасность</b>",
                severity=Severity.CRITICAL,
                description='Описание с <img src=x onerror=alert(1)> и "кавычками"',
                evidence='<script>alert("evidence")</script>',
                entry="../../<svg/onload=alert(1)>.bat",
                offset=3,
            )
        ],
        scanned_entries=1,
        analyzed_bytes=10,
        elapsed_ms=1,
        notes=["<iframe src=//evil>"],
    )
    html = build_html_report(result)
    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "<iframe src" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x" in html


def test_report_result_from_dict_roundtrip():
    result = ScanResult(
        filename="x.bat",
        extension="bat",
        model="m1",
        size=17,
        sha256="a" * 64,
        verdict="suspicious",
        findings=[Finding("bat.x", "t", Severity.HIGH, "d", "e", None, 2)],
        scanned_entries=1,
        analyzed_bytes=17,
        elapsed_ms=3,
        notes=["n"],
    )
    restored = result_from_dict(result.to_dict())
    assert restored is not None
    assert restored.filename == "x.bat"
    assert restored.findings[0].severity is Severity.HIGH
    assert restored.findings[0].offset == 2
    assert restored.notes == ["n"]


def test_result_from_dict_tolerates_garbage():
    assert result_from_dict({}) is not None  # пустой отчёт не должен ронять рендер
    assert result_from_dict({"findings": "not-a-list", "size": "abc"}) is None
    tolerant = result_from_dict({"findings": [{"severity": "unknown"}, "junk"]})
    assert tolerant is not None


def test_result_from_dict_limits_payload():
    payload = {
        "filename": "x" * 5000,
        "findings": [{"sig_id": "s", "title": "t", "severity": "info", "description": "d"}] * 500,
        "notes": ["n"] * 100,
    }
    restored = result_from_dict(payload)
    assert restored is not None
    assert len(restored.filename) <= 180
    assert len(restored.findings) <= 200
    assert len(restored.notes) <= 24


def test_history_is_trimmed(tmp_path):
    storage = Storage(tmp_path / "history.db")
    user = storage.create_user("history@example.com", "hash")
    for index in range(MAX_HISTORY + 5):
        storage.add_scan(
            user.id,
            {
                "filename": f"f{index}.bat",
                "extension": "bat",
                "model": "m1",
                "verdict": "clean",
                "worst_severity": "info",
                "findings": [],
                "size": 1,
                "sha256": "0" * 64,
            },
        )
    scans = storage.list_scans(user.id, limit=100)
    assert len(scans) == MAX_HISTORY
    assert scans[0]["filename"] == f"f{MAX_HISTORY + 4}.bat"
