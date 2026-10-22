"""Дымовой тест интерфейса: app.js в jsdom с заглушкой Firebase."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")


def _has_jsdom() -> bool:
    if NODE is None:
        return False
    probe = subprocess.run(
        [NODE, "-e", "require.resolve('jsdom')"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return probe.returncode == 0


JS_DOM = _has_jsdom()


@pytest.mark.skipif(not JS_DOM, reason="нужен jsdom: npm install --no-save jsdom")
def test_ui_smoke():
    completed = subprocess.run(
        [NODE, "--experimental-loader", "./tests/web/loader.mjs", "tests/web/ui_smoke.mjs"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=240,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "6 сценариев" in completed.stdout
