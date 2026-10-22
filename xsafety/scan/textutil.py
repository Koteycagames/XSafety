"""Декодирование и извлечение строк.

* F-01 — разбор только реально нужных байт, без чтения файла целиком;
* поддержка UTF-8/UTF-16 (BOM и без), cp1251 для кириллицы;
* извлечение ASCII и UTF-16LE строк из бинарников для DLL/EXE.
"""

from __future__ import annotations

import re
from typing import Iterator

_UTF16_HINT = re.compile(rb"(?:\x00[\x20-\x7e]){4,}|(?:[\x20-\x7e]\x00){4,}")
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,256}")
_UTF16LE_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){4,256}")

MAX_STRINGS = 4000


def _nul_ratio(data: bytes) -> float:
    sample = data[:65536]
    if not sample:
        return 0.0
    return sample.count(b"\x00") / len(sample)


def decode_text(data: bytes) -> str:
    """Декодирует байты в строку, никогда не выбрасывая исключение."""
    if not data:
        return ""

    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors="replace")
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        try:
            return data.decode("utf-16", errors="replace")
        except Exception:  # pragma: no cover - decode с replace почти не падает
            return data.decode("utf-8", errors="replace")
    if data.startswith(b"\x1bL") or b"\x00" in data[:4]:
        try:
            return data.decode("utf-16", errors="replace")
        except Exception:  # pragma: no cover
            return data.decode("utf-8", errors="replace")

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass

    # UTF-16LE без BOM: много нулевых байтов на чётных позициях.
    if _nul_ratio(data) > 0.2:
        try:
            text = data.decode("utf-16-le", errors="replace")
            if text.count("\x00") * 10 < len(text):
                return text
        except Exception:  # pragma: no cover
            pass

    # cp1251 — чтобы кириллица не превращалась в мусор.
    try:
        return data.decode("cp1251", errors="replace")
    except Exception:  # pragma: no cover
        return data.decode("latin-1", errors="replace")


def iter_strings(data: bytes) -> Iterator[str]:
    """Извлекает ASCII и UTF-16LE строки (≥4 символов) из бинарных данных."""
    count = 0
    for match in _ASCII_RUN.finditer(data):
        text = match.group().decode("ascii", errors="ignore").strip()
        if len(text) >= 4:
            yield text
            count += 1
            if count >= MAX_STRINGS:
                return
    if b"\x00" in data:
        for match in _UTF16LE_RUN.finditer(data):
            text = match.group().decode("utf-16-le", errors="ignore").strip()
            if len(text) >= 4:
                yield text
                count += 1
                if count >= MAX_STRINGS:
                    return


def unique_strings(data: bytes) -> list[str]:
    """Строки без дублей, в порядке появления."""
    seen: set[str] = set()
    result: list[str] = []
    for item in iter_strings(data):
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def printable_snippet(data: bytes, limit: int = 120) -> str:
    """Короткий читаемый фрагмент для доказательства в отчёте."""
    from .types import clean_text

    text = decode_text(data[: limit * 4])
    return clean_text(text, limit)
