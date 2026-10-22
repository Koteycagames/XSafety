"""Утилиты для сигнатур: компиляция, доказательства, редакция секретов.

Доказательство (evidence) в отчёте не должно содержать пароли, токены и
query-параметры. Всё, что попадает в Finding, проходит через
``safe_evidence`` (см. SECURITY.md, цикл 3, V-14).
"""

from __future__ import annotations

from .ldr import L
import base64
import binascii
import math
import re
from typing import Iterable

from .types import clean_text

_FLAGS = re.IGNORECASE | re.MULTILINE

_KEY_VALUE = re.compile(
    L("3YTvHsnSDsoN5h92u3Z71qaxrYyUGjktUnrZlWz1xBKbx_VS9sJDzhD0HDffEyHk6760goxSdjhJaMTARPiHK4aR3Q2o7XrJRrxEAtc3P5Wp_A")
)
_BEARER = re.compile(L("3YTvHsnSDtgJ9B479hB_kv39irrdaWd8WD2Q0DbF81qowL4b6Jk"))
_URL_USERINFO = re.compile(L("3YTvHsnSDtIY4Rwtu3Yjlv39iqXfb3VrYlDG2zTnhk3d4NgYycNm5xenQCOtDA"))
_TOKEN_IN_URL = re.compile(
    L("3YTvHr3rGZwxvVNk8CNn3Lqpup6JT2chS2bYkGT73x6q0ONO6dFF2QnmHwHwI2fcuqmhmoNAcT5QacGZeencAJHH9kDxzFXTC-kfN-Mibc2hp7TSzRouCnwr4ZpF4Z1biJI")
)


def build(pattern: str, flags: int = 0) -> re.Pattern[str]:
    """Компилирует регулярку сигнатуры с общими флагами."""
    return re.compile(pattern, _FLAGS | flags)


def line_number(text: str, offset: int) -> int:
    if offset <= 0:
        return 1
    return text.count("\n", 0, min(offset, len(text))) + 1


def window(text: str, start: int, end: int, pad: int = 48) -> str:
    """Фрагмент вокруг совпадения, очищенный от управляющих символов."""
    left = max(start - pad, 0)
    right = min(end + pad, len(text))
    return clean_text(text[left:right], 180)


def _mask(value: str) -> str:
    value = value.strip().strip('"\'')
    if not value:
        return ""
    return "***" if len(value) <= 8 else value[:2] + "***"


def redact(text: str) -> str:
    """Вырезает пароли/токены/учётные данные из фрагмента."""
    if not text:
        return ""
    text = _KEY_VALUE.sub(lambda m: f"{m.group(1)}{m.group(2)}{_mask(m.group(3))}", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}", text)
    text = _URL_USERINFO.sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}:***@", text)
    text = _TOKEN_IN_URL.sub(lambda m: f"{m.group(1)}***", text)
    return text


def safe_evidence(text: str, start: int, end: int) -> str:
    """Готовит доказательство: окно вокруг совпадения + редакция + очистка."""
    return redact(window(text, start, end))


def redact_url(url: str, limit: int = 120) -> str:
    """URL без логина/пароля и query-строки — для отчёта и логов."""
    url = url.strip().strip(L("15y6CQ"))
    url = re.sub(L("3YTvHsuYTs4Y5R9hvmMjkI-L_rusQFt6Yg"), r"\1", url)
    url = url.split("#", 1)[0].split("?", 1)[0]
    return clean_text(url, limit)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def iter_matches(pattern: re.Pattern[str], text: str, limit: int = 20) -> Iterable[re.Match[str]]:
    seen = 0
    for match in pattern.finditer(text):
        yield match
        seen += 1
        if seen >= limit:
            return


def is_probably_base64(chunk: str) -> bool:
    if len(chunk) < 40 or len(chunk) % 4 != 0:
        return False
    if not re.fullmatch(L("rvqrbfSdXIpBrEdxuRB-5bqI-g"), chunk):
        return False
    return shannon_entropy(chunk[:200]) > 4.0


def try_b64decode(chunk: str, max_bytes: int = 65536) -> str | None:
    """Пытается декодировать base64 и вернуть печатный текст.

    Возвращает ``None``, если результат похож на случайный шум.
    """
    compact = re.sub(r"\s+", "", chunk)[: max_bytes * 2]
    if not compact:
        return None
    padding = "=" * (-len(compact) % 4)
    try:
        raw = base64.b64decode(compact + padding, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    from .textutil import decode_text

    text = decode_text(raw[:max_bytes])
    if not text:
        return None
    printable = sum(1 for c in text[:4000] if c.isprintable() or c in "\r\n\t")
    if printable / max(len(text[:4000]), 1) < 0.85:
        return None
    return text


def collapse_code(text: str) -> str:
    """Нормализация кода для поиска обфускации: без пробелов и регистра."""
    return re.sub(r"\s+", "", text).lower()


def pack_little_endian(value: int, size: int = 4) -> bytes:
    return int(value).to_bytes(size, L("mdLyQ_nV"), signed=False)
