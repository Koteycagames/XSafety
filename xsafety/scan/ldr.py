"""LDR — Lightweight Detection Rules: компактное кодирование сигнатур.

Паттерны и строковые маркеры в модулях сигнатур хранятся в виде
``L("...")``/``B("...")`` и декодируются при импорте. Это не шифрование
и не защита от целевого реверса: ключ лежит рядом, а цель — чтобы
сигнатуры не читались простым поиском по репозиторию и не копировались
автоматически. Целостность правил обеспечивается тестами, а не секретом
(см. SECURITY.md, дефект D-02).

Формат токена: urlsafe-base64 от (UTF-8 байты XOR повторяющийся ключ).
"""

from __future__ import annotations

import base64

_KEY = bytes.fromhex("f5bb863795b026ba6c956c5e844c0cb9d4d5d1fbf0330651220dbde9189aaf77")


def _xor(data: bytes) -> bytes:
    key = _KEY
    size = len(key)
    return bytes(byte ^ key[index % size] for index, byte in enumerate(data))


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(_xor(value)).decode("ascii").rstrip("=")


def _decode(token: str) -> bytes:
    padded = token + "=" * (-len(token) % 4)
    return _xor(base64.urlsafe_b64decode(padded.encode("ascii")))


def L(token: str) -> str:
    """Декодирует текстовый LDR-маркер."""
    return _decode(token).decode("utf-8")


def B(token: str) -> bytes:
    """Декодирует бинарный LDR-маркер."""
    return _decode(token)


def encode_text(value: str) -> str:
    """Кодирует строку (для генератора правил и тестов)."""
    return _encode(value.encode("utf-8"))


def encode_bytes(value: bytes) -> str:
    return _encode(value)


__all__ = ["B", "L", "encode_bytes", "encode_text"]
