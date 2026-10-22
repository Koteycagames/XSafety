"""Типы данных сканера: серьёзность, находка, файл, результат, бюджет.

Все строки из проверяемого файла считаются недоверенными. Они очищаются
от управляющих символов и обрезаются ещё до попадания в Finding, а
экранирование для HTML выполняет фронтенд через textContent
(см. SECURITY.md, цикл 3, V-14).
"""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from ..config import MAX_TEXT_ANALYZE_BYTES

_CONTROL = {c: None for c in range(0x20) if c not in (0x09, 0x0A, 0x0D)}
_CONTROL.update({0x7F: None})
_CONTROL.update({c: None for c in range(0x80, 0xA0)})


def clean_text(value: str, limit: int = 200) -> str:
    """Убирает управляющие символы, схлопывает пробелы, обрезает длину.

    Возвращает безопасную для логов и JSON строку; HTML-экранирование —
    обязанность слоя отображения.
    """
    if not value:
        return ""
    value = value.translate(_CONTROL)
    value = " ".join(value.split())
    if len(value) > limit:
        value = value[: limit - 1].rstrip() + "…"
    return value


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def label(self) -> str:
        return _SEVERITY_LABEL[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_SEVERITY_LABEL = {
    Severity.INFO: "Информация",
    Severity.LOW: "Низкая",
    Severity.MEDIUM: "Средняя",
    Severity.HIGH: "Высокая",
    Severity.CRITICAL: "Критическая",
}


@dataclass(frozen=True, slots=True)
class Finding:
    sig_id: str
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    entry: str | None = None
    offset: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "sig_id": self.sig_id,
            "title": self.title,
            "severity": self.severity.value,
            "severity_label": self.severity.label,
            "description": self.description,
            "evidence": self.evidence,
            "entry": self.entry,
            "offset": self.offset,
        }


@dataclass(slots=True)
class ScanBudget:
    """Общий бюджет на одну проверку.

    Нужен, чтобы вложенные архивы и «тяжёлые» образцы не могли съесть
    память и процессор: учитываются байты, записи и общий дедлайн.
    """

    max_bytes: int = 64 * 1024 * 1024
    max_seconds: float = 20.0
    bytes_used: int = 0
    entries: int = 0
    max_findings: int = 300
    findings: int = 0
    started: float = field(default_factory=time.monotonic)
    truncated: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    @property
    def exhausted(self) -> bool:
        return self.elapsed > self.max_seconds or self.bytes_used > self.max_bytes

    def take_bytes(self, amount: int) -> int:
        """Резервирует до ``amount`` байт, возвращает разрешённый объём."""
        with self._lock:
            remaining = max(self.max_bytes - self.bytes_used, 0)
            allowed = min(max(amount, 0), remaining)
            self.bytes_used += allowed
            if allowed < amount:
                self.truncated = True
        return allowed

    def take_finding(self) -> bool:
        with self._lock:
            if self.findings >= self.max_findings:
                self.truncated = True
                return False
            self.findings += 1
        return True

    def take_entry(self) -> bool:
        with self._lock:
            self.entries += 1
            return self.entries <= 512


@dataclass(slots=True)
class ScanFile:
    """Один проверяемый объект (файл или элемент архива)."""

    name: str
    data: bytes
    ext: str
    size: int
    model: str
    depth: int = 0
    entry: str | None = None
    parent: str | None = None
    _text: str | None = field(default=None, repr=False)
    _strings: list[str] | None = field(default=None, repr=False)

    @property
    def display_name(self) -> str:
        return self.entry or self.name

    @property
    def text(self) -> str:
        """Текст для сигнатур: BOM-aware декодирование, обрезка по лимиту."""
        if self._text is None:
            from .textutil import decode_text

            self._text = decode_text(self.data[:MAX_TEXT_ANALYZE_BYTES])
        return self._text

    @property
    def strings(self) -> list[str]:
        """ASCII и UTF-16LE строки для бинарных форматов."""
        if self._strings is None:
            from .textutil import iter_strings

            self._strings = list(iter_strings(self.data))
        return self._strings

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


@dataclass(slots=True)
class ScanResult:
    filename: str
    extension: str
    model: str
    size: int
    sha256: str
    verdict: str
    findings: list[Finding]
    scanned_entries: int
    analyzed_bytes: int
    elapsed_ms: int
    notes: list[str] = field(default_factory=list)

    @property
    def worst(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> dict[str, object]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return {
            "filename": self.filename,
            "extension": self.extension,
            "model": self.model,
            "size": self.size,
            "sha256": self.sha256,
            "verdict": self.verdict,
            "worst_severity": self.worst.value,
            "worst_severity_label": self.worst.label,
            "counts": counts,
            "findings": [f.to_dict() for f in self.findings],
            "scanned_entries": self.scanned_entries,
            "analyzed_bytes": self.analyzed_bytes,
            "elapsed_ms": self.elapsed_ms,
            "notes": self.notes,
        }


def verdict_for(findings: Iterable[Finding]) -> str:
    worst = Severity.INFO
    for finding in findings:
        if finding.severity.rank > worst.rank:
            worst = finding.severity
    if worst.rank >= Severity.HIGH.rank:
        return "malicious"
    if worst.rank >= Severity.LOW.rank:
        return "suspicious"
    return "clean"
