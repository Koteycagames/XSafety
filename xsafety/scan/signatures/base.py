"""Каркас сигнатур.

Одна сигнатура = одно правило с уникальным ``sig_id``. Правило живёт в
модуле своего расширения, поэтому отчёт всегда показывает, какая именно
проверка сработала, а не «файл плохой».

Правила не бросают исключений наружу: любая ошибка сигнатуры изолируется
движком (см. ``scan/engine.py``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..pe import PEInfo
from ..sigutil import build, line_number, safe_evidence
from ..textutil import decode_text
from ..types import Finding, ScanFile, Severity

TEXT_EXTENSIONS = frozenset(
    {"bat", "cmd", "py", "pyw", "js", "mjs", "cjs", "ps1", "psm1", "vbs", "vbe", "hta", "txt", "md", "xml", "ini", "cfg", "json", "yaml", "yml"}
)

CheckFn = Callable[[ScanFile, PEInfo | None], Iterable[Finding]]


@dataclass(frozen=True, slots=True)
class Rule:
    """Правило проверки.

    ``patterns`` — регулярки; при ``min_matches > 1`` правило срабатывает
    только когда совпали минимум N разных шаблонов (комбинированная
    эвристика, меньше ложных срабатываний).
    """

    sig_id: str
    title: str
    severity: Severity
    description: str
    patterns: tuple[str, ...] = ()
    extensions: frozenset[str] | None = None
    kind: str = "text"  # text | binary | any | pe | zip
    min_matches: int = 1
    max_findings: int = 3
    check: CheckFn | None = None
    compiled: tuple[re.Pattern[str], ...] = field(default=(), repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.patterns and self.check is None:
            raise ValueError(f"{self.sig_id}: нет ни шаблонов, ни функции проверки")
        if self.patterns:
            object.__setattr__(self, "compiled", tuple(build(p) for p in self.patterns))

    def applies(self, extension: str) -> bool:
        return self.extensions is None or extension in self.extensions

    # ------------------------------------------------------------------
    def run(self, file: ScanFile, pe: PEInfo | None) -> list[Finding]:
        if not self.applies(file.ext):
            return []
        if self.kind == "pe" and pe is None:
            return []
        if self.check is not None:
            found = list(self.check(file, pe))
            return found[: self.max_findings]
        if self.kind == "zip":
            return []
        return self._match(file)

    def _haystack(self, file: ScanFile) -> str:
        if self.kind == "text":
            return file.text
        if self.kind == "binary":
            return "\n".join(file.strings)
        # any
        if file.ext in TEXT_EXTENSIONS:
            return file.text
        return "\n".join(file.strings)

    def _match(self, file: ScanFile) -> list[Finding]:
        haystack = self._haystack(file)
        if not haystack:
            return []
        findings: list[Finding] = []
        seen: set[str] = set()

        if self.min_matches > 1:
            matched = 0
            anchor: re.Match[str] | None = None
            for pattern in self.compiled:
                match = pattern.search(haystack)
                if match is not None:
                    matched += 1
                    if anchor is None:
                        anchor = match
            if matched >= self.min_matches and anchor is not None:
                evidence = safe_evidence(haystack, anchor.start(), anchor.end())
                findings.append(
                    self._finding(file, haystack, anchor, evidence)
                )
            return findings

        for pattern in self.compiled:
            for match in pattern.finditer(haystack):
                evidence = safe_evidence(haystack, match.start(), match.end())
                key = evidence.lower()
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._finding(file, haystack, match, evidence))
                if len(findings) >= self.max_findings:
                    return findings
        return findings

    def _finding(
        self, file: ScanFile, haystack: str, match: re.Match[str], evidence: str
    ) -> Finding:
        offset = None
        if self.kind in ("text", "any") and file.ext in TEXT_EXTENSIONS:
            offset = line_number(haystack, match.start())
        return Finding(
            sig_id=self.sig_id,
            title=self.title,
            severity=self.severity,
            description=self.description,
            evidence=evidence,
            entry=file.entry,
            offset=offset,
        )


def evidence_from_text(sig_id: str, title: str, severity: Severity, description: str, text: str, needle: str) -> Finding | None:
    """Собирает Finding по строковому совпадению (для бинарных проверок)."""
    index = text.lower().find(needle.lower())
    if index < 0:
        return None
    snippet = text[max(index - 40, 0) : index + len(needle) + 60]
    from ..types import clean_text

    return Finding(
        sig_id=sig_id,
        title=title,
        severity=severity,
        description=description,
        evidence=clean_text(snippet, 180),
    )


def decode_base64_payload(chunk: str) -> str | None:
    """Декодирует base64-фрагмент в текст (для проверки «спрятанного» кода)."""
    from ..sigutil import try_b64decode

    return try_b64decode(chunk)


__all__ = ["Rule", "CheckFn", "TEXT_EXTENSIONS", "decode_text", "evidence_from_text", "decode_base64_payload"]
