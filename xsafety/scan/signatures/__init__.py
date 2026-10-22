"""Реестр сигнатур.

Модули разделены по расширениям, чтобы один файл не разрастался и чтобы
на каждый формат можно было точечно добавлять правила. Дубли ``sig_id``
невозможны — проверяются при импорте.

``LDR`` (Lightweight Detection Rules) — компактные правила, которые
движок исполняет на каждую проверку; описания и рекомендации живут
рядом с правилом, поэтому отчёт всегда объясняет находку.
"""

from __future__ import annotations

from typing import Iterable

from ..archives import ArchiveReport
from ..types import Finding
from . import bat, common, dll, exe, hta, jar, js, ps1, py, vbs
from . import zip as zip_sigs
from .base import Rule

#: Порядок определяет приоритет отображения находок в отчёте.
MODULES = (common, bat, py, js, ps1, vbs, hta, dll, exe, jar, zip_sigs)

RULES: tuple[Rule, ...] = tuple(rule for module in MODULES for rule in getattr(module, "SIGNATURES", ()))

_seen: set[str] = set()
for _rule in RULES:
    if _rule.sig_id in _seen:
        raise RuntimeError(f"Дублирующийся sig_id: {_rule.sig_id}")
    _seen.add(_rule.sig_id)
del _seen, _rule

#: Модули, которые умеют проверять контейнер целиком.
ARCHIVE_MODULES = {"zip": zip_sigs, "jar": jar}

#: Расширения, для которых есть PE-разбор.
PE_EXTENSIONS = frozenset({"dll", "exe"})


def rules_for_extension(extension: str) -> tuple[Rule, ...]:
    return tuple(rule for rule in RULES if rule.applies(extension))


def archive_findings(extension: str, report: ArchiveReport) -> list[Finding]:
    module = ARCHIVE_MODULES.get(extension)
    if module is None:
        return []
    return list(module.archive_findings(report))


def signature_count(extensions: Iterable[str] | None = None) -> int:
    """Сколько правил применяется к набору расширений (для витрины)."""
    if extensions is None:
        return len(RULES)
    wanted = frozenset(extensions)
    return sum(1 for rule in RULES if rule.extensions is None or rule.extensions & wanted)


__all__ = [
    "ARCHIVE_MODULES",
    "MODULES",
    "PE_EXTENSIONS",
    "RULES",
    "archive_findings",
    "rules_for_extension",
    "signature_count",
]
