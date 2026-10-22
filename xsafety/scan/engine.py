"""Движок сканирования: один файл → один отчёт.

Порядок работы:

1. имя файла очищается (никаких путей — только basename);
2. проверяется, что модель поддерживает расширение (защита в глубину:
   API делает то же самое до чтения тела запроса);
3. для архивов читаются записи с лимитами и рекурсивно проверяются;
4. для PE разбираются заголовки (без запуска файла);
5. запускаются сигнатуры расширения; падение одной сигнатуры не роняет
   проверку — она пропускается и попадает в примечания.
"""

from __future__ import annotations

import hashlib
import re
import time

from ..config import (
    MAX_BINARY_ANALYZE_BYTES,
    MAX_FINDINGS,
    MAX_TEXT_ANALYZE_BYTES,
    MAX_ZIP_DEPTH,
    model_supports,
)
from .archives import extension_of, looks_like_zip, read_zip
from .pe import parse_pe
from .signatures import ARCHIVE_MODULES, PE_EXTENSIONS, archive_findings, rules_for_extension
from .types import Finding, ScanBudget, ScanFile, ScanResult, Severity, clean_text, verdict_for

MAX_NESTED = 150
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_EXTENSION = re.compile(r"^[a-z0-9]{1,12}$")


class ScanError(Exception):
    """Ошибка проверки с машинным кодом и HTTP-статусом."""

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


def sanitize_filename(name: str) -> str:
    """Оставляет только имя файла: без каталогов и управляющих символов."""
    if not isinstance(name, str):
        raise ScanError("invalid_filename", "Имя файла должно быть строкой")
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    base = _CONTROL.sub("", base).strip().strip(".")
    if not base:
        raise ScanError("invalid_filename", "Пустое имя файла")
    return base[:180]


def extension_from(name: str) -> str:
    if "." not in name:
        return ""
    ext = name.rsplit(".", 1)[1].lower()
    return ext if _EXTENSION.match(ext) else ""


def scan_bytes(filename: str, data: bytes, model_id: str) -> ScanResult:
    """Проверяет один файл. Никогда не пишет на диск и не исполняет код."""
    started = time.monotonic()
    safe_name = sanitize_filename(filename)
    ext = extension_from(safe_name)

    if not ext:
        raise ScanError("unsupported_extension", "Файл без расширения не поддерживается")
    if not model_supports(model_id, ext):
        raise ScanError(
            "extension_not_allowed",
            f"Модель не проверяет файлы .{ext}",
            status=403,
        )

    budget = ScanBudget(max_findings=MAX_FINDINGS)
    file = ScanFile(
        name=safe_name,
        data=data,
        ext=ext,
        size=len(data),
        model=model_id,
        depth=0,
    )
    findings, entries, notes = _scan_node(file, budget, depth=0)

    deduped: list[Finding] = []
    seen: set[tuple[str, str | None, str]] = set()
    for finding in findings:
        key = (finding.sig_id, finding.entry, finding.evidence.lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
        if len(deduped) >= MAX_FINDINGS:
            notes.append("Список находок обрезан по лимиту отчёта.")
            break

    if budget.truncated and "частично" not in " ".join(notes).lower():
        notes.append("Проверка выполнена частично из-за лимитов анализа.")

    analyzed = min(len(data), MAX_TEXT_ANALYZE_BYTES if ext not in PE_EXTENSIONS else MAX_BINARY_ANALYZE_BYTES)
    elapsed = int((time.monotonic() - started) * 1000)

    return ScanResult(
        filename=safe_name,
        extension=ext,
        model=model_id,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        verdict=verdict_for(deduped),
        findings=deduped,
        scanned_entries=max(entries, 1),
        analyzed_bytes=analyzed,
        elapsed_ms=elapsed,
        notes=[clean_text(note, 240) for note in notes][:24],
    )


def _scan_node(file: ScanFile, budget: ScanBudget, depth: int) -> tuple[list[Finding], int, list[str]]:
    findings: list[Finding] = []
    notes: list[str] = []
    entries = 1

    if file.ext in ARCHIVE_MODULES:
        if not looks_like_zip(file.data):
            findings.append(
                Finding(
                    sig_id=f"{file.ext}.not_archive",
                    title="Не архив",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Файл с расширением .{file.ext} не является ZIP-контейнером. "
                        "Возможно, расширение подделано. Проверьте реальный тип файла."
                    ),
                )
            )
            return findings, entries, notes

        report = read_zip(file.data, budget, depth)
        findings.extend(archive_findings(file.ext, report))
        notes.extend(report.notes)
        entries += len(report.entries)

        if depth < MAX_ZIP_DEPTH:
            skipped_unsupported = 0
            for entry in report.entries[:MAX_NESTED]:
                if not entry.extension or entry.extension == "class" or entry.extension == "mf":
                    continue
                if not model_supports(file.model, entry.extension):
                    skipped_unsupported += 1
                    continue
                nested = ScanFile(
                    name=entry.display_name,
                    data=entry.data,
                    ext=entry.extension,
                    size=entry.size,
                    model=file.model,
                    depth=depth + 1,
                    entry=entry.display_name,
                    parent=file.display_name,
                )
                sub_findings, sub_entries, sub_notes = _scan_node(nested, budget, depth + 1)
                for finding in sub_findings:
                    if finding.entry and finding.entry != entry.display_name:
                        path = f"{entry.display_name} → {finding.entry}"
                    else:
                        path = entry.display_name
                    findings.append(
                        Finding(
                            sig_id=finding.sig_id,
                            title=finding.title,
                            severity=finding.severity,
                            description=finding.description,
                            evidence=finding.evidence,
                            entry=clean_text(path, 240),
                            offset=finding.offset,
                        )
                    )
                entries += sub_entries - 1
                notes.extend(sub_notes[:3])
            if skipped_unsupported:
                notes.append(
                    f"Вложений с расширениями вне тарифа пропущено: {skipped_unsupported}. "
                    "Они не проверены — повысьте тариф или проверьте отдельно."
                )
        else:
            notes.append("Глубже вложенные архивы не проверялись.")
        return findings, entries, notes

    pe = None
    if file.ext in PE_EXTENSIONS:
        pe = parse_pe(file.data)
        if pe is None:
            findings.append(
                Finding(
                    sig_id=f"{file.ext}.invalid_pe",
                    title="Файл не является PE",
                    severity=Severity.MEDIUM,
                    description=(
                        "Структура PE не найдена: расширение подделано или файл повреждён. "
                        "Проверьте реальный формат файла."
                    ),
                )
            )

    for rule in rules_for_extension(file.ext):
        if rule.kind == "zip":
            continue
        try:
            findings.extend(rule.run(file, pe))
        except Exception as exc:  # изоляция сигнатур: одна ошибка не ломает отчёт
            notes.append(f"Сигнатура {rule.sig_id} пропущена: {type(exc).__name__}")
        if len(findings) >= MAX_FINDINGS:
            break

    return findings, entries, notes


__all__ = ["ScanError", "extension_from", "sanitize_filename", "scan_bytes", "extension_of"]
