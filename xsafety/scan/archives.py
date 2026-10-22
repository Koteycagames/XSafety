"""Безопасная работа с ZIP-архивами.

Архив НИКОГДА не распаковывается на диск — только в память с жёсткими
лимитами по числу записей, размеру, коэффициенту сжатия и глубине
вложенности. Поэтому zip-slip невозможен, но опасные имена всё равно
попадают в отчёт как признак вредоносного архива
(см. SECURITY.md, цикл 4, V-24/V-25).
"""

from __future__ import annotations

import io
import posixpath
import zipfile
from dataclasses import dataclass, field

from ..config import (
    MAX_ZIP_DEPTH,
    MAX_ZIP_ENTRIES,
    MAX_ZIP_ENTRY_BYTES,
    MAX_ZIP_RATIO,
    MAX_ZIP_TOTAL_UNCOMPRESSED,
)
from .types import ScanBudget, clean_text

ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

INTERESTING_EXTENSIONS = frozenset(
    {"bat", "cmd", "py", "pyw", "js", "mjs", "cjs", "ps1", "psm1", "vbs", "vbe", "hta", "dll", "exe", "jar", "zip", "class", "lnk", "scr", "com", "pif"}
)

MAX_NAME_LENGTH = 260


def looks_like_zip(data: bytes) -> bool:
    return data[:4] in ZIP_SIGNATURES


def sanitize_entry_name(name: str) -> str:
    """Отображаемое имя записи: без управления, ограниченной длины."""
    normalized = name.replace("\\", "/").lstrip("/")
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if len(parts) > 8:
        parts = parts[-8:]
    return clean_text(posixpath.join(*parts) if parts else "(пустое имя)", MAX_NAME_LENGTH)


def has_path_traversal(name: str) -> bool:
    raw = name.replace("\\", "/")
    if raw.startswith("/") or raw[1:3] == ":/":
        return True
    return any(part == ".." for part in raw.split("/"))


def has_double_extension(name: str) -> bool:
    lowered = name.lower()
    dangerous = (".exe", ".scr", ".com", ".pif", ".lnk", ".bat", ".cmd", ".js", ".vbs", ".hta", ".jar", ".dll", ".ps1")
    if not lowered.endswith(dangerous):
        return False
    stem = lowered[: lowered.rfind(".")]
    return "." in stem


def extension_of(name: str) -> str:
    base = posixpath.basename(name.replace("\\", "/"))
    if "." not in base:
        return ""
    return base.rsplit(".", 1)[1].lower()


@dataclass(slots=True)
class ArchiveEntry:
    name: str
    display_name: str
    extension: str
    data: bytes
    size: int
    encrypted: bool = False
    traversal: bool = False
    double_extension: bool = False


@dataclass(slots=True)
class ArchiveReport:
    entries: list[ArchiveEntry] = field(default_factory=list)
    total_entries: int = 0
    skipped: int = 0
    notes: list[str] = field(default_factory=list)
    traversal_names: list[str] = field(default_factory=list)
    double_ext_names: list[str] = field(default_factory=list)
    encrypted_count: int = 0
    ratio_alerts: list[str] = field(default_factory=list)
    oversized: list[str] = field(default_factory=list)
    total_uncompressed: int = 0
    truncated: bool = False
    readable: bool = True


def read_zip(data: bytes, budget: ScanBudget, depth: int = 0) -> ArchiveReport:
    """Читает записи архива с лимитами по количеству, размеру и сжатию."""
    report = ArchiveReport()
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, OSError, ValueError, EOFError) as exc:
        report.readable = False
        report.notes.append(f"Архив не читается: {type(exc).__name__}")
        return report

    report.total_entries = len(infos)
    if report.total_entries > MAX_ZIP_ENTRIES:
        report.truncated = True
        report.notes.append(f"В архиве {report.total_entries} записей — проверены первые {MAX_ZIP_ENTRIES}.")
    if depth >= MAX_ZIP_DEPTH:
        report.notes.append("Достигнут предел вложенности архивов.")
        report.truncated = True
        return report

    for info in infos[:MAX_ZIP_ENTRIES]:
        if info.is_dir():
            continue
        name = info.filename or ""
        display = sanitize_entry_name(name)
        ext = extension_of(name)

        if has_path_traversal(name):
            report.traversal_names.append(display)
        if has_double_extension(name):
            report.double_ext_names.append(display)

        if info.flag_bits & 0x1:
            report.encrypted_count += 1
            continue
        if info.file_size > MAX_ZIP_ENTRY_BYTES:
            report.skipped += 1
            report.oversized.append(display)
            continue
        ratio = (info.file_size / info.compress_size) if info.compress_size else 0
        if info.compress_size and ratio > MAX_ZIP_RATIO:
            report.skipped += 1
            report.ratio_alerts.append(display)
            continue
        if report.total_uncompressed + info.file_size > MAX_ZIP_TOTAL_UNCOMPRESSED:
            report.skipped += 1
            report.truncated = True
            report.notes.append("Достигнут общий лимит распаковки архива.")
            break
        if not budget.take_entry():
            report.truncated = True
            report.notes.append("Исчерпан лимит записей бюджета сканирования.")
            break

        allowed = budget.take_bytes(min(info.file_size, MAX_ZIP_ENTRY_BYTES))
        if allowed <= 0:
            report.truncated = True
            report.notes.append("Исчерпан бюджет анализа архива.")
            break
        try:
            with archive.open(info) as handle:
                raw = handle.read(min(info.file_size, allowed) + 1)
        except (RuntimeError, zipfile.BadZipFile, OSError, ValueError, EOFError) as exc:
            report.skipped += 1
            report.notes.append(f"Запись не читается ({type(exc).__name__}): {display}")
            continue
        if len(raw) > allowed:
            raw = raw[:allowed]
            report.notes.append(f"Запись усечена: {display}")
        report.total_uncompressed += len(raw)
        if not raw and ext not in INTERESTING_EXTENSIONS:
            continue
        report.entries.append(
            ArchiveEntry(
                name=name,
                display_name=display,
                extension=ext,
                data=raw,
                size=max(info.file_size, len(raw)),
                encrypted=False,
                traversal=has_path_traversal(name),
                double_extension=has_double_extension(name),
            )
        )
    return report


__all__ = [
    "ArchiveEntry",
    "ArchiveReport",
    "extension_of",
    "has_double_extension",
    "has_path_traversal",
    "looks_like_zip",
    "read_zip",
    "sanitize_entry_name",
]
