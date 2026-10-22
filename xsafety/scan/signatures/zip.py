"""Сигнатуры уровня ZIP-контейнера.

Проверяются свойства самого архива: имена записей, шифрование,
коэффициент сжатия. Содержимое записей сканируется рекурсивно движком
по правилам их собственных расширений.
"""

from __future__ import annotations

from ..ldr import L
from ..archives import ArchiveReport
from ..types import Finding, Severity, clean_text

EXT = frozenset({"zip"})


def archive_findings(report: ArchiveReport) -> list[Finding]:
    """Собирает находки по метаданным архива (без содержимого записей)."""
    findings: list[Finding] = []

    if report.traversal_names:
        findings.append(
            Finding(
                sig_id=L("j9L2GeXRUtIz4R4_8il-yrW5"),
                title="Запись с выходом из каталога (zip-slip)",
                severity=Severity.CRITICAL,
                description=(
                    "Имена записей содержат «..» или абсолютный путь. При распаковке "
                    "такой архив может перезаписать файлы вне целевого каталога. "
                    "Распаковывайте только в изолированной среде."
                ),
                evidence=clean_text(", ".join(report.traversal_names[:3]), 160),
            )
        )

    if report.double_ext_names:
        findings.append(
            Finding(
                sig_id=L("j9L2GfHfU9gA8DM7_Dhp16e8vpU"),
                title="Двойное расширение файлов",
                severity=Severity.HIGH,
                description=(
                    "Записи вида «счёт.pdf.exe» маскируют исполняемый файл под документ. "
                    "Не открывайте такие файлы."
                ),
                evidence=clean_text(", ".join(report.double_ext_names[:3]), 160),
            )
        )

    if report.ratio_alerts:
        findings.append(
            Finding(
                sig_id=L("j9L2GfbfS8oe8B8t7SNi5ra6vJk"),
                title="Аномальное сжатие (zip-bomb)",
                severity=Severity.HIGH,
                description=(
                    "Одна или несколько записей сжимаются в сотни раз — распаковка "
                    "может исчерпать диск или память. Такие записи пропущены."
                ),
                evidence=clean_text(", ".join(report.ratio_alerts[:3]), 160),
            )
        )

    if report.encrypted_count:
        findings.append(
            Finding(
                sig_id=L("j9L2GfDeRcgV5Rg74A"),
                title="Зашифрованные записи",
                severity=Severity.MEDIUM,
                description=(
                    "Архив защищён паролем: содержимое нельзя проверить антивирусом "
                    "и статическим анализом. Требуйте пароль у отправителя."
                ),
                evidence=f"записей: {report.encrypted_count}",
            )
        )

    if report.oversized:
        findings.append(
            Finding(
                sig_id=L("j9L2GfrGQ8gf_BY74BNp16CnqA"),
                title="Слишком крупные записи",
                severity=Severity.MEDIUM,
                description="Записи превышают лимит анализа и были пропущены.",
                evidence=clean_text(", ".join(report.oversized[:3]), 160),
            )
        )

    if report.truncated:
        findings.append(
            Finding(
                sig_id=L("j9L2GeHCU9QP9Bg74A"),
                title="Архив проверен частично",
                severity=Severity.MEDIUM,
                description=(
                    "Из-за лимитов проверены не все записи. Остаток архива "
                    "требует отдельной проверки."
                ),
                evidence=clean_text("; ".join(report.notes[:2]), 160),
            )
        )

    if not report.readable:
        findings.append(
            Finding(
                sig_id=L("j9L2GeDeVN8N8Q086Ck"),
                title="Повреждённый архив",
                severity=Severity.MEDIUM,
                description=(
                    "Файл с расширением .zip не читается как архив. Возможно, "
                    "это маскировка другого формата или повреждённый файл."
                ),
            )
        )

    return findings


__all__ = ["archive_findings", "EXT"]
