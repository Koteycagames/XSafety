"""Сигнатуры для .jar (ZIP-контейнер с байткодом Java).

JAR разбирается как архив: манифест, подпись, вложенные исполняемые
файлы и строковые константы в .class. Байткод не исполняется.
"""

from __future__ import annotations

from ..ldr import B, L
import re

from ..archives import ArchiveReport, extension_of
from ..textutil import iter_strings
from ..types import Finding, Severity, clean_text

EXT = frozenset({"jar"})

MAX_CLASS_ANALYZE = 64 * 1024 * 1024

_SUSPICIOUS_CLASS_STRINGS = {
    "jar.runtime_exec": (
        (B("n9rwVrrcR9QLuj4r6jhl1LE"), B("kt7yZeDeUtMB8A"), B("kMPjVA")),
        Severity.HIGH,
        "Запуск внешних процессов из Java",
        "Байткод вызывает Runtime.exec — приложение может запускать команды ОС.",
    ),
    "jar.classloader": (
        (B("kd7gXvvVZdYN5h8"), B("oOnKdPnRVckg-g064T4")),
        Severity.MEDIUM,
        "Динамическая загрузка классов",
        "ClassLoader загружает код во время работы — проверьте источник классов.",
    ),
    "jar.reflection": (
        (B("n9rwVrrcR9QLuh474iBp2qA"), B("ht7ydvbTQ8kf_A4y4Q")),
        Severity.LOW,
        "Рефлексия с обходом доступа",
        "Рефлексия используется для обхода модификаторов доступа.",
    ),
}


def _has_all(data: bytes, needles: tuple[bytes, ...]) -> bool:
    return all(needle in data for needle in needles)


def jar_findings(report: ArchiveReport) -> list[Finding]:
    findings: list[Finding] = []
    classes = [e for e in report.entries if e.extension == L("ltfnROY")]
    names = [e.display_name for e in report.entries]
    manifest = next((e for e in report.entries if e.display_name.upper().endswith(L("uP7Sdrj5aPxD2C0QzQpJ6oD7nL0"))), None)

    if manifest is not None:
        text = manifest.data.decode(L("gM_gGq0"), errors=L("h972W_TTQw"))
        main_class = re.search(L("3YTvWrzua9sF-0Ed6C1_yu6JotHYb1V6Cw"), text)
        if main_class:
            findings.append(
                Finding(
                    sig_id=L("n9r0GfjRT9Qz9gA_9z8"),
                    title="Точка входа в манифесте",
                    severity=Severity.INFO,
                    description=(
                        "JAR запускается как приложение через Main-Class. "
                        "Убедитесь, что источник архива вам известен."
                    ),
                    evidence=clean_text(main_class.group(1), 120),
                )
            )

    signed = any(name.upper().startswith(L("uP7Sdrj5aPxD")) and name.upper().endswith((".SF", L("2-nVdg"), L("2__Vdg"), ".EC")) for name in names)
    if signed:
        findings.append(
            Finding(
                sig_id=L("n9r0GebZQdQJ8Q"),
                title="JAR подписан",
                severity=Severity.INFO,
                description="Архив содержит подпись издателя. Проверьте, кому она принадлежит.",
            )
        )
    else:
        findings.append(
            Finding(
                sig_id=L("n9r0GeDeVdML-wk6"),
                title="JAR без подписи",
                severity=Severity.LOW,
                description=(
                    "Подпись отсутствует: происхождение архива не подтверждено. "
                    "Скачивайте JAR только с официальных сайтов."
                ),
            )
        )

    if not classes:
        findings.append(
            Finding(
                sig_id=L("n9r0GfvfedkA9B8t4T8"),
                title="JAR без классов",
                severity=Severity.MEDIUM,
                description=(
                    "В архиве нет .class-файлов, хотя расширение .jar. "
                    "Возможно, это переименованный ZIP с другим содержимым."
                ),
            )
        )

    executables = [e for e in report.entries if e.extension in {"exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "hta", "lnk"}]
    if executables:
        findings.append(
            Finding(
                sig_id=L("n9r0GfDdRN8I8Qk62yl03LegpZqSX2M"),
                title="Исполняемые файлы внутри JAR",
                severity=Severity.HIGH,
                description=(
                    "В JAR лежат exe/dll/скрипты. Java-приложение может извлечь "
                    "и запустить их — типовой способ доставки."
                ),
                evidence=clean_text(", ".join(e.display_name for e in executables[:3]), 160),
            )
        )

    nested = [e for e in report.entries if e.extension in {"jar", "zip"}]
    if nested:
        findings.append(
            Finding(
                sig_id=L("n9r0GfvVVc4J8TM_9i9k0KKw"),
                title="Вложенные архивы",
                severity=Severity.MEDIUM,
                description=(
                    "JAR содержит другие архивы. Вложенность усложняет проверку "
                    "и часто используется для обхода антивирусов."
                ),
                evidence=clean_text(", ".join(e.display_name for e in nested[:3]), 160),
            )
        )

    if report.encrypted_count:
        findings.append(
            Finding(
                sig_id=L("n9r0GfDeRcgV5Rg74A"),
                title="Зашифрованные записи",
                severity=Severity.MEDIUM,
                description="Часть JAR зашифрована — содержимое нельзя проверить.",
            )
        )
    if report.traversal_names:
        findings.append(
            Finding(
                sig_id=L("n9r0GeXRUtIz4R4_8il-yrW5"),
                title="Пути с выходом из каталога",
                severity=Severity.CRITICAL,
                description="Имена записей JAR содержат «..» — риск записи вне каталога установки.",
                evidence=clean_text(", ".join(report.traversal_names[:3]), 160),
            )
        )
    if report.double_ext_names:
        findings.append(
            Finding(
                sig_id=L("n9r0GfHfU9gA8DM7_Dhp16e8vpU"),
                title="Двойные расширения в JAR",
                severity=Severity.HIGH,
                description="Записи маскируют исполняемые файлы под документы.",
                evidence=clean_text(", ".join(report.double_ext_names[:3]), 160),
            )
        )

    analyzed = 0
    joined: list[bytes] = []
    for entry in classes:
        if analyzed >= MAX_CLASS_ANALYZE:
            break
        joined.append(entry.data[: 256 * 1024])
        analyzed += len(entry.data)
    blob = b"\n".join(joined)

    for sig_id, (needles, severity, title, description) in _SUSPICIOUS_CLASS_STRINGS.items():
        if _has_all(blob, needles):
            findings.append(
                Finding(
                    sig_id=sig_id,
                    title=title,
                    severity=severity,
                    description=description,
                )
            )

    strings = "\n".join(iter_strings(blob)).lower()
    if L("hdTxUufDTt8A-Q") in strings or L("ltbiGfDIQ5pD9g") in strings:
        findings.append(
            Finding(
                sig_id=L("n9r0GebYQ9YAyh8q9iVi3qc"),
                title="Команды оболочки Windows",
                severity=Severity.HIGH,
                description="В классах найдены строки запуска PowerShell/cmd — необычно для Java-приложения.",
                evidence=clean_text(L("hdTxUufDTt8A-UxxpC9h3fqwqZ4"), 80),
            )
        )
    if L("nc_yR6-fCQ") in strings or L("nc_yR-aKCZU") in strings:
        findings.append(
            Finding(
                sig_id=L("n9r0GefVS9UY8DMr9iB_"),
                title="Сетевые адреса в классах",
                severity=Severity.LOW,
                description="В JAR есть URL. Сверьте домены с документацией приложения.",
            )
        )

    if classes:
        short_names = [e.display_name for e in classes if len(e.display_name.rsplit("/", 1)[-1].removesuffix(L("29jqVubD"))) <= 2]
        if len(short_names) >= 10:
            findings.append(
                Finding(
                    sig_id=L("n9r0GfrSQM8f9g0q4ShT17W4tIg"),
                    title="Обфускация имён классов",
                    severity=Severity.LOW,
                    description="Большинство классов имеют имена из 1–2 символов — код обфусцирован.",
                    evidence=f"классов: {len(short_names)}",
                )
            )

    return findings


def is_java_class(entry_name: str) -> bool:
    return extension_of(entry_name) == L("ltfnROY")


__all__ = ["jar_findings", "is_java_class", "EXT"]


#: Единое имя для реестра контейнеров.
archive_findings = jar_findings
