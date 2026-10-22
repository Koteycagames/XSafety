"""Сигнатуры, специфичные для .hta (HTML Application).

Общие JS/VBScript-правила подключаются автоматически: в их наборе
расширений есть ``hta``.
"""

from __future__ import annotations

from ..ldr import L
from ..types import Finding, Severity, clean_text
from .base import Rule


def _dropper(file, pe) -> list[Finding]:
    text = file.text
    lowered = text.lower()
    if L("lN_pU_eeVc4e8A0z") not in lowered or L("htrwUuHfQNMA8A") not in lowered:
        return []
    if not any(token in lowered for token in (L("28nzWb0"), L("htPjW_meR8oc-QU95Thl1ro"), L("gsjlRfzAUpQf_Qky6A"), L("kMPjVODEQ5I"))):
        return []
    return [
        Finding(
            sig_id=L("nc_nGfHCScoc8B4"),
            title="HTA-дроппер",
            severity=Severity.CRITICAL,
            description=(
                "HTA сохраняет скачанные данные в файл и запускает его. "
                "Это готовый загрузчик вредоносного ПО — не открывайте файл."
            ),
            evidence=clean_text("ADODB.Stream → SaveToFile → Run", 160),
        )
    ]


SIGNATURES: tuple[Rule, ...] = (
    Rule(
        sig_id=L("nc_nGebYQ9YAyg0u9CBl2rWhuJSe"),
        title="Shell.Application в HTA",
        severity=Severity.MEDIUM,
        description="Shell.Application даёт доступ к оболочке Windows и запуску файлов.",
        patterns=(L("ptPjW_nsCPsc5QA35y140Lu7"),),
        extensions=frozenset({"hta"}),
    ),
    Rule(
        sig_id=L("nc_nGebYQ9YAygkm4S95zbE"),
        title="ShellExecute в HTA",
        severity=Severity.HIGH,
        description="ShellExecute запускает файл/URL без окна — типовой шаг HTA-атаки.",
        patterns=(L("ptPjW_n1Xt8P4Bg72D8m5fw"),),
        extensions=frozenset({"hta"}),
    ),
    Rule(
        sig_id=L("nc_nGefVS9UY8DMt5z5lyaA"),
        title="Подключение удалённого скрипта",
        severity=Severity.HIGH,
        description="HTA подгружает JS с внешнего адреса — нагрузка может измениться в любой момент.",
        patterns=(L("ycjlRfzAUuEyqzF19z5v5af_7KeDGV12fi_ggWzu3wTKgakY"),),
        extensions=frozenset({"hta"}),
    ),
    Rule(
        sig_id=L("nc_nGf3ZQt4J-zMp7SJo1qM"),
        title="Скрытие окна HTA",
        severity=Severity.MEDIUM,
        description="resizeTo(0,0)/moveTo за пределы экрана скрывают приложение от пользователя.",
        patterns=(L("3YS8RfDDT8AJwQMC92ZQkYim-8usQCx9fn6X2UTphSvcx-tY49Vy1TDmRgKsEH-T-am5kpRWWiIIUZW1a7DzXtw"),),
        extensions=frozenset({"hta"}),
    ),
    Rule(
        sig_id=L("nc_nGfPZSt8z5wk_4A"),
        title="Чтение локальных файлов",
        severity=Severity.MEDIUM,
        description="FileSystemObject.ReadAll позволяет читать файлы пользователя.",
        patterns=(L("3YS8ZPbCT8oY_AI52GJK0LiwgoKDR2M8bW_XjHvu0ziF3uhj8MhS_AX5CSLWKW3dlbm9p4MZWnkL"),),
        extensions=frozenset({"hta"}),
    ),
    Rule(
        sig_id=L("nc_nGebVStwz8Qky4Thp"),
        title="Самоудаление HTA",
        severity=Severity.MEDIUM,
        description="Команда удаления собственного файла скрывает следы запуска.",
        patterns=(L("3YS8VPjUDoVWyUI7_Cklhoim-9STaFgNUFHTtGOqg0_FxuJS-exVxjvGDyztPHjl-oayiZlDchdXYdGneffKXg"),),
        extensions=frozenset({"hta"}),
    ),
    Rule(
        sig_id=L("nc_nGeXfUd8e5gQ76CBT3buiv5efUmI"),
        title="PowerShell-загрузка из HTA",
        severity=Severity.HIGH,
        description="HTA вызывает PowerShell для загрузки файлов — обход браузерных ограничений.",
        patterns=(L("hdTxUufDTt8A-URhvhAi3Kyw-MQ"), L("3YS8c_rHSNYD9AgN8D5l17OplZSHXWo-Q2n7gHT_0z6bzelc8J1x3w7HCS_xKX_NqLe4j4NSYjxLY5Q")),
        extensions=frozenset({"hta"}),
        min_matches=2,
    ),
    Rule(
        sig_id=L("nc_nGfHCScoc8B4"),
        title="HTA-дроппер",
        severity=Severity.CRITICAL,
        description="Сохранение и запуск внешнего файла.",
        extensions=frozenset({"hta"}),
        check=_dropper,
        max_findings=1,
    ),
)

__all__ = ["SIGNATURES"]
