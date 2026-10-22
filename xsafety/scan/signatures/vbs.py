"""Сигнатуры для .vbs / .vbe и VBScript внутри .hta."""

from __future__ import annotations

from ..ldr import L
import re

from ..types import Finding, Severity, clean_text
from .base import Rule

EXT = frozenset({"vbs", "vbe", "hta"})

_CHR_CHAIN = re.compile(L("3YS8dP3CDoVWwkVh2D8m5fyJotGsV31gDjjAtWuw816pyKwRquxVkEXuVHL5"), re.IGNORECASE)
_FSO_LOOP = re.compile(L("3YS8cfrCeslH0A097BdS5aaJv6aLAyppEnCV1iLcxhuQyPpx_NxDkxDRAwL3Z1vRvbm00g"), re.IGNORECASE)


def _chr_obfuscation(file, pe) -> list[Finding]:
    match = _CHR_CHAIN.search(file.text)
    if not match:
        return []
    return [
        Finding(
            sig_id=L("g9n1GfbYVOUD9wor9y9tzb26vw"),
            title="Обфускация через Chr()",
            severity=Severity.MEDIUM,
            description=(
                "Строки собраны из Chr()-последовательностей — так скрывают команды "
                "от антивирусных сигнатур."
            ),
            evidence=clean_text(match.group()[:140], 140),
        )
    ]


def _mass_file_write(file, pe) -> list[Finding]:
    text = file.text
    lowered = text.lower()
    if L("htj0XuXET9QLuwo36Cl_wKehtJafUWw0QXk") not in lowered:
        return []
    if not _FSO_LOOP.search(text):
        return []
    if L("28z0XuHV") not in lowered and L("ltT2TvPZSt8") not in lowered and L("mNTwUvPZSt8") not in lowered:
        return []
    return [
        Finding(
            sig_id=L("g9n1GfjRVckz8wUy4RN7y72htA"),
            title="Массовая запись/копирование файлов",
            severity=Severity.HIGH,
            description=(
                "VBScript перебирает файлы и пишет в них — возможен файловый "
                "шифровальщик или распространение по сети."
            ),
            evidence=clean_text("FileSystemObject + перебор файлов + запись", 160),
        )
    ]


SIGNATURES: tuple[Rule, ...] = (
    Rule(
        sig_id=L("g9n1GeLDRcgF5RgB9yRp1bg"),
        title="Запуск программ через WScript.Shell",
        severity=Severity.HIGH,
        description=(
            "WScript.Shell.Run запускает внешние процессы. Проверьте, что именно "
            "запускается и откуда взялся файл."
        ),
        patterns=(L("oujlRfzAUuZCxgQ76CA"), L("qZWuCK_iU9QQ0BQ75zBf0bG5vb6IVmUkVmiUtWuw818")),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("g9n1GfHfUdQA-g062yl03Lc"),
        title="Загрузка и запуск из интернета",
        severity=Severity.CRITICAL,
        description=(
            "XMLHTTP/WinHttp скачивает файл, ADODB.Stream сохраняет его, а Shell.Run "
            "запускает — классическая цепочка загрузчика."
        ),
        patterns=(
            L("3YS8esboa_ZeyUJ2u3ZU9Jidha-gT1U0UHvYm0DX4z-h79Ye6edP1CThGC7YYlvQup2lj4BhYyBXaM6dZNfGFIfU9VjzxHqUNNggFtAYXJA"),
            L("3YS8dtH_Yvgwuz8q9ilt1KiGsI2VZ2kXS2HYwA"),
            L("3YS8a7viU9QQyUIb_ClvxYe9tJecdn40QXjJjDE"),
        ),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("g9n1GfDIQ9kZ4QkB4Tpt1Q"),
        title="Execute/Eval строки",
        severity=Severity.MEDIUM,
        description="Execute/Eval выполняет динамический код — проверьте источник строки.",
        patterns=(L("qdmuCK_1Xt8P4Bg7-Al62LiplIOVUHMlR0rRhnr7w16pyKxrvQ"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("g9n1GefVQdMf4R4n2z551w"),
        title="Автозапуск через реестр",
        severity=Severity.HIGH,
        description="Регистрация в Run/RunOnce обеспечивает запуск при входе в систему.",
        patterns=(L("3YS8ZfDXccgF4Qki1ilr-qawsI-VeGMoC1bjtWrGwSrf-PNF59VIzjrwHi3tI2LliIeklQ"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("g9n1GfHZVdsO-QkB9ylvzKa8pYI"),
        title="Отключение защитных механизмов",
        severity=Severity.HIGH,
        description="Правка политик отключает диспетчер задач, редактор реестра или обновления.",
        patterns=(
            L("3YS8c_zDR9gA8Dg_9ydB3qaplZKDUmQ9R1_YjnHp2wWM7-lY-cNa_gXmDTzoKU_0kKmVkoNSZD1HWtSHfPXYBKDL4lbh1WfZD_AfLa0"),
        ),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("g9n1GefRSMkD-Bs_9ik"),
        title="Удаление резервных копий",
        severity=Severity.CRITICAL,
        description="vssadmin/bcdedit в VBScript — подготовка к шифрованию данных.",
        patterns=(L("3YS8QebDR94B_AIF2hB-5bqI-5-VX2MlR1HOwmvyzhOazPVL4tJH3gH8AgXaEH7luoj7n5VfYyVHcd-KfP_LHoHg2Gvn7EjnRr1TZKs_ac2o-rWenFZyNAsk"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("g9n1Gf3ZQt4J-zMp7SJo1qM"),
        title="Скрытый запуск",
        severity=Severity.LOW,
        description="Параметр окна 0 скрывает консоль от пользователя.",
        patterns=(L("qZXUQvvsVZAwvTcA2D5Q14n__aeDGTYNUSeRtWuwh0jP7_RC8Mxg2wDmCXe7EH-TiPw"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("g9n1GfHfUdQA-g062z94y727tg"),
        title="Загрузка текста и исполнение",
        severity=Severity.HIGH,
        description="Скачанный текст передаётся в Execute — удалённое управление.",
        patterns=(L("qZWuCK_iQ8kc-gIt4RhpwaCpg56DQ2k_UWj_hnzjhg"), L("3YS8cu3VRc8Y8BAb8i1gkIim-6fY")),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("g9n1GeDDROUf5R475Sg"),
        title="Распространение через съёмные носители",
        severity=Severity.HIGH,
        description="Перебор дисков и копирование autorun.inf/скрипта — поведение червя.",
        patterns=(L("3YS8c-fZUN847Bw72D8mhIim-8qMbygVUGTLjGvGzV4"), L("3YS8VuDEScgZ-zBw7SJqxZe6oYK2Wmo0Cw")),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("g9n1GfbYVOUD9wor9y9tzb26vw"),
        title="Обфускация через Chr()",
        severity=Severity.MEDIUM,
        description="Строки собираются из кодов символов, чтобы скрыть команды.",
        extensions=EXT,
        check=_chr_obfuscation,
        max_findings=1,
    ),
    Rule(
        sig_id=L("g9n1GfjRVckz8wUy4RN7y72htA"),
        title="Массовая запись файлов",
        severity=Severity.HIGH,
        description="Перебор файлов и запись в них — возможный шифровальщик.",
        extensions=EXT,
        check=_mass_file_write,
        max_findings=1,
    ),
)

__all__ = ["SIGNATURES", "EXT"]

#: Дополнение: Shell.Run в VBScript может вызываться без скобок.
SIGNATURES = SIGNATURES + (
    Rule(
        sig_id=L("g9n1GebYQ9YAyh4r6hNu2Kaw"),
        title="Запуск процесса через Shell.Run",
        severity=Severity.HIGH,
        description=(
            "Вызов Shell.Run/Exec запускает внешнюю программу. В VBScript "
            "скобки необязательны, поэтому проверяются оба варианта."
        ),
        patterns=(L("qZXaRL-YGYA-4AIiwTRp2v2JotCrbyR2fzLmqDXAzlqPi6sOyux6lUKvSSCkYVHC5vms"),),
        extensions=EXT,
        min_matches=1,
    ),
)
