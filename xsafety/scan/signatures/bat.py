"""Сигнатуры для .bat / .cmd.

Каждая сигнатура проверяет конкретное поведение и имеет собственную
рекомендацию по исправлению (description). Разбор — только текст,
лимит байт уже применён в ScanFile.
"""

from __future__ import annotations

from ..ldr import L
import re

from ..sigutil import try_b64decode
from ..types import Finding, Severity, clean_text
from .base import Rule

EXT = frozenset({"bat", "cmd"})

_B64_CHUNK = re.compile(L("rvqrbfSdXIpBrEdx2Tc0ifio7IDAHzQs"))


def _encoded_payload(file, pe) -> list[Finding]:
    """Ищет base64-блоки, которые декодируются в исполняемый код."""
    findings: list[Finding] = []
    text = file.text
    for match in _B64_CHUNK.finditer(text):
        decoded = try_b64decode(match.group())
        if not decoded:
            continue
        lowered = decoded.lower()
        if not any(token in lowered for token in (L("hdTxUufDTt8A-Q"), L("ltbiGfDIQw"), L("nc_yR6-fCQ"), L("nc_yR-aKCZU"), L("nNXwWP7VCw"), L("kdTxWfnfR94f4R436is"), L("gsjlRfzAUg"), L("mMjuQ_Q"))):
            continue
        findings.append(
            Finding(
                sig_id=L("l9ryGfDeRdUI8AgB9C111bu0tQ"),
                title="Скрытый код в base64",
                severity=Severity.CRITICAL,
                description=(
                    "В скрипте найден base64-блок, который декодируется в команды "
                    "запуска/загрузки. Так маскируют загрузчики и стилеры. "
                    "Не запускайте файл; проверьте исходный код у автора."
                ),
                evidence=clean_text(decoded, 180),
            )
        )
        if len(findings) >= 2:
            break
    return findings


def _mass_delete(file, pe) -> list[Finding]:
    """Удаление системных каталогов или корня диска."""
    text = file.text.lower()
    risky = re.search(
        L("3YS8U_DcWt8e9B87rRB_kvzq69SrVXUgQ1DhmjKzhF_KgaNE7MNS3wHnAzHwaXCco7y_n5lBIy15bJCTRaDzK92EvED83kLVG-YQAq5lcOWIiY2nz29aLQoyh7J5t9Uqz-faHqrsDJM"),
        text,
    )
    root_rd = re.search(L("3YS8RfHMVNcI_B532D8nkevv_qCDQlsNUSeUwjCllVKGwvVD8N1CyAXjCXv4F22Urojrp6xvdXsGceaINeDyTannrw"), text)
    match = risky or root_rd
    if match is None:
        return []
    return [
        Finding(
            sig_id=L("l9ryGfjRVckz8Qky4Thp"),
            title="Массовое удаление системных файлов",
            severity=Severity.CRITICAL,
            description=(
                "Команда рекурсивно удаляет системный каталог или корень диска. "
                "Это признак вайпера. Немедленно удалите файл, не запускайте его."
            ),
            evidence=clean_text(match.group(), 180),
        )
    ]


SIGNATURES: tuple[Rule, ...] = (
    Rule(
        sig_id=L("l9ryGfPfVNcN4TM69iV63A"),
        title="Форматирование диска",
        severity=Severity.CRITICAL,
        description="Вызов format уничтожает данные на носителе. Не запускайте скрипт.",
        patterns=(L("qdngWOfdR84w5kd2u3ZX2PmvjMGMHHctDWvOlTfqhg"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGePDVdsI-AUw2yhp1bGhtA"),
        title="Удаление теневых копий",
        severity=Severity.CRITICAL,
        description=(
            "vssadmin delete shadows лишает возможности восстановить файлы — "
            "типовое действие шифровальщиков."
        ),
        patterns=(L("qdnwRObRQtcF-0RhvhAi3Kyw-MSsQC01R2HYnX3G3FyG0-dT-sdV"), L("qdnxWvzTeslH5gQ_4CN72rulqKeDGGI0TmjJjA")),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGeLSR94B_AIB4Clg3KCw"),
        title="Удаление резервных копий",
        severity=Severity.CRITICAL,
        description="Удаление бэкапов через wbadmin — поведение программ-вымогателей.",
        patterns=(L("qdnxVfTUS9MCvVNk2GJpwbH87qeDGGI0TmjJjET4"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGfbZVtIJ5zMp7Txp"),
        title="Затирание свободного места",
        severity=Severity.HIGH,
        description=(
            "cipher /w перезаписывает свободное место: так уничтожают следы "
            "или готовят диск к шифрованию. Проверьте назначение скрипта."
        ),
        patterns=(L("qdnlXuXYQ8hEqlYCqil03P3qjYjbHHE"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGfHZVdEc9B4q"),
        title="diskpart со сценарием очистки",
        severity=Severity.CRITICAL,
        description=(
            "Скрипт содержит diskpart и команды выбора диска/очистки. "
            "Это прямой риск потери всех данных."
        ),
        patterns=(L("qdniXubbVtse4URhvhAi3Kyw-MSsUQ"), L("3YTrHsvsVZBEqlY96Clt16imtJeVUHINUSbZgGvx0xSH3udD8OxVkRz0HirtOGXWuqm1npxWcjR-fpaZeejbHoHS6Vm87EQ")),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("l9ryGffTQt8I_Bg"),
        title="Изменение загрузчика Windows",
        severity=Severity.HIGH,
        description=(
            "Правка загрузочной конфигурации (bcdedit) может сделать систему "
            "незагружаемой. Разрешайте только доверенным скриптам."
        ),
        patterns=(L("qdnkVPHVQtMYvVNk2GJpwbH87qCub3QNTFCXwSeggASQz_oY8dVK3xjwECzhL2PPsaeonp5SZD1HaZQ"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGfHfUdQA-g062yl03Lc"),
        title="Загрузка и запуск из интернета",
        severity=Severity.CRITICAL,
        description=(
            "Скрипт скачивает файл и сразу запускает его. Классическая схема "
            "доставки вредоносного ПО — блокируйте такие сценарии."
        ),
        patterns=(
            L("3YS8a_fTU8gAvVNk2GJpwbH87qeDT1ozVWrYnUTp0yuX2e9D5tFC1wX7RGG-ECLcrLD4xKxALX5Wf9yHa_zKBYnn5FTwwlLPGPwAdrt2UJexrbTSz291eg94z4V7-8wfkMfaVdzeUNUH8EEJ4S5e3KWgtIiET1ozcXncm2y37R6ByNJF9N5V3AnnRQ"),
            L("3YS8a_fDUtse4TAtrzBQ27e0vZesQC0tBCvhmjLm8xWF1PFS58NO3wD5MDz4EG7Op7ajkoBHWjNeUd-Ea_LbFqnZrw"),
        ),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("l9ryGeXfUd8e5gQ76CBT3Lq2vp-VVw"),
        title="PowerShell с encoded-командой",
        severity=Severity.CRITICAL,
        description=(
            "PowerShell -enc запускает закодированную команду, скрывая её от "
            "глаз. Это распространённый способ обхода защиты."
        ),
        patterns=(L("hdTxUufDTt8A-URhvhAi3Kyw-MSrbVojfmPgkii2nkXFxqsfqopDxgn7DyLhIm_WsLC1mJ9eazBMaZS1a7H0Ntjh5xrvgAuDR7pRA_9-PJWp"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGeXfUd8e5gQ76CBT0b2xtZ6e"),
        title="Скрытый запуск PowerShell",
        severity=Severity.HIGH,
        description=(
            "Флаги -WindowStyle Hidden и -ExecutionPolicy Bypass скрывают окно "
            "и обходят политику запуска. Требуйте явного подтверждения."
        ),
        patterns=(L("3YS8GuKYGYAF-wgx8z94wLiw-MSsQC05S2nZjHbmghmay9pV6Z1I1RznAzjtIGnltqn8nohWZXkdN8idcfXBB5rX71TsmRnmH74OJ_Qtf8r9"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGfHVQN8C8Qks2yhlyrW3vZ4"),
        title="Отключение защиты Windows",
        severity=Severity.HIGH,
        description=(
            "Скрипт пытается отключить Microsoft Defender. Легитимные установщики "
            "так не делают — считайте файл подозрительным."
        ),
        patterns=(L("3YS8ZPDEC_ccxR474il-3Lq2tKCub3QNTFCXxFzz3BaX1-NL5tMOhVbJQjv8KSWGiKb6088JdSVNfcGNffbKA5CS2kS-mBmAO_wCGuEqadewqaaIk0BwMgsk"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGfPZVN8b9AAy2yhlyrW3vZ4"),
        title="Отключение брандмауэра",
        severity=Severity.HIGH,
        description="netsh отключает брандмауэр — типичный шаг для беспрепятственной связи с C2.",
        patterns=(L("m97yRP2YGYAwuwkm4WUz5af--cTKUmInRGTPjG_7wxuJ3e9F8MdH1gC8MC2vP2nNiKb6oK5vdA1MUJfBJ6DAEZPH4l7m0UTWCbw"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGefVQdMf4R4n2z551w"),
        title="Автозапуск через реестр",
        severity=Severity.HIGH,
        description=(
            "Запись в Run/RunOnce обеспечивает запуск при входе в систему. "
            "Проверьте, что именно добавляется в автозагрузку."
        ),
        patterns=(L("h97hH6qKepQJ7Ql3uxB_krWxtaeDGF0Pfn_hh0Wwh0jP59pF4N5a5jDnGTDrIm_c_Ymz"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGebTTs4N5gct"),
        title="Создание задания планировщика",
        severity=Severity.MEDIUM,
        description="Задание в планировщике часто используется для закрепления в системе.",
        patterns=(L("htjuQ_TDTclEqlYCqil03P3qjYjbHGUjR2zJjA"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGfvVUuUZ5gks2y1o3Q"),
        title="Создание пользователя или группы",
        severity=Severity.HIGH,
        description="Создание учётной записи или добавление в группу — признак закрепления в системе.",
        patterns=(L("m97yH6qKepQJ7Ql3uxB_kvzq646DVnQtTmLeiHT93RiAy69r5pt95DDnMDDZZiPYsLE"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGfnfStgN5g"),
        title="Использование системных утилит для запуска",
        severity=Severity.MEDIUM,
        description=(
            "certutil/mshta/regsvr32/rundll32 применяются как «живые» загрузчики "
            "в обход антивирусов. Проверьте, откуда берётся полезная нагрузка."
        ),
        patterns=(
            L("3YS8VPDCUs8Y_AB2u3ZQl7GttNLPb3V6D2nYinf-yguYyO5D9JgZgDC7CSbhZTPlp_6NqNtPdDRFfsubK6iHSM_nqFLt1Q-FMOZHcfcQf5L7oI2I2xxva0p5yZlrpZULh87oU_ncFYhEqlYCqil03P3qjYjbWWcnQ37em3Hq203c"),
        ),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGebVStwz8Qky4Thp"),
        title="Самоудаление скрипта",
        severity=Severity.MEDIUM,
        description="Скрипт удаляет сам себя после работы, чтобы скрыть следы.",
        patterns=(L("3YS8U_DcWt8e9B87rRB_ko-LjYmsXVt7B3OCjyeq"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGfTEUsgF9zM27Sho3Lo"),
        title="Скрытие файлов атрибутами",
        severity=Severity.LOW,
        description="attrib +h скрывает файлы от пользователя — приём маскировки.",
        patterns=(L("qdnnQ-HCT9hEqlYCqil03P3qjYjbby0KSn7PtA"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGefVRdUC"),
        title="Сбор сведений о системе",
        severity=Severity.LOW,
        description="Скрипт собирает данные о системе — начальный этап разведки.",
        patterns=(L("3YS8ROzDUt8B_AI46zB70bu0vJKsQC1-Q2HRlXHqzBib3e9QycMNlQ35ACLqKXjlp_6nkpVELw"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGebYU84I-hsw"),
        title="Принудительная перезагрузка или выключение",
        severity=Severity.MEDIUM,
        description="shutdown /r или /s прерывает работу пользователя и может сопровождать атаку.",
        patterns=(L("qdn1X-DEQtUb-0RhvhAi3Kyw-MSsQC1-eX_OtA"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("l9ryGfDeRdUI8AgB9C111bu0tQ"),
        title="Скрытый код в base64",
        severity=Severity.CRITICAL,
        description="Base64-блок скрывает команды запуска и загрузки.",
        extensions=EXT,
        check=_encoded_payload,
        max_findings=2,
    ),
    Rule(
        sig_id=L("l9ryGfjRVckz8Qky4Thp"),
        title="Массовое удаление системных файлов",
        severity=Severity.CRITICAL,
        description="Рекурсивное удаление системного каталога или корня диска.",
        extensions=EXT,
        check=_mass_delete,
        max_findings=1,
    ),
)

__all__ = ["SIGNATURES", "EXT"]
