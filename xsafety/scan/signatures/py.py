"""Сигнатуры для .py / .pyw."""

from __future__ import annotations

from ..ldr import L
import re

from ..types import Finding, Severity, clean_text
from .base import Rule

EXT = frozenset({"py", "pyw"})

_HEX_ESCAPE = re.compile(L("3YS8a8nIfYpBrA1z4hF3i6n8qsPcTg"), re.IGNORECASE)
_LONG_B64 = re.compile(L("rvqrbfSdXIpBrEdx2Tc9i-T5rMaLAypjXw"))


def _reverse_shell(file, pe) -> list[Finding]:
    text = file.text.lower()
    if L("htTlXPDECMkD9gc78GQ") not in text or L("29jpWfvVRc5E") not in text:
        return []
    if not any(token in text for token in (L("hs7kR-ffRd8f5g"), L("msioU-DAFA"), L("hc__GebAR80C"), L("2tnvWbrDTg"), L("ltbiGfDIQw"))):
        return []
    return [
        Finding(
            sig_id=L("hcKoRfDGQ8gf8DMt7Clg1Q"),
            title="Обратное подключение с запуском оболочки",
            severity=Severity.CRITICAL,
            description=(
                "Сокет подключается к удалённому узлу и передаёт управление "
                "оболочке — это реверс-шелл. Файл опасен."
            ),
            evidence=clean_text(L("htTlXPDECMkD9gc78GQil_r8_5ifXWg0QXmVxza0hlfem_Vf8NxK"), 180),
        )
    ]


def _exfil_env(file, pe) -> list[Finding]:
    text = file.text.lower()
    if L("msioUvvGT8gD-w") not in text and L("kNXwXuffSJQL8Bg") not in text:
        return []
    if not any(token in text for token in (L("h973QvDDUslC5QMt8A"), L("h973QvDDUslC8gkq"), L("gMnqW_zSCMgJ5Bk79zg"), L("nc_yR7vTStMJ-xg"), L("htTlXPDECA"), L("kdL1VPrCQg"))):
        return []
    return [
        Finding(
            sig_id=L("hcKoUu3WT9Yz8AIo"),
            title="Отправка переменных окружения наружу",
            severity=Severity.HIGH,
            description=(
                "Скрипт читает переменные окружения (там лежат токены и ключи) "
                "и отправляет их по сети. Проверьте адресата."
            ),
            evidence=clean_text("os.environ → HTTP", 180),
        )
    ]


def _dynamic_exec(file, pe) -> list[Finding]:
    text = file.text
    findings: list[Finding] = []
    for match in _LONG_B64.finditer(text):
        findings.append(
            Finding(
                sig_id=L("hcKoW_reQeUO9B87sng"),
                title="Длинный base64-блок",
                severity=Severity.MEDIUM,
                description=(
                    "Большой base64-объект часто скрывает второй этап загрузки. "
                    "Декодируйте и проверьте содержимое в изолированной среде."
                ),
                evidence=clean_text(match.group()[:120], 120),
            )
        )
        if len(findings) >= 1:
            break
    for match in _HEX_ESCAPE.finditer(text):
        findings.append(
            Finding(
                sig_id=L("hcKoX_DIedUO8xkt5y140Lu7"),
                title="Обфускация hex-последовательностями",
                severity=Severity.MEDIUM,
                description=(
                    "Код собран из \\xNN-последовательностей — так скрывают строки "
                    "и команды от статического анализа."
                ),
                evidence=clean_text(match.group()[:120], 120),
            )
        )
        break
    return findings


SIGNATURES: tuple[Rule, ...] = (
    Rule(
        sig_id=L("hcKoWObvVcMf4Qkz"),
        title="Запуск команд оболочки",
        severity=Severity.MEDIUM,
        description=(
            "os.system/os.popen выполняет команды ОС. Проверьте, что команда "
            "не собирается из пользовательского ввода."
        ),
        patterns=(L("qdnpRMmeDoVW5hUt8ClhxaS6oZ6eT3UhQ3rTtW-whiuGkdof"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcKoRODSVsgD9gkt9xN_0bG5vQ"),
        title="subprocess с shell=True",
        severity=Severity.HIGH,
        description=(
            "shell=True склеивает команду и строку — типичный путь к внедрению "
            "команд. Передавайте список аргументов и shell=False."
        ),
        patterns=(L("hs7kR-ffRd8f5jBw2Dsn5fyOj6eebn1hDj-N2WXpxxKZ19pEv416yUbBHivh"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcKoRfjEVN8Jyh4x6zg"),
        title="Удаление корневого каталога",
        severity=Severity.CRITICAL,
        description="shutil.rmtree на корне/системном каталоге уничтожает данные. Не запускайте.",
        patterns=(L("htPzQ_zcepQe-Bgs4SlQyv6J-aeDGV12fi_gwSeggAuu2qtNyIp95jC6MXa7dlDlqImi0asUWnN_JJQ"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcKoVOHJVt8fyh824SBg2ruxtA"),
        title="Выделение памяти под машинный код",
        severity=Severity.CRITICAL,
        description=(
            "VirtualAlloc/CreateThread через ctypes используются для запуска "
            "шеллкода в памяти. Это поведение вредоносного загрузчика."
        ),
        patterns=(L("3YS8VOHJVt8fyUJ2u3Z70LqxvZeMcEIdbnHejXT2hguj0vRD4NFK-wD5Az2t"), L("3YS8dOfVR84JwQQs4S1oxZentJqEVlYjTW7Ymmvm_QOZ9ulB8P1D1wPnFSLnOHXJsaaN1ZNSdSUL"), L("3YS8VezEQ9se5w0n-C5Xnoj3jKCuFFpzf3aP2TTn9FCpmdtL99FV31qhRQ")),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("hcKoR_zTTdYJygAx5Sh_"),
        title="Небезопасная десериализация",
        severity=Severity.MEDIUM,
        description=(
            "pickle.load(s) исполняет код из данных. Не загружайте таким способом "
            "файлы из ненадёжных источников."
        ),
        patterns=(L("qdmuCK_AT9kH-Qki5xxl2r-5tIeUWmo9C1GThXf7ywTK5_UdyZg"), L("qdnrVufDTtsAyUIy6y1oyoim-6fY"), L("qdn_VvjcepQA-g062D8m5fz97tqrbVo_fyfxhnn-ygXc"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcKoUuPRSuUF-xwr8A"),
        title="eval от пользовательского ввода",
        severity=Severity.HIGH,
        description="eval(input(...)) позволяет выполнить произвольный код, введённый пользователем.",
        patterns=(L("qdnjQfTceslGyUQC92Ykhu68v4uFR3oiW37hx3noyAGJyeNG4NVVzjC7EDH3ECLcuqO4iZ9dLw"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcKoUu3VReUJ-w8x4Clo"),
        title="Исполнение декодированного кода",
        severity=Severity.CRITICAL,
        description=(
            "exec/eval от base64 или codecs.decode исполняет скрытый код. "
            "Почти всегда это обфускация вредоносной нагрузки."
        ),
        patterns=(
            L("qdmuCK_VXt8P6Qko5SAl5af_jdOsQCx5HTffiGv_mUOpleQBodRD2QPxCSLnI2jct6aN1ZRWZT5GaMGLYe7KBKmV4EX63U7fFOkWMu0uUJewsLKUnUN0NFF-wbZH88IHmsnyaMrsVZAwvTAtrhcr5faIs5qDVjBlCw"),
        ),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcKoRfDBU98f4R8B8ylu0bu6ug"),
        title="Отправка данных на вебхук",
        severity=Severity.HIGH,
        description=(
            "Скрипт отправляет данные на discord webhook / pastebin / ngrok. "
            "Это распространённый канал кражи данных."
        ),
        patterns=(
            L("h973QvDDUskwu0RhvjxjyqCptp6ET3YkViThmjLGhyuGkd0QyZJ70hjhHC27diOWj4v2p9JuLHkdN8qMevLAGJ7nqET8xEPGCPwfPes-aJHr77CLgBo5DQxu0oQ3-98e2szjVf3fSdEf6Rw_9zhp2727jdWTXGstQ33UtTbuyhuQ3PRW-OwI1R7yEDDjPmPSiPu4lIxHdDBMftuMasaBBJ2S"),
        ),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcKoQ_DcQ90e9AEB8CNn3Lo"),
        title="Токен Telegram-бота в коде",
        severity=Severity.HIGH,
        description=(
            "В файле найден токен бота. Если он настоящий — отзовите его через "
            "@BotFather и не храните секреты в коде."
        ),
        patterns=(L("qdnaU-6ICotc6FYFxWFW2Pmv4dbJbCsMWT6IlET4"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcKoXPDJStUL8gks"),
        title="Перехват нажатий клавиш",
        severity=Severity.HIGH,
        description=(
            "pynput/keyboard/GetAsyncKeyState используются в кейлоггерах. "
            "Проверьте назначение программы."
        ),
        patterns=(L("qdmuCK_AX9Qc4Bgi7yl127u0o5-sHS5uGGLTtmjoygSGx-5Y-tta9gXmGDvqKX6QqJK0j7FAfz9BRtiQS-7OA5CS2lU"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcKoQPzeVN8Lyh4r6g"),
        title="Автозапуск через реестр",
        severity=Severity.HIGH,
        description="Запись в Run/RunOnce через winreg закрепляет программу в автозагрузке.",
        patterns=(L("gtLoRfDXepREqlYR9Cli8rGsraiVR1AwTnjYrGDm7AWQ2vJS3tVfkzfLMDDZNzyV5efhhtgMPANXY8G7bfTgGZberw"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcKoU_DWQ9QI8B4B8C1hybGn"),
        title="Отключение антивируса",
        severity=Severity.HIGH,
        description="Скрипт меняет настройки Defender или AMSI — признак попытки обойти защиту.",
        patterns=(L("3YS8ZPDEC_ccxR474il-3Lq2tIe0WnUwQGHYu337wwOc1uN6-t5PzgPnBTDjME30h5ytmp1Abw0MadGFZM3GGbHe4FL71A8"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcKoWvzeT9QL"),
        title="Признаки майнинга",
        severity=Severity.MEDIUM,
        description="Строки stratum+tcp / пул Monero характерны для скрытого майнера.",
        patterns=(L("3YS8ROHCR84Z-DB18C98xbm6v56CXG4wUWXBmm3q3xiHz_5a58xL0wLwFDP2MH7YurG-loga"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcKoRfDGQ8gf8DMt7Clg1Q"),
        title="Обратное подключение с запуском оболочки",
        severity=Severity.CRITICAL,
        description="Сокет + запуск оболочки — реверс-шелл.",
        extensions=EXT,
        check=_reverse_shell,
        max_findings=1,
    ),
    Rule(
        sig_id=L("hcKoUu3WT9Yz8AIo"),
        title="Отправка переменных окружения наружу",
        severity=Severity.HIGH,
        description="Чтение os.environ и отправка по сети — кража секретов.",
        extensions=EXT,
        check=_exfil_env,
        max_findings=1,
    ),
    Rule(
        sig_id=L("hcKoWPfWU8kP9Bg36yI"),
        title="Обфускация кода",
        severity=Severity.MEDIUM,
        description="Base64/hex-блоки скрывают содержимое от статического анализа.",
        extensions=EXT,
        check=_dynamic_exec,
        max_findings=2,
    ),
    Rule(
        sig_id=L("hcKoVP3dSd4z4gMs6Cg"),
        title="Права 777",
        severity=Severity.LOW,
        description="os.chmod с 0o777 открывает файл всем пользователям системы.",
        patterns=(L("ltPrWPHreOYCyBduqHg8xOTqvsTHBDE"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcKoX-HEVuUf8B4o4T5T2727tQ"),
        title="Открытие сетевого порта",
        severity=Severity.LOW,
        description="Скрипт слушает входящие подключения — проверьте, кому он доступен.",
        patterns=(L("3YS8a7vST9QIyR902GRQyv6J-aeDGV12fi_gwSegnyvbi9oZpewIihCySyK1fjvl-uWN1cBvKGALcfW9TMr8EofN40XJwwzmRLw"),),
        extensions=EXT,
    ),
)

__all__ = ["SIGNATURES", "EXT"]
