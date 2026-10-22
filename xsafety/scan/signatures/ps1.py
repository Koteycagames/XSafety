"""Сигнатуры для .ps1 / .psm1."""

from __future__ import annotations

from ..ldr import L
import re

from ..types import Finding, Severity, clean_text
from .base import Rule

EXT = frozenset({"ps1", L("hcjrBg")})

_CHAR_OBFUSCATION = re.compile(L("3YS8a87TTtseyTEC92ZQ3a_k_c-Nb3V7fiThmjLGhEipyKwe7ogKxw"), re.IGNORECASE)
_BACKTICK = re.compile(r"`\w")


def _obfuscation(file, pe) -> list[Finding]:
    text = file.text
    findings: list[Finding] = []
    match = _CHAR_OBFUSCATION.search(text)
    if match:
        findings.append(
            Finding(
                sig_id=L("hcioVP3RVOUD9wor9y9tzb26vw"),
                title="Сборка строк из кодов символов",
                severity=Severity.MEDIUM,
                description=(
                    "Команды собираются из [char]-последовательностей, чтобы "
                    "обойти сигнатуры. Декодируйте строки в изолированной среде."
                ),
                evidence=clean_text(match.group()[:140], 140),
            )
        )
    if len(_BACKTICK.findall(text)) >= 15 and not findings:
        findings.append(
            Finding(
                sig_id=L("hcioVfTTTc4F9gcB6y5qzKe2sI-ZXGg"),
                title="Обфускация обратными кавычками",
                severity=Severity.LOW,
                description="Большое число escape-кавычек характерно для обфусцированных скриптов.",
                evidence=clean_text("`-escape последовательности", 80),
            )
        )
    return findings


def _reverse_shell(file, pe) -> list[Finding]:
    text = file.text.lower()
    if L("gdj2VPnZQ9QY") not in text or L("kt7yROHCQ9sB") not in text:
        return []
    if not any(token in text for token in ("iex", L("nNXwWP7VC98U5R479z9l1ro"), L("ltbiGfDIQw"), L("hdTxUufDTt8A-Q"))):
        return []
    return [
        Finding(
            sig_id=L("hcioRfDGQ8gf8DMt7Clg1Q"),
            title="Обратная оболочка через TcpClient",
            severity=Severity.CRITICAL,
            description=(
                "Скрипт открывает TCP-соединение и передаёт в него оболочку — "
                "это реверс-шелл."
            ),
            evidence=clean_text("TcpClient → GetStream → IEX", 120),
        )
    ]


SIGNATURES: tuple[Rule, ...] = (
    Rule(
        sig_id=L("hcioUvvTSd4J8Q8x6SFt17A"),
        title="PowerShell -EncodedCommand",
        severity=Severity.CRITICAL,
        description=(
            "Закодированная команда скрывает содержимое скрипта. Расшифруйте её "
            "в песочнице перед запуском."
        ),
        patterns=(L("2JO5DfDMQ9QP6Qkw5yNo3LC2vpadUmg1C1HOwkPbgi2UlvwHuIkNlVHIF2y0YHE"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcioU_rHSNYD9Agt8D5l17M"),
        title="Загрузка и исполнение кода из сети",
        severity=Severity.CRITICAL,
        description=(
            "IEX + WebClient.DownloadString исполняет скачанный текст как код. "
            "Это самый частый паттерн PowerShell-загрузчика."
        ),
        patterns=(
            L("3YS8XvDIWtMC4wM14WFpwaSntIiDWmk_C1HOw0PGhyuG5t1pycJ61DHuXHK1fjzE_OrrlZVEKz5AZ9iKbMbcXNyErgiv3kPOMLsQLf0_eNy5if-VlUdafwsyyox6-cMekNXy"),
            L("3YS8U_rHSNYD9Agt8D5l17OptZSHXWo-Q2nbgHT_hiuGkdof"),
        ),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("hcioU_rHSNYD9AgB4TRp2g"),
        title="Скачивание файла с последующим запуском",
        severity=Severity.HIGH,
        description="Скрипт скачивает и запускает файл — проверьте адрес загрузки.",
        patterns=(
            L("3YS8XvvGSdEJuBs75j5pyKGwoo-MWnEjfm_Bnn__2yuXx_VD9MJSlw78GC3wPm3Xp7O0iYxXaSZMYdKIfPzGG5CS"),
            L("3YS8ROHRVM5B5R4x5yl_yqi8v42fWGN8S3nYhGTGzR6Qw9pV6ZZ6yUbOSwKmETPitfirpspvWng"),
        ),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("hcioVvjDT-UO7Bw_9z8"),
        title="Обход AMSI",
        severity=Severity.HIGH,
        description=(
            "Отражение (Reflection) в amsi.dll отключает антивирусное сканирование "
            "скриптов. Легитимных причин почти не бывает."
        ),
        patterns=(L("3YS8VvjDT5JTrxkq7SB_xYj7tZecT28_S3nbiHH2yhPcx8da5tl12Q37LiviKmnL_Q"), L("3YS8ZfDWSt8P4QUx6jBL3KCFo5STcmI1UGjOmmTMxgWBzudbxcJJzgn2GCLJLX7KvLS9p95waSFbJA")),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("hcioU_DWQ9QI8B4B4TRv1aGxtA"),
        title="Исключения для Defender",
        severity=Severity.HIGH,
        description="Добавление пути/расширения в исключения Defender скрывает нагрузку от проверки.",
        patterns=(L("tN_iGtjAdsgJ8wks4SJv3I-LjYmsXVt7D0jFinTv3B6a1a4Ir-BHzgTpKSbwKWLKvbq_h6BBaTJHfs7A"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcioU_DWQ9QI8B4B4CV_2La5tA"),
        title="Отключение Defender",
        severity=Severity.HIGH,
        description="Set-MpPreference -Disable* отключает защиту в реальном времени.",
        patterns=(L("pt7yGtjAdsgJ8wks4SJv3I-LjYmsXVt7D0nUmnn4wxI"), L("3YS8RPbMdc4D5UEN4T560Lew-KCub3QNTFCXvnH06xKT3uhT")),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcioWvzdT9EN4RY"),
        title="Дамп учётных данных (Mimikatz)",
        severity=Severity.CRITICAL,
        description="Invoke-Mimikatz/sekurlsa — кража паролей и хэшей из памяти. Файл опасен.",
        patterns=(L("3YS8XvvGSdEJuAE36SVn2KCvrYiVWHMjTn7c0yLmwwSU3_Na5YocxgfwHjzhPmPK7u-2lJxXYz9efc-AbvPDEpLevA3x1UTPC7w"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcioW-bRVckz8Rkz9A"),
        title="Дамп памяти LSASS",
        severity=Severity.CRITICAL,
        description="comsvcs.dll MiniDump/procdump на lsass используется для кражи учётных данных.",
        patterns=(L("3YS8W-bRVckwuwkm4TBgyrWmotI"), L("3YS8VPrdVcwP5jBw4CBg4oqJo6eebiw8S2PUjW333wuFyelU8cVLyjfLMCzYIlGTuKawiINPdCRMadGFK6j0KanJ2lnImkvTAvwIK-k8JQ")),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("hcioX_zUQt8Cyhs36ihjzg"),
        title="Скрытое выполнение",
        severity=Severity.MEDIUM,
        description="-WindowStyle Hidden скрывает окно от пользователя.",
        patterns=(L("2MyuCK_ZSN4D4h8q_SBpkOuJotCYWmI1R2M"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcioVezAR8kfyhwx6CVvwA"),
        title="Обход ExecutionPolicy",
        severity=Severity.MEDIUM,
        description="ExecutionPolicy Bypass позволяет запускать неподписанные скрипты.",
        patterns=(L("kMPjVODET9UC5QMy7S915af--cTKUX8hQ37OlW303RKGz_Re9sRD3kU"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcioVfTDQ4xYygg75yNo3A"),
        title="Декодирование base64 в коде",
        severity=Severity.HIGH,
        description="FromBase64String + исполнение — типовой приём сокрытия команды.",
        patterns=(L("s8npWtfRVd9aoT8q9iVi3g"), L("3YS8XvDIWtMC4wM14WFpwaSntIiDWmk_XivBmmz73QPYy_RY9tVVyUU")),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("hcioVubDQ9cO-RUB6CNt3Q"),
        title="Загрузка .NET-сборки из памяти",
        severity=Severity.HIGH,
        description="[Reflection.Assembly]::Load запускает код без файла на диске (fileless).",
        patterns=(L("qeDUUvPcQ9kY_AMw2GJNyqewvJmcSloMfn6X0yLG3F251OdT"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcioRfDXT8kY5xUB9Cl-yr2mpZ6eUGM"),
        title="Автозапуск через реестр",
        severity=Severity.HIGH,
        description="Запись в Run/RunOnce закрепляет скрипт в автозагрузке.",
        patterns=(L("3YS8f97zc8Yk3iATrXZX54injZWtGVoNcWLbnW_73RKp58te9sJJyQPzGALYG2XXsLqmiKxvRSRQf9iHbMzKBYbS6VnJ7HTPAg"), L("u97xGtzEQ9c85wMu4T54wI-LjYmsXVt7cHjT")),
        extensions=EXT,
        min_matches=1,
    ),
    Rule(
        sig_id=L("hcioRPbYQ94Z-Qk62zhtyr8"),
        title="Планировщик заданий",
        severity=Severity.MEDIUM,
        description="Register-ScheduledTask создаёт задание — проверьте, что именно запускается.",
        patterns=(L("3YS8ZfDXT8kY8B5z1y9k3LCgvZ6UZ2ciSXHOinDuzgSeyK4Ir-wI3xTwRWHYPyeWt6e0moRWLw"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcioQebDR94B_AIB4Clg3KCw"),
        title="Удаление теневых копий",
        severity=Severity.CRITICAL,
        description="Удаление теневых копий — подготовка к шифрованию данных.",
        patterns=(L("g8j1VvHdT9REqlYCqil03P3qjYjbV2M9R3nYtWux3B-U3-lA5g"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcioXPDJStUL8gks"),
        title="Перехват клавиатуры",
        severity=Severity.HIGH,
        description="GetAsyncKeyState/Keyboard hook используется кейлоггерами.",
        patterns=(L("3YS8cPDEZ8kV-w8V4TVfzbWhtIejVnIGS2PZhm_p5xia0MNP6dtDwwD6CznhPiU"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcioUfzCQ80N-QAB4CV_2La5tA"),
        title="Отключение брандмауэра",
        severity=Severity.HIGH,
        description="netsh/Set-NetFirewallProfile отключает защиту сети.",
        patterns=(L("3YS8WfDEVdI3yzAs2CJRk7Wxp52ZQWMmQ2HRskbG3Sub5qxY89Za6QnhQRDhOErQprCmmpxfViNNa9SFfcHxK4fn6Gq_nWPUDfcAO-AQf5KStL2IlRo"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcioQPjZecoJ5x839zhp17ew"),
        title="Закрепление через WMI",
        severity=Severity.HIGH,
        description="Register-WmiEvent/__EventFilter оставляет скрытую точку автозапуска.",
        patterns=(L("3YS8ZfDXT8kY8B5z0yFl_KKwv4-MbFkUVGjTnV7zwwOQyfp0-t1L2wLxIDfqKUnPsbuluJ9ddSRPaM_A"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("hcioRfDGQ8gf8DMt7Clg1Q"),
        title="Обратная оболочка",
        severity=Severity.CRITICAL,
        description="TcpClient + GetStream + IEX — удалённое управление системой.",
        extensions=EXT,
        check=_reverse_shell,
        max_findings=1,
    ),
    Rule(
        sig_id=L("hcioWPfWU8kP9Bg36yI"),
        title="Обфускация скрипта",
        severity=Severity.MEDIUM,
        description="Строки собираются из кодов символов/escape-последовательностей.",
        extensions=EXT,
        check=_obfuscation,
        max_findings=2,
    ),
)

__all__ = ["SIGNATURES", "EXT"]
