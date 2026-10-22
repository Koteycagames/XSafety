"""Общие сигнатуры: тестовый вирус, утечки секретов, креды.

Правила применяются к любому поддерживаемому расширению. Секреты в
доказательствах маскируются (sigutil.redact) ещё до формирования отчёта.
"""

from __future__ import annotations

from ..ldr import L
import re

from ..types import Severity
from .base import Rule

SECRET_EXT = frozenset({"bat", "cmd", "py", "pyw", "js", "mjs", "cjs", "ps1", L("hcjrBg"), "vbs", "vbe", "hta"})

EICAR = (
    L("rY7JFsWVZvs8yTdq2BBc44zg5afYY1oPfiSKqlvGhkCpxtoT0Pll-z64PwrFAkj4hpH8ur5nTwdrX-i6Nc7qJKGWwH7Z9QfmSN0wdcwQJg")
)


def _eicar_ok(file, pe) -> list:
    # Регулярка с обратными слэшами проверяется ещё раз по «сырой» строке.
    from ..types import Finding, clean_text

    needle = L("rY7JFsWVZvs8zlgC1BZUjOD9gaXZBEUSCzrAzV3T7DanltVj1P5i-z7RQR_KGEXvnYeEqN1nQwJ2IPugVN-OU72Qzh0")
    haystack = file.text if file.ext in {"bat", "cmd", "py", "pyw", "js", "mjs", "cjs", "ps1", L("hcjrBg"), "vbs", "vbe", "hta"} else "\n".join(file.strings)
    if needle in haystack:
        return [
            Finding(
                sig_id=L("ltTrWvreCN8F9g0s"),
                title="Тестовый вирус EICAR",
                severity=Severity.CRITICAL,
                description=(
                    "Файл содержит сигнатуру EICAR — безопасный тестовый образец "
                    "для проверки антивируса. Если вы не тестируете защиту, "
                    "удалите файл."
                ),
                evidence=clean_text(needle, 60),
            )
        ]
    return []


SIGNATURES: tuple[Rule, ...] = (
    Rule(
        sig_id=L("ltTrWvreCN8F9g0s"),
        title="Тестовый вирус EICAR",
        severity=Severity.CRITICAL,
        description="Сигнатура EICAR используется для проверки антивирусов.",
        check=_eicar_ok,
        kind="any",
        max_findings=1,
    ),
    Rule(
        sig_id=L("ltTrWvreCMoe_Bo_8ClT0rGs"),
        title="Приватный ключ в файле",
        severity=Severity.CRITICAL,
        description=(
            "В файле лежит приватный ключ. Если он настоящий — немедленно "
            "отзовите сертификат и уберите ключ из репозитория."
        ),
        patterns=(L("2JarGrjyY_0l20x2u3Ze6pX1rb6zE3oeckjzukvSjwul_NYXvI926CXDLQrBbEf8jfj81t0e"),),
        kind="any",
        max_findings=1,
    ),
    Rule(
        sig_id=L("ltTrWvreCNsb5jM14TU"),
        title="Ключ доступа AWS",
        severity=Severity.HIGH,
        description="Найден ключ AWS (AKIA...). Отзовите его в IAM и храните секреты в менеджере.",
        patterns=(L("qdnHfNzxfYpBrC1z3hF3iOKojZk"),),
        kind="any",
        max_findings=1,
    ),
    Rule(
        sig_id=L("ltTrWvreCN0F4QQr5hN41r-wvw"),
        title="Токен GitHub",
        severity=Severity.HIGH,
        description="Найден токен GitHub. Отзовите его в настройках разработчика.",
        patterns=(L("qdnhX87ASc8f5zEB3w0h47X4q8vdClsqETuRlET4"), L("qdnhXuHYU9gz5Q0q2xdNlI60_IHAHj8Of3aJ2TTn8xU")),
        kind="any",
        max_findings=1,
    ),
    Rule(
        sig_id=L("ltTrWvreCMkA9A812zhj0rG7"),
        title="Токен Slack",
        severity=Severity.HIGH,
        description="Найден токен Slack. Отзовите его в административной панели.",
        patterns=(L("qdn-WO3rRNsc5x8DqRdNlI60_IHAHj98f3aM2TTn"),),
        kind="any",
        max_findings=1,
    ),
    Rule(
        sig_id=L("ltTrWvreCN4F5g8x9ihTzrG3uZSfWA"),
        title="Вебхук Discord",
        severity=Severity.MEDIUM,
        description=(
            "В файле указан вебхук Discord — канал, через который часто "
            "выгружают украденные данные. Проверьте, кто его создал."
        ),
        patterns=(L("nc_yR-aKCZVEqlYu8C5Ql6i2sJWRQX8NDCSCjXHpzBiH364Ir9FWykWqMHDnI2GWtaW41IdWZDlNYtaaN8bLXNrgxxrP0QvAXLhVAakRJw"),),
        kind="any",
        max_findings=1,
    ),
    Rule(
        sig_id=L("ltTrWvreCM4J-Qk59i1h5qC6up6e"),
        title="Токен Telegram-бота",
        severity=Severity.HIGH,
        description=(
            "Найден токен Telegram-бота. Отзовите его через @BotFather: "
            "токен даёт полный контроль над ботом."
        ),
        patterns=(L("qdnaU-6ICotc6FYFxWFW2Pmv4dbJbCsMWT6IlET4"),),
        kind="any",
        max_findings=1,
    ),
    Rule(
        sig_id=L("ltTrWvreCMoA9AUw8Cl0zYulsIiDRGkjRg"),
        title="Пароль в открытом виде",
        severity=Severity.LOW,
        description=(
            "В скрипте хранится пароль. Используйте переменные окружения или "
            "менеджер секретов, а пароль смените."
        ),
        patterns=(
            L("3YTvHsnSDoVW5Q0t9ztjy7CpoZqDQHE1Xn3KjTHGzSuGkd0NqO16yUbOSwKmEVfn84nzp4JvaAxZPpHfLOf0UKmZ2w"),
        ),
        extensions=SECRET_EXT,
        kind=L("gd7-Qw"),
        max_findings=2,
    ),
    Rule(
        sig_id=L("ltTrWvreCNYD-wsB8CNn3Lo"),
        title="Длинный секрет в коде",
        severity=Severity.MEDIUM,
        description=(
            "Строка похожа на API-ключ или JWT. Проверьте, не является ли она "
            "действительным секретом, и уберите её из кода."
        ),
        patterns=(
            L("qdnjTt_rZ5c29EEktGE15vmIqsrAH3sNDFb8xEL7gg3Flr9ouO1di1y5EQKqF02UjrT8gcAePw4PUMbYKLbSK5c"),
            L("3YTvHsnSDoVW9Bw33xMh5Ou-tIKMQGMyUGjJlWz1xBKbktpVycMM4VaoMQL3ZleeiPeMoLEeXDAPd43EIcXzWqjAtAO5zX2dMLcx"),
        ),
        extensions=SECRET_EXT,
        kind=L("gd7-Qw"),
        max_findings=1,
    ),
)

__all__ = ["SIGNATURES", "EICAR"]
