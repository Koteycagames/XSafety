"""Сигнатуры для .js / .mjs / .cjs и встроенного JS внутри .hta."""

from __future__ import annotations

from ..ldr import L
from ..types import Severity
from .base import Rule

EXT = frozenset({"js", "mjs", "cjs", "hta"})
JS_ONLY = frozenset({"js", "mjs", "cjs"})

SIGNATURES: tuple[Rule, ...] = (
    Rule(
        sig_id=L("n8ioUuPRSuUN4QM8"),
        title="eval(atob(...))",
        severity=Severity.CRITICAL,
        description=(
            "Код декодирует base64 и сразу исполняет результат — способ скрыть "
            "вредоносную нагрузку. Не открывайте файл в браузере."
        ),
        patterns=(
            L("qdnjQfTceslGyUQC92Ykhu60pZSST3M_R37eiGj_0xOQ2OlT8OV08y_6AS7rImnXoPyNiNpvLg"),
            L("qdnjQfTceslGyUQC92Ykhu6GpYmZXWENDGvPhnXZxxaH-OlT8MxkzwrzCSzYYmrLu7j4p4MZWnk"),
        ),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("n8ioUuPRSuUI7AI_6SVv"),
        title="Динамическое исполнение кода",
        severity=Severity.MEDIUM,
        description=(
            "eval/new Function исполняют строку как код. Если строка приходит "
            "из сети или ввода — это критическая уязвимость."
        ),
        patterns=(L("qdmuCK_VUNsA6QI78xB_kpKgv5iEWmk_C1HOw0Sy"), L("qdnAQvvTUtMD-zAtrhAk5af_itysEVs")),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("n8ioQObTVNMc4TMt7Clg1Q"),
        title="WScript.Shell",
        severity=Severity.HIGH,
        description=(
            "WScript.Shell запускает процессы Windows. В связке с Run/Exec это "
            "типовой способ доставки нагрузки через HTA/JS."
        ),
        patterns=(L("oujlRfzAUuZCxgQ76CA"), L("qZWuCK_iU9QQ0BQ752VQyv6J-Q")),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("n8ioVvbET8wJ7QM87ilvzQ"),
        title="ActiveXObject",
        severity=Severity.MEDIUM,
        description=(
            "ActiveXObject даёт доступ к системе (файлы, сеть, оболочка). "
            "Современный легитимный код его почти не использует."
        ),
        patterns=(L("m97xa-abZ9kY_Bo73ANu07G2paeDGVp5fn6Xsj_GjSrdhLxgxtNU0xzhMHDXJGnVuKmCmIJadiVLY9q1NtzGG5Do_0Th1Uv1Dv8JPfAwQeqMmJ3JrB16Bktj9Z1s6vNZifrCeNHyepRF"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("n8ioVP3ZSt4z5R4x5yl_yg"),
        title="child_process.exec",
        severity=Severity.HIGH,
        description="Node.js исполняет системные команды — проверьте источник аргументов.",
        patterns=(L("3YS8RfDBU9Me8DAtrhAk5af_itysEVsySmTRjUfq3RiW3vVEzpd6mDHJRSLiPmPUiKb6oNdvJAxBZdSFfMXfBZrY40Tm6wHmTshF"), L("qdmuCK_VXt8P6Qkm4S9fwLq2rYiAUnE_cXTTijHG3F2pkw")),
        extensions=JS_ONLY,
        min_matches=2,
    ),
    Rule(
        sig_id=L("n8ioQPDSTtUD_jM7_Cpl1Q"),
        title="Отправка данных на вебхук",
        severity=Severity.HIGH,
        description=(
            "Код отправляет данные на Discord webhook/pastebin/ngrok — "
            "типовой канал кражи токенов и Cookie."
        ),
        patterns=(
            L("3YS8UfDERdIQ9BQ36z9Ql_zq64ufQHItRWjJwGTC4ju9z_JHx9VXzwnmGHffEH_lh4iqy9wCMGFfMtWdbOrcSM-UqWzLl3qYMOYxdKxzNt29prKUglcubhhszZkxpfNZltTrGPTAT5Ub8A426yNnyqiitJmYXGk6fiPOgGz_0weUyPJS99lI5kL2AzP4LXzQiPulnpxWYSNDYOHHd-jIC5vc9Fj-7AjTA-kYLOUif9-xp43Vg1sv"),
        ),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("n8ioVPrfTdMJygkm4iVg"),
        title="Кража document.cookie",
        severity=Severity.HIGH,
        description="Cookie читаются и отправляются по сети — угон сессии.",
        patterns=(L("kdTlQvjVSM4wuw8x6ydl3A"), L("3YS8UfDERdIQzSESzDh4yYawoI6VQHIta2Dcjn3G3F2pk9pEv-wPxh_nDwL3ZjGQ")),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("n8ioU_zDRdUe8TMq6ydp14uyo5qS"),
        title="Кража токена Discord",
        severity=Severity.CRITICAL,
        description=(
            "Код ищет токен Discord в localStorage и отправляет его наружу. "
            "Это вредоносный стилер."
        ),
        patterns=(
            L("mdTlVvnjUtUe9As72GIkhu6ytI-5R2M8XmbYkDHG3F2pk91pvO0MklOvGDHvKWLFsLyimJ9BYng"),
            L("kdL1VPrCQuEw5jAN2Tc8leXn4YbYDDwlTWbYh2TtyhWd1OlcvA"),
        ),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("n8ioVOfJVs4Dyg8y7Txu1rWntQ"),
        title="Подмена криптоадреса в буфере",
        severity=Severity.HIGH,
        description=(
            "Код читает буфер обмена и ищет криптоадрес — признак клиппера, "
            "подменяющего реквизиты платежа."
        ),
        patterns=(
            L("3YS8WfTGT90N4QMs2GJv1b2ls5SRQWItR3XYilv1whqU1eJr5pp6kjDmRgWjEC7kt7qhgoxEbz9GYsq1NvnDHoXZ6Vbn1A8"),
            L("3YS8VfaBfdtB71xzvRF3i-H54sKNTzYpeWyQj1m36UfYgttMoYBbxjekXwPfLSHSufirut17THxsXZCzKbeWKo6JsxumhFuT"),
        ),
        extensions=EXT,
        min_matches=2,
    ),
    Rule(
        sig_id=L("n8ioR_rHQ8gf_Qky6BNp17e6tZ6U"),
        title="Запуск PowerShell с encoded-командой",
        severity=Severity.CRITICAL,
        description="JS/HTA передаёт PowerShell закодированную команду — обход защиты и скрытая нагрузка.",
        patterns=(L("hdTxUufDTt8A-URhvhAi3Kyw-MSrbVojfmPgkii2nkXFxqsfqopDxgn7DyLhIm_WsLC1mJ9eazBMaZS1a7H0Ntjh5xrvgAuDR7pRA_9-PJWp"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("n8ioWubYUts"),
        title="Рекурсивный запуск mshta",
        severity=Severity.HIGH,
        description="mshta запускает удалённый HTA-файл — распространённый лоадер.",
        patterns=(L("mMjuQ_SYGYAwuwkm4WUz5af--cTKW3IlUn6C02TwzgGUyOVF_MBSgBDjDi3nPmXJoO_4"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("n8ioWPfWU8kP9Bg36yJT3Ke2sIuVQA"),
        title="Обфускация escape-последовательностями",
        severity=Severity.MEDIUM,
        description=(
            "Множество \\xNN/\\uNNNN подряд скрывает строки от анализа. "
            "Декодируйте и проверьте содержимое."
        ),
        patterns=(L("3YS8a8nIfYpBrA1z4hF3i6n8qsrCH3s"), L("3YS8a8nFfYpBrA1z4hF3jan8qsrCH3s")),
        extensions=EXT,
        max_findings=1,
    ),
    Rule(
        sig_id=L("n8ioUu3Ved4D4gIy6y1o"),
        title="Скачивание исполняемого файла",
        severity=Severity.HIGH,
        description="Скрипт загружает .exe/.dll/.ps1 — проверьте источник и цель.",
        patterns=(L("3YS8UfDERdIQzSESzDh4yYawoI6VQHItSnnJmWullVjakt1pycJ61DHuXHK2fDzEiPv5xMpWfjReadGFZOrcRonI5UXp0kfOEPYBOq0Qbg"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("n8ioQPzeQtUbyg8y6z9p5ry8tZ4"),
        title="Скрытие окна",
        severity=Severity.LOW,
        description="Скрипт скрывает окно или перекрывает интерфейс — приём маскировки.",
        patterns=(L("3YS8QPzeQtUbyUJ2u3Zv1bumtIedXHA0dmKUtWuw81-JyONb8-wI2ADgHgL3ZlCRqLG4iIBfZyh-fpfTROmFGZrV4x4"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("n8ioVOfJVs4DygE36iVi3g"),
        title="Скрытый майнинг",
        severity=Severity.MEDIUM,
        description="Подключение к пулу (stratum) или майнер CoinHive — скрытое использование ресурсов.",
        patterns=(L("3YS8ROHCR84Z-DB18C98xbe6uJWYWnA0Xm7SgHa3xx6D3vpU58lWzgP7BTnsOHDUvbu0iZ9vKDJBJA"),),
        extensions=EXT,
    ),
    Rule(
        sig_id=L("n8ioXvPCR9cJyh476SN43A"),
        title="Скрытый удалённый iframe",
        severity=Severity.MEDIUM,
        description="Невидимый iframe подгружает сторонний контент без ведома пользователя.",
        patterns=(L("lsnjVuHVY9YJ-Akw8BB_k4j9jYjaaCENAFDUj2r7whKunNoVyA"), L("3YS8U_zDVtYN7DAtrnZQyv67vpWVT3A4UWTfgHTz2w6pyKwNycMM0gXxCDvqMHvQsKG5p4MZOw1RJ-bORLjySMWS")),
        extensions=EXT,
        min_matches=2,
    ),
)

__all__ = ["SIGNATURES", "EXT"]
