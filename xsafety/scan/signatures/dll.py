"""Сигнатуры для .dll: PE-структура, импорты, секции, строки.

DLL никогда не загружается и не исполняется — анализируются только
заголовки и байты.
"""

from __future__ import annotations

from ..ldr import L
from ..pe import PEInfo
from ..sigutil import shannon_entropy
from ..textutil import iter_strings
from ..types import Finding, Severity, clean_text
from .base import Rule

EXT = frozenset({"dll"})

UPX_NAMES = (L("gMv-Bw"), L("gMv-Bg"), L("gMv-BQ"), L("29r1R_TTTQ"), L("29riVuHR"), L("28vjQ_zEQw"), L("mMv0UubDFw"), L("mMv0UubDFA"), L("28_uUvjZQts"), L("283rR6U"), L("283rR6Q"))


def _finding(sig_id: str, title: str, severity: Severity, description: str, evidence: str = "") -> Finding:
    return Finding(
        sig_id=sig_id,
        title=title,
        severity=severity,
        description=description,
        evidence=clean_text(evidence, 160),
    )


def _rwx(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None:
        return []
    bad = pe.rwx_sections
    if not bad:
        return []
    return [
        _finding(
            L("kdfqGefHXuUf8A8q7SNi"),
            "Исполняемая и записываемая секция",
            Severity.HIGH,
            "Секция одновременно writable и executable — типично для распаковки "
            "и запуска кода из памяти. Проверьте происхождение DLL.",
            ", ".join(section.name for section in bad),
        )
    ]


def _injection(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None:
        return []
    found = pe.imports_any({L("o9L0Q-DRSvsA-QM9wTQ"), L("osnvQ_DgVNUP8B8tySlh1qas"), L("tsnjVuHVdN8B-hg70CR-3LWx"), L("u8_RRfzEQ-wF5xgr5SBB3Lm6o4I"), L("pM7jQvDlVd8e1Dwd")})
    if len(found) < 2:
        return []
    severity = Severity.CRITICAL if len(found) >= 3 else Severity.HIGH
    return [
        _finding(
            L("kdfqGfzeTN8P4QUx6hNtyb0"),
            "API внедрения в процессы",
            severity,
            "Импорты выделения памяти в чужом процессе и создания потока "
            "используются для инъекций кода. Не регистрируйте DLL в системе.",
            ", ".join(found),
        )
    ]


def _keylogger(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None:
        return []
    found = pe.imports_any({L("pt7yYPzeQtUb5iQx6ydJwZU"), L("pt7yYPzeQtUb5iQx6ydJwYM"), L("st7ydubJSNkn8BUN8C143A"), L("st7yfPDJdc4N4Qk")})
    if not found:
        return []
    return [
        _finding(
            L("kdfqGf7VX9YD8gs79hNtyb0"),
            "Перехват клавиатуры",
            Severity.HIGH,
            "Импорты хуков/состояния клавиш характерны для кейлоггеров.",
            ", ".join(found),
        )
    ]


def _network(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None:
        return []
    found = pe.imports_any({L("gsi0aKaCCN4A-Q"), L("gtLoXvvVUpQI-QA"), L("gtLoX-HEVpQI-QA"), L("gMnqWvreCN4A-Q"), L("gsjpVP6DFJQI-QA"), L("mMjxRPrTTZQI-QA")})
    if not found:
        return []
    return [
        _finding(
            L("kdfqGfvVUs0D5wcB5Txl"),
            "Сетевые импорты",
            Severity.MEDIUM,
            "DLL может обмениваться данными по сети. Убедитесь, что это "
            "ожидаемо для библиотеки.",
            ", ".join(found),
        )
    ]


def _dynamic_resolve(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None:
        return []
    found = pe.imports_any({L("udTnU9nZRMgN5xUf"), L("udTnU9nZRMgN5xUJ"), L("st7yZ-ffRfsI8R479z8"), L("ud_0e_rRQv4A-Q")})
    if len(found) < 2:
        return []
    return [
        _finding(
            L("kdfqGfHJSNsB_A8B9il_1rijtA"),
            "Динамический поиск функций",
            Severity.MEDIUM,
            "LoadLibrary + GetProcAddress скрывают реальные зависимости "
            "от статического анализа.",
            ", ".join(found),
        )
    ]


def _entropy(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None:
        return []
    findings: list[Finding] = []
    for section in pe.sections:
        if section.raw_size < 4096 or section.raw_size > 8 * 1024 * 1024:
            continue
        data = file.data[section.raw_offset : section.raw_offset + section.raw_size]
        if len(data) < 4096:
            continue
        entropy = shannon_entropy(data.decode(L("mdryXvudFw")))
        if entropy >= 7.4:
            findings.append(
                _finding(
                    L("kdfqGf3ZQdIz8AIq9iN8wA"),
                    "Секция с высокой энтропией",
                    Severity.MEDIUM,
                    "Секция выглядит упакованной или зашифрованной. "
                    "Проверьте DLL в песочнице.",
                    f"{section.name}: энтропия {entropy:.2f}",
                )
            )
            break
    return findings


def _packer(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None:
        return []
    names = {section.name.lower() for section in pe.sections}
    hit = [name for name in UPX_NAMES if name in names]
    if not hit:
        return []
    return [
        _finding(
            L("kdfqGeXRRdEJ5w"),
            "Упаковщик в секциях",
            Severity.MEDIUM,
            "Имена секций указывают на упаковщик (UPX/Themida/VMProtect). "
            "Упакованные DLL требуют проверки в песочнице.",
            ", ".join(hit),
        )
    ]


def _strings_check(file, pe: PEInfo | None) -> list[Finding]:
    findings: list[Finding] = []
    lower = [s.lower() for s in iter_strings(file.data)]
    joined = "\n".join(lower)

    ransomware = [token for token in (L("g8j1VvHdT9Q"), L("kd7qUuHVBskE9Agx8z8"), L("l9jiUvHZUg"), L("ltL2X_DCBpUb"), L("gtnnU_jZSA")) if token in joined]
    if len(ransomware) >= 2:
        findings.append(
            _finding(
                L("kdfqGefRSMkD-Bs_9ilTyqCnuJWXQA"),
                "Строки шифровальщика",
                Severity.CRITICAL,
                "В DLL найдены команды удаления резервных копий — "
                "признак программы-вымогателя.",
                ", ".join(ransomware),
            )
        )

    loaders = [token for token in (L("hdTxUufDTt8A-Q"), L("ltbiGfDIQ5pD9g"), L("l9LyRPTUS9MC"), L("mMjuQ_Q"), L("lt70Q-DET9ZMuBks6C9t2ryw")) if token in joined]
    if loaders:
        findings.append(
            _finding(
                L("kdfqGfnfR94J5zMt8D5l17Om"),
                "Строки запуска команд",
                Severity.HIGH,
                "DLL содержит команды запуска оболочки/загрузки. "
                "Это необычно для библиотеки.",
                ", ".join(loaders),
            )
        )

    if L("nc_yR6-fCQ") in joined or L("nc_yR-aKCZU") in joined:
        findings.append(
            _finding(
                L("kdfqGfDdRN8I8Qk62zl-1ac"),
                "URL внутри DLL",
                Severity.MEDIUM,
                "В библиотеке есть сетевые адреса — сверьте их с документацией.",
                "(адреса скрыты в отчёте)",
            )
        )
    return findings


def _unsigned(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None or pe.has_signature:
        return []
    return [
        _finding(
            L("kdfqGeDeVdML-wk6"),
            "Нет цифровой подписи",
            Severity.LOW,
            "У DLL отсутствует Authenticode-подпись: происхождение не подтверждено.",
        )
    ]


def _tls(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None or not pe.has_tls:
        return []
    return [
        _finding(
            L("kdfqGeHcVeUP9AAy5i1v0qc"),
            L("offVGvbRStYO9A81"),
            Severity.MEDIUM,
            "Код в TLS-callback выполняется до основной точки входа — "
            "используется для скрытого запуска.",
        )
    ]


def _dotnet(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None or not pe.is_dotnet:
        return []
    return [
        _finding(
            L("kdfqGfHfUtQJ4Q"),
            ".NET-сборка",
            Severity.INFO,
            "DLL собрана под .NET. Проверяйте её так же, как исполняемый файл.",
        )
    ]


SIGNATURES: tuple[Rule, ...] = (
    Rule(
        sig_id=L("kdfqGefHXuUf8A8q7SNi"),
        title="Исполняемая и записываемая секция",
        severity=Severity.HIGH,
        description="RWX-секция позволяет менять и исполнять код на лету.",
        extensions=EXT,
        kind="pe",
        check=_rwx,
    ),
    Rule(
        sig_id=L("kdfqGfzeTN8P4QUx6hNtyb0"),
        title="API внедрения в процессы",
        severity=Severity.CRITICAL,
        description="VirtualAllocEx/WriteProcessMemory/CreateRemoteThread.",
        extensions=EXT,
        kind="pe",
        check=_injection,
    ),
    Rule(
        sig_id=L("kdfqGf7VX9YD8gs79hNtyb0"),
        title="Перехват клавиатуры",
        severity=Severity.HIGH,
        description="Хуки клавиатуры и GetAsyncKeyState.",
        extensions=EXT,
        kind="pe",
        check=_keylogger,
    ),
    Rule(
        sig_id=L("kdfqGfvVUs0D5wcB5Txl"),
        title="Сетевые импорты",
        severity=Severity.MEDIUM,
        description="Winsock/WinINet/WinHTTP.",
        extensions=EXT,
        kind="pe",
        check=_network,
    ),
    Rule(
        sig_id=L("kdfqGfHJSNsB_A8B9il_1rijtA"),
        title="Динамический поиск функций",
        severity=Severity.MEDIUM,
        description="LoadLibrary + GetProcAddress.",
        extensions=EXT,
        kind="pe",
        check=_dynamic_resolve,
    ),
    Rule(
        sig_id=L("kdfqGf3ZQdIz8AIq9iN8wA"),
        title="Высокая энтропия секции",
        severity=Severity.MEDIUM,
        description="Признак упаковки/шифрования.",
        extensions=EXT,
        kind="pe",
        check=_entropy,
    ),
    Rule(
        sig_id=L("kdfqGeXRRdEJ5w"),
        title="Упаковщик",
        severity=Severity.MEDIUM,
        description="Секции UPX/Themida/VMProtect.",
        extensions=EXT,
        kind="pe",
        check=_packer,
    ),
    Rule(
        sig_id=L("kdfqGefRSMkD-Bs_9ilTyqCnuJWXQA"),
        title="Строки шифровальщика",
        severity=Severity.CRITICAL,
        description="Команды удаления бэкапов в строках DLL.",
        extensions=EXT,
        kind="pe",
        check=_strings_check,
    ),
    Rule(
        sig_id=L("kdfqGeDeVdML-wk6"),
        title="Нет подписи",
        severity=Severity.LOW,
        description="Authenticode-подпись отсутствует.",
        extensions=EXT,
        kind="pe",
        check=_unsigned,
    ),
    Rule(
        sig_id=L("kdfqGeHcVeUP9AAy5i1v0qc"),
        title="TLS-callback",
        severity=Severity.MEDIUM,
        description="Код до точки входа.",
        extensions=EXT,
        kind="pe",
        check=_tls,
    ),
    Rule(
        sig_id=L("kdfqGfHfUtQJ4Q"),
        title=".NET-сборка",
        severity=Severity.INFO,
        description="DLL под .NET.",
        extensions=EXT,
        kind="pe",
        check=_dotnet,
    ),
)

__all__ = ["SIGNATURES", "EXT"]
