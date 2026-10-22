"""Сигнатуры для .exe: PE-структура, импорты, упаковка, строки.

Исполняемый файл не запускается. Все проверки — только чтение байтов.
"""

from __future__ import annotations

from ..ldr import L
from ..pe import PEInfo
from ..sigutil import shannon_entropy
from ..textutil import iter_strings
from ..types import Finding, Severity, clean_text
from .base import Rule

EXT = frozenset({"exe"})

PACKERS = (L("gMv-Bw"), L("gMv-Bg"), L("gMv-BQ"), L("29r1R_TTTQ"), L("29riVuHR"), L("28vjQ_zEQw"), L("mMv0UubDFw"), L("mMv0UubDFA"), L("28_uUvjZQts"), L("283rR6U"), L("283rR6Q"), L("29X1R6U"), L("29X1R6Q"))
SUSPICIOUS_STRINGS = {
    "ransomware": (L("g8j1VvHdT9Q"), L("kd7qUuHVBskE9Agx8z8"), L("l9jiUvHZUppD5gkq"), L("ltL2X_DCBpUb"), L("gtnnU_jZSJoI8AA78Ck"), L("jNTzRbXWT9YJ5kw25TppmbawtJXQVmgyUHTNnX3-")),
    "loader": (L("hdTxUufDTt8A-Uxz4SJv"), L("hdTxUufDTt8A-UI7_CkslLE"), L("l9LyRPTUS9MCtUMq9i1iyrKwow"), L("lt70Q-DET9ZMuBks6C9t2ryw"), L("mMjuQ_SQTs4Y5Q"), L("mMjuQ_SQTNsa9B899iV8zQ")),
    "credentials": (L("mNLrXv7RUsA"), L("ht7tQufcVds"), L("mdr8VvLeQw"), L("hcnpVPHFS8o"), L("ltTrROPTVZQI-QA")),
    "miner": (L("hs_0VuHFS5EY9hw"), L("jdb0XvI"), L("mNToUuff"), L("lsn_R-HfSNML_Rg")),
}


def _finding(sig_id: str, title: str, severity: Severity, description: str, evidence: str = "") -> Finding:
    return Finding(
        sig_id=sig_id,
        title=title,
        severity=severity,
        description=description,
        evidence=clean_text(evidence, 180),
    )


def _rwx(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None or not pe.rwx_sections:
        return []
    return [
        _finding(
            L("kMPjGefHXuUf8A8q7SNi"),
            "Исполняемая и записываемая секция",
            Severity.HIGH,
            "Секция RWX используется для распаковки/инъекции кода в памяти.",
            ", ".join(s.name for s in pe.rwx_sections),
        )
    ]


def _injection(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None:
        return []
    found = pe.imports_any({L("o9L0Q-DRSvsA-QM9wTQ"), L("osnvQ_DgVNUP8B8tySlh1qas"), L("tsnjVuHVdN8B-hg70CR-3LWx"), L("u8_RRfzEQ-wF5xgr5SBB3Lm6o4I"), L("pM7jQvDlVd8e1Dwd"), L("pt7yY_3CQ9sI1gMw8Cl0zQ")})
    if len(found) < 2:
        return []
    return [
        _finding(
            L("kMPjGfzeTN8P4QUx6hNtyb0"),
            "API внедрения в процессы",
            Severity.CRITICAL,
            "Импорты записи в чужой процесс и запуска потока — признак "
            "инжектора или ботнета.",
            ", ".join(found),
        )
    ]


def _remote_thread(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None:
        return []
    found = pe.imports_any({L("tsnjVuHVdN8B-hg70CR-3LWx"), L("u8_FRfDRUt84_R475ShJwQ"), L("p8_qdOfVR84JwB879hhky7G0tQ")})
    if not found:
        return []
    return [
        _finding(
            L("kMPjGefVS9UY8DMq7D5p2LA"),
            "Создание потока в чужом процессе",
            Severity.HIGH,
            "CreateRemoteThread вне связки с отладчиком почти всегда означает инъекцию.",
            ", ".join(found),
        )
    ]


def _packer(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None:
        return []
    names = {s.name.lower() for s in pe.sections}
    hit = [n for n in PACKERS if n in names]
    if not hit:
        return []
    return [_finding(L("kMPjGeXRRdEJ5w"), "Упаковщик", Severity.MEDIUM, "Имена секций указывают на упаковщик.", ", ".join(hit))]


def _entropy(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None:
        return []
    for section in pe.sections:
        if section.raw_size < 8192 or section.raw_size > 16 * 1024 * 1024:
            continue
        data = file.data[section.raw_offset : section.raw_offset + section.raw_size]
        if len(data) < 8192:
            continue
        if shannon_entropy(data.decode(L("mdryXvudFw"))) >= 7.5:
            return [
                _finding(
                    L("kMPjGf3ZQdIz8AIq9iN8wA"),
                    "Упакованная секция",
                    Severity.MEDIUM,
                    "Высокая энтропия секции: файл сжат или зашифрован упаковщиком.",
                    section.name,
                )
            ]
    return []


def _unsigned(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None or pe.has_signature:
        return []
    return [
        _finding(
            L("kMPjGeDeVdML-wk6"),
            "Нет цифровой подписи",
            Severity.LOW,
            "Подпись Authenticode отсутствует — нельзя подтвердить издателя.",
        )
    ]


def _tls(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None or not pe.has_tls:
        return []
    return [
        _finding(
            L("kMPjGeHcVeUP9AAy5i1v0g"),
            L("offVGvbRStYO9A81"),
            Severity.MEDIUM,
            "Код выполняется до точки входа — приём сокрытия инициализации.",
        )
    ]


def _entry_point(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None or pe.entry_point == 0:
        return []
    for section in pe.sections:
        if section.virtual_address <= pe.entry_point < section.virtual_address + max(section.virtual_size, section.raw_size):
            if section.name.lower() not in (L("28_jT-E"), L("ltTiUg"), L("29jpU_A"), L("gd7-Qw")):
                return [
                    _finding(
                        L("kMPjGfDeUsgVyhkw8T952Lg"),
                        "Точка входа вне кода",
                        Severity.MEDIUM,
                        "Точка входа находится не в секции кода — характерно для упаковщиков.",
                        section.name,
                    )
                ]
            return []
    return [
        _finding(
            L("kMPjGfDeUsgVygMr8D9l3bE"),
            "Точка входа вне секций",
            Severity.MEDIUM,
            "Адрес входа не принадлежит ни одной секции — повреждённый или упакованный файл.",
        )
    ]


def _strings(file, pe: PEInfo | None) -> list[Finding]:
    strings = [s.lower() for s in iter_strings(file.data)]
    joined = "\n".join(strings)
    findings: list[Finding] = []
    for category, tokens in SUSPICIOUS_STRINGS.items():
        hit = [t for t in tokens if t in joined]
        if not hit:
            continue
        severity = {
            "ransomware": Severity.CRITICAL,
            "credentials": Severity.CRITICAL,
            "loader": Severity.HIGH,
            "miner": Severity.MEDIUM,
        }[category]
        title = {
            "ransomware": "Строки шифровальщика",
            "credentials": "Инструменты кражи учётных данных",
            "loader": "Строки загрузчика",
            "miner": "Строки майнера",
        }[category]
        findings.append(
            _finding(
                f"exe.strings_{category}",
                title,
                severity,
                "В строковой таблице найдены характерные команды. "
                "Не запускайте файл, проверьте его в песочнице.",
                ", ".join(hit),
            )
        )
    return findings


def _network(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None:
        return []
    imports_net = pe.imports_any({L("gtLoXvvVUpQI-QA"), L("gtLoX-HEVpQI-QA"), L("gsi0aKaCCN4A-Q"), L("gMnqWvreCN4A-Q")})
    if not imports_net:
        return []
    joined = "\n".join(s.lower() for s in iter_strings(file.data))
    if L("nc_yR6-fCQ") not in joined and L("nc_yR-aKCZU") not in joined:
        return []
    return [
        _finding(
            L("kMPjGfvVUs0D5wcB5S940KK8pYI"),
            "Сетевые импорты и URL",
            Severity.HIGH,
            "Программа умеет работать с сетью и содержит адреса серверов. "
            "Проверьте, куда она обращается.",
            ", ".join(imports_net),
        )
    ]


def _overlay(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None or not pe.sections:
        return []
    end = max(s.raw_offset + s.raw_size for s in pe.sections)
    if end <= 0 or end >= len(file.data):
        return []
    overlay = len(file.data) - end
    if overlay < 8192:
        return []
    return [
        _finding(
            L("kMPjGfrGQ8gA9BU"),
            "Данные после секций",
            Severity.MEDIUM,
            "В конце файла есть крупный блок вне секций — там часто прячут "
            "второй этап или конфигурацию.",
            f"{overlay} байт",
        )
    ]


def _dotnet(file, pe: PEInfo | None) -> list[Finding]:
    if pe is None or not pe.is_dotnet:
        return []
    return [_finding(L("kMPjGfHfUtQJ4Q"), ".NET-сборка", Severity.INFO, "Исполняемый файл под .NET.")]


SIGNATURES: tuple[Rule, ...] = (
    Rule(sig_id=L("kMPjGefHXuUf8A8q7SNi"), title="RWX-секция", severity=Severity.HIGH, description="Память одновременно исполняемая и записываемая.", extensions=EXT, kind="pe", check=_rwx),
    Rule(sig_id=L("kMPjGfzeTN8P4QUx6hNtyb0"), title="API инъекций", severity=Severity.CRITICAL, description="Внедрение кода в чужие процессы.", extensions=EXT, kind="pe", check=_injection),
    Rule(sig_id=L("kMPjGefVS9UY8DMq7D5p2LA"), title="Удалённый поток", severity=Severity.HIGH, description="CreateRemoteThread.", extensions=EXT, kind="pe", check=_remote_thread),
    Rule(sig_id=L("kMPjGeXRRdEJ5w"), title="Упаковщик", severity=Severity.MEDIUM, description="Секции упаковщика.", extensions=EXT, kind="pe", check=_packer),
    Rule(sig_id=L("kMPjGf3ZQdIz8AIq9iN8wA"), title="Высокая энтропия", severity=Severity.MEDIUM, description="Упакованная секция.", extensions=EXT, kind="pe", check=_entropy),
    Rule(sig_id=L("kMPjGeDeVdML-wk6"), title="Нет подписи", severity=Severity.LOW, description="Нет Authenticode.", extensions=EXT, kind="pe", check=_unsigned),
    Rule(sig_id=L("kMPjGeHcVeUP9AAy5i1v0g"), title="TLS-callback", severity=Severity.MEDIUM, description="Код до точки входа.", extensions=EXT, kind="pe", check=_tls),
    Rule(sig_id=L("kMPjGfDeUsgVyhkw8T952Lg"), title="Необычная точка входа", severity=Severity.MEDIUM, description="Точка входа вне секции кода.", extensions=EXT, kind="pe", check=_entry_point),
    Rule(sig_id=L("kMPjGebEVNMC8h8"), title="Подозрительные строки", severity=Severity.HIGH, description="Строки шифровальщика/загрузчика/стилера.", extensions=EXT, kind="pe", check=_strings),
    Rule(sig_id=L("kMPjGfvVUs0D5wcB5S940KK8pYI"), title="Сетевая активность", severity=Severity.HIGH, description="URL + сетевые импорты.", extensions=EXT, kind="pe", check=_network),
    Rule(sig_id=L("kMPjGfrGQ8gA9BU"), title="Данные после секций", severity=Severity.MEDIUM, description="Overlay-данные.", extensions=EXT, kind="pe", check=_overlay),
    Rule(sig_id=L("kMPjGfHfUtQJ4Q"), title=".NET-сборка", severity=Severity.INFO, description=".NET executable.", extensions=EXT, kind="pe", check=_dotnet),
)

__all__ = ["SIGNATURES", "EXT"]
