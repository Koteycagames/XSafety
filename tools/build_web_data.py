"""Выгрузка сигнатур XSafety в статический сайт (GitHub Pages).

Единственный источник правды — Python-реестр ``xsafety.scan.signatures``.
Скрипт собирает его в браузерный формат:

* ``js/data/signatures/<ext>.js`` — по файлу на расширение (как в Python);
* ``js/data/signatures/index.js`` — общий реестр;
* ``js/data/catalog.js`` — модели, тарифы и цены из ``xsafety.config``.

Все строки уходят в браузер в LDR-виде (``L()``/``D()`` с тем же ключом),
поэтому паттерны не лежат в статике открытым текстом. Данные совпадают с
Python-реестром: расхождение ловит ``tests/test_web_data.py``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from xsafety.config import ALL_EXTENSIONS, MODELS, PLAN_ORDER, PLANS, PRICING, REFILL_PERIOD
from decimal import Decimal

from xsafety.pricing import discount_percent, format_percent
from xsafety.scan.ldr import encode_text
from xsafety.scan.signatures import RULES
from xsafety.scan.signatures import bat, dll, exe, hta, ps1, py, vbs

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "js" / "data"

TEXT_EXTENSIONS = {
    "bat", "cmd", "py", "pyw", "js", "mjs", "cjs", "ps1", "psm1", "vbs", "vbe",
    "hta", "txt", "md", "xml", "ini", "cfg", "json", "yaml", "yml",
}
PE_EXTENSIONS = {"exe", "dll"}
INLINE_FLAGS = re.compile(r"^\(\?([aiLmsux]+)\)")


def js_flags(pattern: str) -> tuple[str, str]:
    """Переносит Python-флаги ``(?i)``/``(?m)`` в JS-флаги."""
    flags = set()
    text = pattern
    while True:
        match = INLINE_FLAGS.match(text)
        if not match:
            break
        flags.update(c for c in match.group(1) if c in "ims")
        text = text[match.end():]
    return text, "".join(sorted(flags))


def pack(data) -> str:
    """Кодирует произвольный JSON в LDR-токен."""
    def default(value):
        if isinstance(value, Decimal):
            return float(value)
        raise TypeError(f"не сериализуется: {type(value).__name__}")

    return encode_text(json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=default))


def module_of(sig_id: str) -> str:
    return sig_id.split(".", 1)[0]


def pattern_rule(rule) -> dict:
    payload: dict = {
        "i": rule.sig_id,
        "t": rule.title,
        "s": rule.severity.value,
        "d": rule.description,
        "p": [],
        "m": rule.min_matches,
        "x": rule.max_findings,
        "k": rule.kind,
    }
    if rule.extensions is not None:
        payload["e"] = sorted(rule.extensions)
    for pattern in rule.patterns:
        body, flags = js_flags(pattern)
        if flags:
            payload["p"].append(body)
            payload.setdefault("f", {})[body] = flags
        else:
            payload["p"].append(body)
    return payload


def _tokens(func, start: int = 0) -> list[str]:
    """Достаёт декодированные L()-литералы по порядку из функции проверки."""
    import ast
    import inspect
    import textwrap

    from xsafety.scan.ldr import L

    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    values: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "L":
            for argument in node.args:
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    value = L(argument.value)
                    if value not in values:
                        values.append(value)
    return values[start:]


def _finding(rule, **extra) -> dict:
    payload = {
        "i": rule.sig_id,
        "t": rule.title,
        "s": rule.severity.value,
        "d": rule.description,
    }
    payload.update(extra)
    return payload


def check_spec(rule) -> dict | None:
    """Описание проверки правила, реализованное в браузерном движке."""
    sid = rule.sig_id
    tokens = _tokens(rule.check)

    if sid == "common.eicar":
        return {"kind": "eicar", "needle": tokens[0], "text_ext": ["psm1"], "exts": sorted(TEXT_EXTENSIONS)}

    if sid == "bat.encoded_payload":
        return {
            "kind": "b64_exec",
            "regex": bat._B64_CHUNK.pattern,
            "needles": tokens[1:],
            "max": 2,
        }

    if sid == "bat.mass_delete":
        return {"kind": "regex_hit", "regexes": [tokens[0], tokens[1]], "evidence": True}

    if sid == "py.reverse_shell":
        return {"kind": "text_require", "all": tokens[0:2], "any": tokens[3:-1] or tokens[3:], "evidence": None}

    if sid == "py.exfil_env":
        return {"kind": "text_require", "all": [], "any_of": tokens[0:2], "any": tokens[3:]}

    if sid == "py.obfuscation":
        return {
            "kind": "multi",
            "items": [
                {"m": {"regex": py._LONG_B64.pattern}, **_finding(rule, i="py.long_base64", t="Длинный base64-блок", s="medium", e="b64")},
                {"m": {"regex": py._HEX_ESCAPE.pattern}, **_finding(rule, i="py.hex_obfuscation", t="Обфускация hex-последовательностями", s="medium")},
            ],
        }

    if sid == "ps.reverse_shell":
        return {"kind": "text_require", "all": tokens[0:2], "any": tokens[3:-1] or tokens[3:]}

    if sid == "ps.obfuscation":
        return {
            "kind": "multi",
            "items": [
                {"m": {"regex": ps1._CHAR_OBFUSCATION.pattern}, **_finding(rule, i="ps.char_obfuscation", t="Сборка строк из кодов символов", s="medium", e="match")},
                {"m": {"regex": ps1._BACKTICK.pattern, "min_hits": 15}, **_finding(rule, i="ps.backtick_obfuscation", t="Обфускация обратными кавычками", s="low", e="static")},
            ],
        }

    if sid == "vbs.chr_obfuscation":
        return {"kind": "regex_hit", "regexes": [vbs._CHR_CHAIN.pattern], "evidence": True}

    if sid == "vbs.mass_file_write":
        return {
            "kind": "text_require",
            "all": [tokens[0]],
            "regex_all": [vbs._FSO_LOOP.pattern],
            "any": tokens[2:5],
        }

    if sid == "hta.dropper":
        return {"kind": "text_require", "all": tokens[0:2], "any": tokens[3:]}

    if sid == "dll.rwx_section":
        return {"kind": "pe_rwx", "evidence": "sections"}

    if sid == "dll.injection_api":
        return {"kind": "pe_imports", "imports": tokens[0:5], "min": 2, "severity_at": {"3": "critical"}}

    if sid == "dll.keylogger_api":
        return {"kind": "pe_imports", "imports": tokens[0:4], "min": 1}

    if sid == "dll.network_api":
        return {"kind": "pe_imports", "imports": tokens[0:6], "min": 1}

    if sid == "dll.dynamic_resolve":
        return {"kind": "pe_imports", "imports": tokens[0:4], "min": 2}

    if sid == "dll.high_entropy":
        return {"kind": "pe_entropy", "min_raw": 4096, "max_raw": 8 * 1024 * 1024, "threshold": 7.4, "evidence": "entropy"}

    if sid == "dll.packer":
        return {"kind": "pe_packer", "names": sorted({name.lower() for name in dll.UPX_NAMES})}

    if sid == "dll.ransomware_strings":
        return {
            "kind": "pe_strings",
            "groups": [
                {"tokens": tokens[2:7], "min": 2, **_finding(rule, i="dll.ransomware_strings", t="Строки шифровальщика", s="critical")},
                {"tokens": tokens[8:14], "min": 1, **_finding(rule, i="dll.loader_strings", t="Строки запуска команд", s="high")},
                {"tokens": ["http://", "https://"], "min": 1, **_finding(rule, i="dll.embedded_urls", t="URL внутри DLL", s="medium")},
            ],
        }

    if sid == "dll.unsigned":
        return {"kind": "pe_unsigned"}

    if sid == "dll.tls_callbacks":
        return {"kind": "pe_tls"}

    if sid == "dll.dotnet":
        return {"kind": "pe_dotnet"}

    if sid == "exe.rwx_section":
        return {"kind": "pe_rwx", "evidence": "sections"}

    if sid == "exe.injection_api":
        return {"kind": "pe_imports", "imports": tokens[0:5], "min": 2}

    if sid == "exe.remote_thread":
        return {"kind": "pe_imports", "imports": tokens[0:3], "min": 1}

    if sid == "exe.packer":
        return {"kind": "pe_packer", "names": sorted({name.lower() for name in exe.PACKERS})}

    if sid == "exe.high_entropy":
        return {"kind": "pe_entropy", "min_raw": 8192, "max_raw": 16 * 1024 * 1024, "threshold": 7.5, "evidence": "section"}

    if sid == "exe.unsigned":
        return {"kind": "pe_unsigned"}

    if sid == "exe.tls_callback":
        return {"kind": "pe_tls"}

    if sid == "exe.entry_unusual":
        return {
            "kind": "pe_entry",
            "code_names": [".text", "code", ".code", "text"],
            "outside": {"i": "exe.entry_outside", "t": "Точка входа вне секций", "s": "medium",
                        "d": "Адрес входа не принадлежит ни одной секции — повреждённый или упакованный файл."},
        }

    if sid == "exe.strings":
        return {
            "kind": "pe_strings",
            "groups": [
                {"tokens": list(tokens_list), "min": 1, **_finding(rule, i=f"exe.strings_{category}", t=title, s=severity)}
                for category, (tokens_list, title, severity) in {
                    "ransomware": (exe.SUSPICIOUS_STRINGS["ransomware"], "Строки шифровальщика", "critical"),
                    "credentials": (exe.SUSPICIOUS_STRINGS["credentials"], "Инструменты кражи учётных данных", "critical"),
                    "loader": (exe.SUSPICIOUS_STRINGS["loader"], "Строки загрузчика", "high"),
                    "miner": (exe.SUSPICIOUS_STRINGS["miner"], "Строки майнера", "medium"),
                }.items()
            ],
        }

    if sid == "exe.network_activity":
        return {
            "kind": "pe_network_urls",
            "imports": tokens[0:4],
            "urls": tokens[4:6],
        }

    if sid == "exe.overlay":
        return {"kind": "pe_overlay", "min_bytes": 8192}

    if sid == "exe.dotnet":
        return {"kind": "pe_dotnet"}

    return None


def build() -> dict[str, list[dict]]:
    by_ext: dict[str, list[dict]] = {ext: [] for ext in ALL_EXTENSIONS}
    for rule in RULES:
        payload = pattern_rule(rule) if rule.patterns else {
            "i": rule.sig_id,
            "t": rule.title,
            "s": rule.severity.value,
            "d": rule.description,
            "p": [],
            "m": rule.min_matches,
            "x": rule.max_findings,
            "k": rule.kind,
        }
        if rule.extensions is not None:
            payload["e"] = sorted(rule.extensions)
        if rule.check is not None:
            spec = check_spec(rule)
            if spec is None:
                raise SystemExit(f"нет браузерной спецификации для {rule.sig_id}")
            payload["w"] = spec
        exts = rule.extensions or set(ALL_EXTENSIONS)
        for ext in sorted(exts):
            by_ext.setdefault(ext, []).append(payload)
    return by_ext


def catalog() -> dict:
    plans = []
    for plan_id in PLAN_ORDER:
        plan = PLANS[plan_id]
        offers = []
        for offer in PRICING.get(plan_id, ()):
            percent = discount_percent(offer.old_price, offer.price)
            offers.append(
                {
                    "id": offer.id,
                    "label": offer.label,
                    "price": offer.price,
                    "old_price": offer.old_price,
                    "discount": round(percent, 1),
                    "discount_label": format_percent(percent),
                    "saving": offer.old_price - offer.price,
                }
            )
        limits = {
            model_id: {"requests": allowance.requests, "mb": allowance.mb}
            for model_id, allowance in plan.allowances.items()
        }
        plans.append(
            {
                "id": plan.id,
                "name": plan.name,
                "tagline": plan.tagline,
                "features": list(plan.features),
                "limits": limits,
                "offers": offers,
            }
        )
    models = [
        {
            "id": model.id,
            "name": model.name,
            "tagline": model.tagline,
            "extensions": list(model.extensions),
            "signatures": len([rule for rule in RULES if set(rule.extensions or ALL_EXTENSIONS) & set(model.extensions)]),
        }
        for model in MODELS
    ]
    return {
        "plans": plans,
        "models": models,
        "extensions": sorted(ALL_EXTENSIONS),
        "currency": "грн",
        "refill_hours": int(REFILL_PERIOD.total_seconds() // 3600),
        "default_plan": "default",
    }


def main() -> None:
    by_ext = build()
    target = OUT / "signatures"
    target.mkdir(parents=True, exist_ok=True)

    counts = {}
    for path in target.glob("*.js"):
        if path.name != "index.js":
            path.unlink()

    for ext, rules in sorted(by_ext.items()):
        if not rules:
            continue
        (target / f"{ext}.js").write_text(
            '/* Автогенерация: python3 tools/build_web_data.py — не редактировать вручную. */\n'
            'import { D } from "../../core/ldr.js";\n\n'
            f'export default D("{pack(rules)}");\n',
            encoding="utf-8",
        )
        counts[ext] = len({rule["i"] for rule in rules})

    order = sorted(ext for ext in by_ext if by_ext[ext])
    imports = "\n".join(f'import {ext} from "./{ext}.js";' for ext in order)
    counts_json = json.dumps(counts, ensure_ascii=False, sort_keys=True)
    (target / "index.js").write_text(
        "/* Автогенерация: python3 tools/build_web_data.py — не редактировать вручную. */\n"
        f"{imports}\n\n"
        f"const GROUPS = [{', '.join(order)}];\n\n"
        "// Правило может относиться к нескольким расширениям — оставляем по одному экземпляру.\n"
        "const registry = new Map();\n"
        "for (const group of GROUPS) {\n"
        "  for (const rule of group) if (!registry.has(rule.i)) registry.set(rule.i, rule);\n"
        "}\n\n"
        "export const SIGNATURES = [...registry.values()];\n"
        f"export const RULE_COUNT = {len(RULES)};\n"
        f"export const COUNTS = {counts_json};\n",
        encoding="utf-8",
    )

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "catalog.js").write_text(
        "/* Автогенерация: python3 tools/build_web_data.py — не редактировать вручную. */\n"
        'import { D } from "../core/ldr.js";\n\n'
        f'export default D("{pack(catalog())}");\n',
        encoding="utf-8",
    )

    print(f"расширений: {len([ext for ext in by_ext if by_ext[ext]])}, правил: {len(RULES)}")
    print("по расширениям:", ", ".join(f"{ext}={counts[ext]}" for ext in sorted(counts)))


if __name__ == "__main__":
    main()
