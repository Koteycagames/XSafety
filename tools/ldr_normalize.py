#!/usr/bin/env python3
"""Склеивает вложенные LDR-обёртки в один уровень.

После нескольких прогонов кодирования в исходниках могли появиться
``L(L("..."))`` и ``B(L("..."))``. Скрипт вычисляет итоговое значение и
переписывает вызов в эквивалентный одноуровневый ``L("...")``/``B("...")``.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from xsafety.scan.ldr import B, L, encode_bytes, encode_text  # noqa: E402

SIGNATURE_DIR = ROOT / "xsafety" / "scan" / "signatures"
EXTRA_FILES = [ROOT / "xsafety" / "scan" / "sigutil.py"]


class Unsupported(Exception):
    pass


def value_of(node: ast.AST):
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return node.value
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"L", "B"}
        and len(node.args) == 1
        and not node.keywords
    ):
        argument = value_of(node.args[0])
        if not isinstance(argument, str):
            raise Unsupported
        return L(argument) if node.func.id == "L" else B(argument)
    raise Unsupported


def outermost_ldr_calls(tree: ast.AST) -> list[ast.Call]:
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    result: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Name) and node.func.id in {"L", "B"}):
            continue
        parent = parents.get(node)
        if (
            isinstance(parent, ast.Call)
            and isinstance(parent.func, ast.Name)
            and parent.func.id in {"L", "B"}
            and any(arg is node for arg in parent.args)
        ):
            continue
        result.append(node)
    return result


def transform(path: Path) -> int:
    source = path.read_bytes()
    if b"ldr import" not in source:
        return 0
    tree = ast.parse(source, filename=str(path))
    calls = outermost_ldr_calls(tree)
    starts = [0]
    for index, byte in enumerate(source):
        if byte == 0x0A:
            starts.append(index + 1)

    replacements: list[tuple[int, int, bytes]] = []
    for call in calls:
        try:
            value = value_of(call)
        except Unsupported:
            continue
        start = starts[call.lineno - 1] + call.col_offset
        end = starts[(call.end_lineno or call.lineno) - 1] + (call.end_col_offset or call.col_offset)
        if isinstance(value, bytes):
            replacement = f'B("{encode_bytes(value)}")'.encode("ascii")
        else:
            replacement = f'L("{encode_text(value)}")'.encode("ascii")
        replacements.append((start, end, replacement))

    if not replacements:
        return 0
    data = bytearray(source)
    for start, end, replacement in sorted(replacements, reverse=True):
        data[start:end] = replacement
    path.write_bytes(bytes(data))
    return len(replacements)


def main() -> int:
    total = 0
    for path in sorted(SIGNATURE_DIR.glob("*.py")) + EXTRA_FILES:
        count = transform(path)
        if count:
            total += count
            print(f"{path.relative_to(ROOT)}: нормализовано {count}")
    print(f"Итого: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
