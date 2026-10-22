#!/usr/bin/env python3
"""Кодирует LDR-маркеры в модулях сигнатур.

Правила:
* кодируются строковые и байтовые литералы (ASCII, длина ≥ 4) в модулях
  сигнатур и в ``sigutil.py``;
* остаются читаемыми: docstring'и, заголовки и описания правил, русские
  тексты, ключи словарей и ``__all__``;
* замена функционально прозрачна: ``L("...")``/``B("...")`` декодируются
  при импорте, поэтому сравнения и регулярки работают как раньше.

Запуск: ``python3 tools/ldr_encode.py`` (повторный запуск безопасен).
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from xsafety.scan.ldr import encode_bytes, encode_text  # noqa: E402

SIGNATURE_DIR = ROOT / "xsafety" / "scan" / "signatures"
EXTRA_FILES = [ROOT / "xsafety" / "scan" / "sigutil.py"]
MIN_LENGTH = 4


def _is_ascii(value: str) -> bool:
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return True


def _docstring_positions(tree: ast.AST) -> set[int]:
    positions: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                positions.add(id(body[0].value))
    return positions


def _inside_all(parents: dict[ast.AST, ast.AST], node: ast.AST) -> bool:
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, ast.Assign):
            for target in current.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    return True
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            return False
    return False


def _inside_annotation(parents: dict[ast.AST, ast.AST], node: ast.AST) -> bool:
    """Только сама аннотация, а не значение аннотированного присваивания."""
    current = node
    while current in parents:
        parent = parents[current]
        if isinstance(parent, ast.AnnAssign) and parent.annotation is current:
            return True
        if isinstance(parent, ast.arg) and parent.annotation is current:
            return True
        current = parent
    return False


def _in_fstring(parents: dict[ast.AST, ast.AST], node: ast.AST) -> bool:
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.JoinedStr, ast.FormattedValue)):
            return True
    return False


def _is_dict_key(parents: dict[ast.AST, ast.AST], node: ast.AST) -> bool:
    parent = parents.get(node)
    return isinstance(parent, ast.Dict) and any(key is node for key in parent.keys)


def _is_rule_text(parents: dict[ast.AST, ast.AST], node: ast.AST) -> bool:
    parent = parents.get(node)
    return isinstance(parent, ast.keyword) and parent.arg in {"title", "description"}


def _inside_ldr(parents: dict[ast.AST, ast.AST], node: ast.AST) -> bool:
    """Не трогаем аргументы уже закодированных L(...)/B(...)."""
    current = node
    while current in parents:
        parent = parents[current]
        if (
            isinstance(parent, ast.Call)
            and isinstance(parent.func, ast.Name)
            and parent.func.id in {"L", "B"}
            and any(arg is current for arg in parent.args)
        ):
            return True
        current = parent
    return False


def collect_nodes(tree: ast.AST, source: bytes) -> list[ast.Constant]:
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    docstrings = _docstring_positions(tree)
    selected: list[ast.Constant] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant):
            continue
        if id(node) in docstrings:
            continue
        if _in_fstring(parents, node) or _is_dict_key(parents, node):
            continue
        if _inside_ldr(parents, node):
            continue
        if _inside_all(parents, node) or _inside_annotation(parents, node):
            continue
        if _is_rule_text(parents, node):
            continue
        value = node.value
        if isinstance(value, str):
            if len(value) < MIN_LENGTH or not _is_ascii(value):
                continue
        elif isinstance(value, bytes):
            if len(value) < MIN_LENGTH or any(byte > 0x7E or byte < 0x20 for byte in value):
                continue
        else:
            continue
        selected.append(node)
    return selected


def _line_starts(source: bytes) -> list[int]:
    starts = [0]
    for index, byte in enumerate(source):
        if byte == 0x0A:
            starts.append(index + 1)
    return starts


def _offset(starts: list[int], line: int, col: int) -> int:
    return starts[line - 1] + col


def transform(path: Path) -> tuple[int, int]:
    source = path.read_bytes()
    has_import = b"from ..ldr import" in source or b"from .ldr import" in source
    tree = ast.parse(source, filename=str(path))
    nodes = collect_nodes(tree, source)
    if not nodes:
        return 0, 0

    starts = _line_starts(source)
    replacements: list[tuple[int, int, bytes]] = []
    uses_bytes = False
    for node in nodes:
        start = _offset(starts, node.lineno, node.col_offset)
        end = _offset(starts, node.end_lineno or node.lineno, node.end_col_offset or node.col_offset)
        raw = source[start:end]
        if not raw or raw[:1] not in (b'"', b"'", b"b", b"r", b"B", b"R"):
            # Пропускаем нестандартные литералы: безопаснее не трогать.
            continue
        if isinstance(node.value, bytes):
            token = encode_bytes(node.value)
            replacement = f'B("{token}")'.encode("ascii")
            uses_bytes = True
        else:
            token = encode_text(node.value)
            replacement = f'L("{token}")'.encode("ascii")
        replacements.append((start, end, replacement))

    if not replacements:
        return 0, 0

    transformed = bytearray(source)
    for start, end, replacement in sorted(replacements, key=lambda item: item[0], reverse=True):
        transformed[start:end] = replacement

    if not has_import:
        prefix = ".." if path.parent == SIGNATURE_DIR else "."
        names = "B, L" if uses_bytes else "L"
        import_line = f"from {prefix}ldr import {names}\n".encode("ascii")

        future_marker = b"from __future__ import annotations\n"
        position = transformed.find(future_marker)
        if position >= 0:
            insert_at = position + len(future_marker)
            if transformed[insert_at:insert_at + 1] == b"\n":
                insert_at += 1
        else:
            insert_at = 0
        transformed[insert_at:insert_at] = import_line

    path.write_bytes(bytes(transformed))
    return len(replacements), 1


def main() -> int:
    targets = sorted(SIGNATURE_DIR.glob("*.py")) + EXTRA_FILES
    total, files = 0, 0
    for path in targets:
        if path.name in {"__init__.py", "base.py"}:
            continue
        count, changed = transform(path)
        if count:
            total += count
            files += changed
            print(f"{path.relative_to(ROOT)}: закодировано {count} маркеров")
    print(f"Итого: {total} маркеров в {files} файлах.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
