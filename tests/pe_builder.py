"""Сборка минимального валидного PE для тестов парсера.

Файл не исполняется: это только структура заголовков, секций и таблицы
импорта, чтобы проверить разбор границ и импортов.
"""

from __future__ import annotations

import struct

SECTION_HEADERS = 0x400


def build_pe(
    *,
    is64: bool = True,
    dll: bool = False,
    import_functions: tuple[str, ...] = ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"),
    import_library: str = "kernel32.dll",
    rwx: bool = False,
    extra_section: str | None = None,
) -> bytes:
    size_headers = SECTION_HEADERS
    data = bytearray(0x1000)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"

    coff = 0x84
    section_count = 3 if extra_section else 2
    struct.pack_into("<H", data, coff, 0x8664 if is64 else 0x14C)
    struct.pack_into("<H", data, coff + 2, section_count)
    struct.pack_into("<I", data, coff + 4, 0x60000000)
    struct.pack_into("<H", data, coff + 16, 0xF0)
    struct.pack_into("<H", data, coff + 18, 0x2022 if dll else 0x0022)

    opt = coff + 20
    struct.pack_into("<H", data, opt, 0x20B if is64 else 0x10B)
    struct.pack_into("<I", data, opt + 16, 0x1000)  # AddressOfEntryPoint
    if is64:
        struct.pack_into("<Q", data, opt + 24, 0x140000000)
    else:
        struct.pack_into("<I", data, opt + 28, 0x400000)
    struct.pack_into("<I", data, opt + 32, 0x1000)
    struct.pack_into("<I", data, opt + 36, 0x200)
    struct.pack_into("<I", data, opt + 56, 0x5000)
    struct.pack_into("<I", data, opt + 60, size_headers)
    struct.pack_into("<H", data, opt + 68, 3)  # GUI
    struct.pack_into("<I", data, opt + (108 if is64 else 92), 16)
    directories = opt + (112 if is64 else 96)
    struct.pack_into("<I", data, directories + 8, 0x2000)  # Import
    struct.pack_into("<I", data, directories + 12, 40)

    section_table = opt + 0xF0

    def write_section(index: int, name: bytes, virtual_address: int, virtual_size: int, raw_offset: int, raw_size: int, flags: int) -> None:
        base = section_table + index * 40
        data[base : base + 8] = name.ljust(8, b"\x00")
        struct.pack_into("<I", data, base + 8, virtual_size)
        struct.pack_into("<I", data, base + 12, virtual_address)
        struct.pack_into("<I", data, base + 16, raw_size)
        struct.pack_into("<I", data, base + 20, raw_offset)
        struct.pack_into("<I", data, base + 36, flags)

    write_section(0, b".text", 0x1000, 0x1000, 0x400, 0x200, 0x60000020)
    rdata_flags = 0xE0000020 if rwx else 0x40000040
    write_section(1, b".rdata", 0x2000, 0x400, 0x600, 0x400, rdata_flags)
    if extra_section:
        write_section(2, extra_section.encode()[:8], 0x3000, 0x1000, 0xE00, 0x200, 0xE0000020)

    def rva_to_offset(rva: int) -> int:
        return rva - 0x2000 + 0x600

    import_offset = rva_to_offset(0x2000)
    struct.pack_into("<I", data, import_offset, 0x2100)  # OriginalFirstThunk
    struct.pack_into("<I", data, import_offset + 12, 0x2180)  # Name
    struct.pack_into("<I", data, import_offset + 16, 0x2200)  # FirstThunk

    name_offset = rva_to_offset(0x2180)
    encoded = import_library.encode("ascii")
    data[name_offset : name_offset + len(encoded)] = encoded

    step = 8 if is64 else 4
    for index, function in enumerate(import_functions[:32]):
        thunk_rva = 0x2100 + index * step
        struct.pack_into("<Q" if is64 else "<I", data, rva_to_offset(thunk_rva), 0x2300 + index * 0x40)
        hint_offset = rva_to_offset(0x2300 + index * 0x40)
        struct.pack_into("<H", data, hint_offset, 0)
        function_bytes = function.encode("ascii")
        data[hint_offset + 2 : hint_offset + 2 + len(function_bytes)] = function_bytes

    struct.pack_into("<Q" if is64 else "<I", data, rva_to_offset(0x2100 + len(import_functions) * step), 0)
    return bytes(data)
