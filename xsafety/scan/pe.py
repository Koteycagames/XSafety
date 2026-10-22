"""Безопасный разбор PE-заголовков (EXE/DLL) без исполнения файла.

Разбор полностью защищён от выхода за границы буфера, циклов и
«заголовков-бомб»: все смещения проверяются, количество секций и
импортов ограничено. Любая ошибка → ``None``, а не исключение
(см. SECURITY.md, цикл 1, V-01/V-02).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MAX_SECTIONS = 96
MAX_IMPORTS = 64
MAX_FUNCTIONS = 128
MAX_TOTAL_FUNCTIONS = 512
MAX_NAME = 256
#: Минимальный размер корректного PE-файла с одним заголовком.
MIN_PE_SIZE = 0x40


@dataclass(slots=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)  # IMAGE_SCN_MEM_WRITE


@dataclass(slots=True)
class PEInfo:
    is_dll: bool
    is_dotnet: bool
    machine: int
    magic: int
    subsystem: int
    entry_point: int
    timestamp: int
    has_signature: bool
    has_tls: bool
    sections: list[Section] = field(default_factory=list)
    #: Имена функций из таблицы импорта (например, VirtualAllocEx).
    imports: list[str] = field(default_factory=list)
    #: Имена библиотек (например, kernel32.dll).
    libraries: list[str] = field(default_factory=list)
    export_count: int = 0
    export_names: list[str] = field(default_factory=list)

    @property
    def rwx_sections(self) -> list[Section]:
        return [s for s in self.sections if s.executable and s.writable]

    @property
    def is_64(self) -> bool:
        return self.magic == 0x20B

    def imports_any(self, names: set[str]) -> list[str]:
        wanted = {n.lower() for n in names}
        found = [item for item in self.imports if item.lower() in wanted]
        found.extend(item for item in self.libraries if item.lower() in wanted)
        return found


class _Reader:
    __slots__ = ("data",)

    def __init__(self, data: bytes) -> None:
        self.data = data

    def u16(self, offset: int) -> int:
        if offset < 0 or offset + 2 > len(self.data):
            raise ValueError("out of bounds")
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset: int) -> int:
        if offset < 0 or offset + 4 > len(self.data):
            raise ValueError("out of bounds")
        return struct.unpack_from("<I", self.data, offset)[0]

    def u64(self, offset: int) -> int:
        if offset < 0 or offset + 8 > len(self.data):
            raise ValueError("out of bounds")
        return struct.unpack_from("<Q", self.data, offset)[0]

    def cstr(self, offset: int, limit: int = MAX_NAME) -> str:
        if offset < 0 or offset >= len(self.data):
            raise ValueError("out of bounds")
        end = self.data.find(b"\x00", offset, min(offset + limit, len(self.data)))
        if end == -1:
            end = min(offset + limit, len(self.data))
        return self.data[offset:end].decode("ascii", errors="ignore")

    def bytes_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError("out of bounds")
        return self.data[offset : offset + size]


def _rva_to_offset(rva: int, sections: list[Section], size_of_headers: int) -> int | None:
    for section in sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + span:
            delta = rva - section.virtual_address
            if delta < section.raw_size:
                return section.raw_offset + delta
            return None
    if rva < size_of_headers:
        return rva
    return None


def parse_pe(data: bytes) -> PEInfo | None:
    """Возвращает PEInfo или None, если файл не является корректным PE."""
    try:
        return _parse(data)
    except (ValueError, struct.error, IndexError, OverflowError):
        return None


def _parse(data: bytes) -> PEInfo | None:
    if len(data) < MIN_PE_SIZE or data[:2] != b"MZ":
        return None
    reader = _Reader(data)
    e_lfanew = reader.u32(0x3C)
    if e_lfanew < 0x40 or e_lfanew + 24 > len(data):
        return None
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None

    coff = e_lfanew + 4
    machine = reader.u16(coff)
    section_count = reader.u16(coff + 2)
    timestamp = reader.u32(coff + 4)
    size_of_optional = reader.u16(coff + 16)
    characteristics = reader.u16(coff + 18)
    if section_count > MAX_SECTIONS:
        raise ValueError("too many sections")
    is_dll = bool(characteristics & 0x2000)

    opt = coff + 20
    magic = reader.u16(opt)
    if magic not in (0x10B, 0x20B):
        return None
    is_pe64 = magic == 0x20B
    entry_point = reader.u32(opt + 16)
    # Смещения полей различаются для PE32/PE32+.
    subsystem = reader.u16(opt + (68 if is_pe64 else 68))
    size_of_headers = reader.u32(opt + 60)
    number_of_rva = reader.u32(opt + (108 if is_pe64 else 92))
    dir_base = opt + (112 if is_pe64 else 96)
    if number_of_rva > 16:
        number_of_rva = 16

    def directory(index: int) -> tuple[int, int]:
        if index >= number_of_rva:
            return 0, 0
        offset = dir_base + index * 8
        return reader.u32(offset), reader.u32(offset + 4)

    import_rva, import_size = directory(1)
    export_rva, export_size = directory(0)
    security_rva, security_size = directory(4)
    tls_rva, _ = directory(9)
    cli_rva, _ = directory(14)

    section_table = opt + size_of_optional
    sections: list[Section] = []
    for index in range(section_count):
        base = section_table + index * 40
        if base + 40 > len(data):
            break
        sections.append(
            Section(
                name=reader.cstr(base, 8).rstrip("\x00"),
                virtual_size=reader.u32(base + 8),
                virtual_address=reader.u32(base + 12),
                raw_size=reader.u32(base + 16),
                raw_offset=reader.u32(base + 20),
                characteristics=reader.u32(base + 36),
            )
        )

    libraries: list[str] = []
    functions: list[str] = []
    if import_rva and import_size:
        offset = _rva_to_offset(import_rva, sections, size_of_headers)
        if offset is not None:
            for index in range(MAX_IMPORTS):
                base = offset + index * 20
                if base + 20 > len(data):
                    break
                original_first_thunk = reader.u32(base)
                name_rva = reader.u32(base + 12)
                first_thunk = reader.u32(base + 16)
                if name_rva == 0:
                    break
                name_offset = _rva_to_offset(name_rva, sections, size_of_headers)
                if name_offset is None:
                    break
                library = reader.cstr(name_offset)
                if not library:
                    break
                libraries.append(library)

                thunk_rva = original_first_thunk or first_thunk
                thunk_offset = _rva_to_offset(thunk_rva, sections, size_of_headers) if thunk_rva else None
                if thunk_offset is None:
                    continue
                step = 8 if is_pe64 else 4
                for position in range(MAX_FUNCTIONS):
                    entry = thunk_offset + position * step
                    try:
                        value = reader.u64(entry) if is_pe64 else reader.u32(entry)
                    except ValueError:
                        break
                    if value == 0:
                        break
                    ordinal_mask = 1 << 63 if is_pe64 else 1 << 31
                    if value & ordinal_mask:
                        continue
                    hint_offset = _rva_to_offset(value & (ordinal_mask - 1), sections, size_of_headers)
                    if hint_offset is None:
                        continue
                    try:
                        function = reader.cstr(hint_offset + 2)
                    except ValueError:
                        continue
                    if function:
                        functions.append(function)
                        if len(functions) >= MAX_TOTAL_FUNCTIONS:
                            break
                if len(functions) >= MAX_TOTAL_FUNCTIONS:
                    break

    export_names: list[str] = []
    export_count = 0
    if export_rva and export_size:
        offset = _rva_to_offset(export_rva, sections, size_of_headers)
        if offset is not None and offset + 40 <= len(data):
            export_count = reader.u32(offset + 24)  # NumberOfFunctions
            names_rva = reader.u32(offset + 32)
            names_count = reader.u32(offset + 24)
            if names_rva and names_count:
                names_offset = _rva_to_offset(names_rva, sections, size_of_headers)
                if names_offset is not None:
                    for index in range(min(names_count, 32)):
                        base = names_offset + index * 4
                        if base + 4 > len(data):
                            break
                        name_rva = reader.u32(base)
                        name_offset = _rva_to_offset(name_rva, sections, size_of_headers)
                        if name_offset is None:
                            continue
                        export_names.append(reader.cstr(name_offset))

    return PEInfo(
        is_dll=is_dll,
        is_dotnet=bool(cli_rva),
        machine=machine,
        magic=magic,
        subsystem=subsystem,
        entry_point=entry_point,
        timestamp=timestamp,
        has_signature=bool(security_rva and security_size),
        has_tls=bool(tls_rva),
        sections=sections,
        imports=functions,
        libraries=libraries,
        export_count=max(export_count, 0),
        export_names=export_names,
    )
