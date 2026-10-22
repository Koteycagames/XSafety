/* Безопасный разбор PE (EXE/DLL): только чтение заголовков и импортов.
 * Порт xsafety/scan/pe.py. Любая ошибка → null, файл никогда не исполняется.
 */
const MAX_SECTIONS = 96;
const MAX_IMPORTS = 64;
const MAX_FUNCTIONS = 128;
const MAX_TOTAL_FUNCTIONS = 512;
const MAX_NAME = 256;
const MIN_PE_SIZE = 0x40;

function reader(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const need = (offset, size) => {
    if (offset < 0 || size < 0 || offset + size > bytes.length) throw new RangeError("out of bounds");
    return offset;
  };
  return {
    u16: (offset) => (need(offset, 2), view.getUint16(offset, true)),
    u32: (offset) => (need(offset, 4), view.getUint32(offset, true)),
    u64: (offset) => (need(offset, 8), Number(view.getBigUint64(offset, true))),
    cstr(offset, limit = MAX_NAME) {
      let out = "";
      for (let i = 0; i < limit; i++) {
        const position = offset + i;
        if (position >= bytes.length) break;
        const byte = bytes[position];
        if (byte === 0) break;
        out += String.fromCharCode(byte);
      }
      return out;
    },
    ascii(offset, size) {
      need(offset, size);
      let out = "";
      for (let i = 0; i < size; i++) out += String.fromCharCode(bytes[offset + i]);
      return out;
    },
    slice(offset, size) {
      need(offset, size);
      return bytes.subarray(offset, offset + size);
    },
    length: bytes.length,
  };
}

function rvaToOffset(rva, sections, headersSize) {
  if (rva < headersSize) return rva;
  for (const section of sections) {
    const span = Math.max(section.virtualSize, section.rawSize);
    if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
      return section.rawOffset + (rva - section.virtualAddress);
    }
  }
  return null;
}

export function parsePE(bytes) {
  try {
    return parse(bytes);
  } catch {
    return null;
  }
}

function parse(bytes) {
  if (!bytes || bytes.length < MIN_PE_SIZE) return null;
  if (bytes[0] !== 0x4d || bytes[1] !== 0x5a) return null;
  const r = reader(bytes);
  const peOffset = r.u32(0x3c);
  if (peOffset < 0x40 || peOffset + 24 > bytes.length) return null;
  if (r.ascii(peOffset, 4) !== "PE\u0000\u0000") return null;

  const coff = peOffset + 4;
  const machine = r.u16(coff);
  const sectionCount = r.u16(coff + 2);
  const timestamp = r.u32(coff + 4);
  const optionalSize = r.u16(coff + 16);
  const characteristics = r.u16(coff + 18);
  if (sectionCount > MAX_SECTIONS) return null;

  const opt = coff + 20;
  const magic = r.u16(opt);
  if (magic !== 0x10b && magic !== 0x20b) return null;
  const is64 = magic === 0x20b;
  const entryPoint = r.u32(opt + 16);
  const subsystem = r.u16(opt + 68);
  const headersSize = r.u32(opt + 60);
  const dirCount = Math.min(r.u32(opt + (is64 ? 108 : 92)), 16);
  const dirBase = opt + (is64 ? 112 : 96);
  const dir = (index) => (index >= dirCount ? [0, 0] : [r.u32(dirBase + index * 8), r.u32(dirBase + index * 8 + 4)]);

  const [exportRva, exportSize] = dir(0);
  const [importRva, importSize] = dir(1);
  const [securityRva, securitySize] = dir(4);
  const [tlsRva] = dir(9);
  const [cliRva] = dir(14);

  const table = opt + optionalSize;
  const sections = [];
  for (let index = 0; index < sectionCount; index++) {
    const base = table + index * 40;
    if (base + 40 > bytes.length) break;
    sections.push({
      name: r.cstr(base, 8).replace(/\u0000+$/, ""),
      virtualSize: r.u32(base + 8),
      virtualAddress: r.u32(base + 12),
      rawSize: r.u32(base + 16),
      rawOffset: r.u32(base + 20),
      characteristics: r.u32(base + 36),
    });
  }
  for (const section of sections) {
    section.executable = Boolean(section.characteristics & 0x20000000);
    section.writable = Boolean(section.characteristics & 0x80000000);
  }

  const libraries = [];
  const imports = [];
  if (importRva && importSize) {
    const start = rvaToOffset(importRva, sections, headersSize);
    if (start !== null) {
      for (let index = 0; index < MAX_IMPORTS; index++) {
        const base = start + index * 20;
        if (base + 20 > bytes.length) break;
        const originalFirstThunk = r.u32(base);
        const nameRva = r.u32(base + 12);
        const firstThunk = r.u32(base + 16);
        if (!nameRva) break;
        const nameOffset = rvaToOffset(nameRva, sections, headersSize);
        if (nameOffset === null) break;
        const library = r.cstr(nameOffset);
        if (!library) break;
        libraries.push(library);

        const thunkRva = originalFirstThunk || firstThunk;
        const thunkOffset = thunkRva ? rvaToOffset(thunkRva, sections, headersSize) : null;
        if (thunkOffset === null) continue;
        const step = is64 ? 8 : 4;
        for (let position = 0; position < MAX_FUNCTIONS; position++) {
          const entry = thunkOffset + position * step;
          let value;
          try {
            value = is64 ? r.u64(entry) : r.u32(entry);
          } catch {
            break;
          }
          if (value === 0) break;
          const ordinalMask = is64 ? 2 ** 63 : 2 ** 31;
          if (value >= ordinalMask) continue; // импорт по номеру, имени нет
          const hintOffset = rvaToOffset(value, sections, headersSize);
          if (hintOffset === null) continue;
          let hint = "";
          try {
            hint = r.cstr(hintOffset + 2);
          } catch {
            continue;
          }
          if (hint) {
            imports.push(hint);
            if (imports.length >= MAX_TOTAL_FUNCTIONS) break;
          }
        }
        if (imports.length >= MAX_TOTAL_FUNCTIONS) break;
      }
    }
  }

  const exportNames = [];
  let exportCount = 0;
  if (exportRva && exportSize) {
    const offset = rvaToOffset(exportRva, sections, headersSize);
    if (offset !== null && offset + 40 <= bytes.length) {
      exportCount = r.u32(offset + 24);
      const namesRva = r.u32(offset + 32);
      if (namesRva) {
        const namesOffset = rvaToOffset(namesRva, sections, headersSize);
        if (namesOffset !== null) {
          for (let index = 0; index < Math.min(exportCount, 32); index++) {
            const base = namesOffset + index * 4;
            if (base + 4 > bytes.length) break;
            const nameOffset = rvaToOffset(r.u32(base), sections, headersSize);
            if (nameOffset === null) continue;
            exportNames.push(r.cstr(nameOffset));
          }
        }
      }
    }
  }

  return {
    isDll: Boolean(characteristics & 0x2000),
    isDotnet: Boolean(cliRva),
    machine,
    magic,
    subsystem,
    entryPoint,
    timestamp,
    hasSignature: Boolean(securityRva && securitySize),
    hasTls: Boolean(tlsRva),
    sections,
    imports,
    libraries,
    exportCount: Math.max(exportCount, 0),
    exportNames,
    is64,
    rwxSections: sections.filter((section) => section.executable && section.writable),
  };
}

export function importsAny(pe, names) {
  if (!pe) return [];
  const wanted = new Set(names.map((name) => name.toLowerCase()));
  const found = pe.imports.filter((name) => wanted.has(name.toLowerCase()));
  for (const library of pe.libraries) {
    if (wanted.has(library.toLowerCase())) found.push(library);
  }
  return found;
}
