/* ZIP-контейнер: чтение каталога, безопасная распаковка в память, находки.
 * Порт xsafety/scan/archives.py и части xsafety/scan/signatures/zip.py.
 * Ничего не пишется на диск: распаковка идёт через DecompressionStream.
 */
import { cleanText } from "./text.js";

const MAX_ENTRIES = 512;
const MAX_ENTRY_BYTES = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const MAX_RATIO = 150;
const MAX_DEPTH = 2;

const DANGEROUS = new Set(["exe", "dll", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "ps1", "hta", "jar", "msi"]);

function u16(bytes, offset) {
  return bytes[offset] | (bytes[offset + 1] << 8);
}
function u32(bytes, offset) {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
}

export function looksLikeZip(bytes) {
  if (!bytes || bytes.length < 4) return false;
  if (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 3 && bytes[3] === 4) return true;
  if (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 5 && bytes[3] === 6) return true;
  if (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 7 && bytes[3] === 8) return true;
  return false;
}

function findEocd(bytes) {
  const start = Math.max(bytes.length - 65557, 0);
  for (let index = bytes.length - 22; index >= start; index--) {
    if (u32(bytes, index) === 0x06054b50) return index;
  }
  return -1;
}

function normalizeName(name) {
  return name.replace(/\\/g, "/").replace(/^\/+/, "");
}

function isTraversal(name) {
  const parts = normalizeName(name).split("/");
  return parts.includes("..") || /^[a-zA-Z]:\//.test(name) || name.startsWith("/");
}

function isDoubleExtension(name) {
  const base = name.split("/").pop() || "";
  const parts = base.toLowerCase().split(".");
  if (parts.length < 3) return false;
  return DANGEROUS.has(parts[parts.length - 1]);
}

async function inflateRaw(bytes) {
  if (typeof DecompressionStream === "undefined") return null;
  try {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
    const reader = stream.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_ENTRY_BYTES) {
        try {
          await reader.cancel();
        } catch {
          /* поток уже закрыт */
        }
        return null;
      }
      chunks.push(value);
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  } catch {
    return null;
  }
}

/** Читает каталог ZIP и (по запросу) распаковывает записи в память. */
export async function readZip(bytes, { inflate = true } = {}) {
  const report = {
    readable: false,
    entries: [],
    names: [],
    traversalNames: [],
    doubleExtNames: [],
    ratioAlerts: [],
    oversized: [],
    encryptedCount: 0,
    truncated: false,
    notes: [],
    totalUnpacked: 0,
  };
  const eocd = findEocd(bytes);
  if (eocd < 0) {
    report.notes.push("не найден конец каталога ZIP");
    return report;
  }
  const count = u16(bytes, eocd + 10);
  let offset = u32(bytes, eocd + 16);
  if (!count || offset >= bytes.length) {
    report.notes.push("каталог ZIP пуст или повреждён");
    return report;
  }

  for (let index = 0; index < count; index++) {
    if (index >= MAX_ENTRIES) {
      report.truncated = true;
      break;
    }
    if (offset + 46 > bytes.length || u32(bytes, offset) !== 0x02014b50) break;
    const flags = u16(bytes, offset + 8);
    const method = u16(bytes, offset + 10);
    const compressed = u32(bytes, offset + 20);
    const uncompressed = u32(bytes, offset + 24);
    const nameLength = u16(bytes, offset + 28);
    const extraLength = u16(bytes, offset + 30);
    const commentLength = u16(bytes, offset + 32);
    const localOffset = u32(bytes, offset + 42);
    const nameStart = offset + 46;
    if (nameStart + nameLength > bytes.length) break;
    const name = new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(nameStart, nameStart + nameLength));
    offset = nameStart + nameLength + extraLength + commentLength;

    const entry = {
      name,
      method,
      compressed,
      size: uncompressed,
      encrypted: Boolean(flags & 1),
      localOffset,
    };
    report.entries.push(entry);
    report.names.push(name);

    if (isTraversal(name)) report.traversalNames.push(name);
    if (isDoubleExtension(name)) report.doubleExtNames.push(name);
    if (entry.encrypted) report.encryptedCount += 1;
    if (uncompressed > MAX_ENTRY_BYTES) report.oversized.push(name);
    if (compressed > 0 && uncompressed / compressed > MAX_RATIO && uncompressed > 1024 * 1024) {
      report.ratioAlerts.push(`${name} (${Math.round(uncompressed / compressed)}:1)`);
    }
  }

  report.readable = report.entries.length > 0;

  if (inflate) {
    for (const entry of report.entries) {
      if (report.totalUnpacked >= MAX_TOTAL_BYTES) {
        report.truncated = true;
        break;
      }
      if (entry.encrypted || entry.localOffset >= bytes.length) continue;
      const local = entry.localOffset;
      if (u32(bytes, local) !== 0x04034b50) continue;
      const nameLength = u16(bytes, local + 26);
      const extraLength = u16(bytes, local + 28);
      const dataStart = local + 30 + nameLength + extraLength;
      const data = bytes.subarray(dataStart, dataStart + entry.compressed);
      if (entry.method === 0) {
        entry.data = data;
      } else if (entry.method === 8) {
        const inflated = await inflateRaw(data);
        if (!inflated) {
          report.notes.push(`не удалось распаковать ${cleanText(entry.name, 60)}`);
          continue;
        }
        entry.data = inflated;
      } else {
        continue;
      }
      report.totalUnpacked += entry.data.length;
    }
  }

  if (report.truncated) report.notes.push("часть записей пропущена по лимитам анализа");
  return report;
}

function finding(sig_id, title, severity, description, evidence) {
  return {
    sig_id,
    title,
    severity,
    description,
    evidence: cleanText(evidence || "", 160),
    offset: null,
    entry: null,
  };
}

/** Находки уровня архива (.zip). */
export function archiveFindings(report) {
  const out = [];
  if (report.traversalNames.length) {
    out.push(finding("zip.path_traversal", "Запись с выходом из каталога (zip-slip)", "critical",
      "Имена записей содержат «..» или абсолютный путь. При распаковке такой архив может перезаписать файлы вне целевого каталога. Распаковывайте только в изолированной среде.",
      report.traversalNames.slice(0, 3).join(", ")));
  }
  if (report.doubleExtNames.length) {
    out.push(finding("zip.double_extension", "Двойное расширение файлов", "high",
      "Записи вида «счёт.pdf.exe» маскируют исполняемый файл под документ. Не открывайте такие файлы.",
      report.doubleExtNames.slice(0, 3).join(", ")));
  }
  if (report.ratioAlerts.length) {
    out.push(finding("zip.compression_bomb", "Аномальное сжатие (zip-bomb)", "high",
      "Одна или несколько записей сжимаются в сотни раз — распаковка может исчерпать диск или память. Такие записи пропущены.",
      report.ratioAlerts.slice(0, 3).join(", ")));
  }
  if (report.encryptedCount) {
    out.push(finding("zip.encrypted", "Зашифрованные записи", "medium",
      "Архив защищён паролем: содержимое нельзя проверить антивирусом и статическим анализом. Требуйте пароль у отправителя.",
      `записей: ${report.encryptedCount}`));
  }
  if (report.oversized.length) {
    out.push(finding("zip.oversized_entry", "Слишком крупные записи", "medium",
      "Записи превышают лимит анализа и были пропущены.", report.oversized.slice(0, 3).join(", ")));
  }
  if (report.truncated) {
    out.push(finding("zip.truncated", "Архив проверен частично", "medium",
      "Из-за лимитов проверены не все записи. Остаток архива требует отдельной проверки.",
      report.notes.slice(0, 2).join("; ")));
  }
  if (!report.readable) {
    out.push(finding("zip.unreadable", "Повреждённый архив", "medium",
      "Файл с расширением .zip не читается как архив. Возможно, это маскировка другого формата или повреждённый файл.", ""));
  }
  return out;
}

const JAR_SHELL = ["powershell", "cmd.exe /c", "http://", "https://"];

/** Находки уровня JAR: подписи, манифест, классы, вложенные исполняемые файлы. */
export function jarFindings(report) {
  const out = [];
  const names = report.names.map((name) => name.replace(/\\/g, "/"));
  const lowered = names.map((name) => name.toLowerCase());
  const manifestEntry = report.entries.find((entry) => /meta-inf\/manifest\.mf$/i.test(entry.name));
  let mainClass = "";
  if (manifestEntry && manifestEntry.data) {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(manifestEntry.data);
    const match = /^Main-Class:\s*(\S+)/im.exec(text);
    if (match) mainClass = match[1];
  }
  if (mainClass) {
    out.push(finding("jar.main_class", "Указан главный класс", "info",
      `Манифест запускает ${cleanText(mainClass, 80)} при двойном клике. Проверьте, что это ожидаемое приложение.`, mainClass));
  }
  const signed = names.some((name) => /^META-INF\/[^/]+\.(RSA|DSA|EC|SF)$/i.test(name));
  if (!signed) {
    out.push(finding("jar.unsigned", "JAR без подписи", "low",
      "Архив не подписан: издателя нельзя подтвердить. Запускайте только из доверенного источника.", ""));
  }
  if (!lowered.some((name) => name.endsWith(".class"))) {
    out.push(finding("jar.no_classes", "В JAR нет классов", "medium",
      "Внутри нет .class-файлов — это не обычная Java-программа, возможно маскировка.", ""));
  }
  const embedded = names.filter((name) => /\.(exe|dll|scr|bat|cmd|ps1|vbs|js|hta)$/i.test(name));
  if (embedded.length) {
    out.push(finding("jar.embedded_executable", "Вложенный исполняемый файл", "high",
      "Внутри JAR лежит исполняемый файл. Легитимные библиотеки так делают редко.", embedded.slice(0, 3).join(", ")));
  }
  const nested = names.filter((name) => /\.(zip|jar|war|ear)$/i.test(name));
  if (nested.length) {
    out.push(finding("jar.nested_archive", "Вложенный архив", "medium",
      "Внутри JAR есть другой архив — проверка вложенности ограничена.", nested.slice(0, 3).join(", ")));
  }
  if (report.encryptedCount) {
    out.push(finding("jar.encrypted", "Зашифрованные записи", "medium",
      "Часть записей зашифрована: их содержимое не проверено.", `записей: ${report.encryptedCount}`));
  }
  if (report.traversalNames.length) {
    out.push(finding("jar.path_traversal", "Zip-slip в JAR", "critical",
      "Имена записей выходят за пределы каталога распаковки.", report.traversalNames.slice(0, 3).join(", ")));
  }
  if (report.doubleExtNames.length) {
    out.push(finding("jar.double_extension", "Двойное расширение", "high",
      "Запись маскируется под документ, оставаясь исполняемой.", report.doubleExtNames.slice(0, 3).join(", ")));
  }
  const shell = [];
  for (const entry of report.entries) {
    if (!entry.data || entry.data.length > 512 * 1024) continue;
    const text = new TextDecoder("utf-8", { fatal: false }).decode(entry.data).toLowerCase();
    if (/getruntime|runtime\.getruntime|processbuilder/.test(text)) shell.push(entry.name);
  }
  if (shell.length) {
    out.push(finding("jar.runtime_exec", "Запуск процессов из Java", "high",
      "Классы вызывают Runtime.exec/ProcessBuilder — типично для дропперов и бэкдоров.",
      shell.slice(0, 3).join(", ")));
  }
  const strings = [];
  for (const entry of report.entries) {
    if (!entry.data || entry.data.length > 512 * 1024) continue;
    const text = new TextDecoder("latin1").decode(entry.data).toLowerCase();
    const hit = JAR_SHELL.filter((needle) => text.includes(needle));
    if (hit.length) strings.push(`${entry.name}: ${hit.join(", ")}`);
  }
  if (strings.length) {
    out.push(finding("jar.shell_strings", "Команды запуска внутри JAR", "high",
      "В содержимом архива найдены команды оболочки и адреса загрузки.", strings.slice(0, 2).join("; ")));
  }
  return out;
}
