/* Движок сканирования в браузере.
 *
 * Тот же контракт, что у Python-движка: файл никогда не исполняется и не
 * покидает устройство; архивы распаковываются только в памяти с лимитами.
 */
import CATALOG from "../data/catalog.js";
import { SIGNATURES } from "../data/signatures/index.js";
import { runCheck } from "./checks.js";
import { parsePE } from "./pe.js";
import {
  buildRegex, cleanText, decodeText, iterStrings, lineNumber, safeEvidence,
  SEVERITY_LABEL, sha256Hex, verdictFor,
} from "./text.js";
import { archiveFindings, jarFindings, looksLikeZip, readZip } from "./zip.js";

const MAX_UPLOAD_BYTES = 64 * 1024 * 1024;
const MAX_TEXT_BYTES = 512 * 1024;
const MAX_FINDINGS = 300;
const MAX_ENTRIES = 512;
const MAX_DEPTH = 2;
const MAX_SECONDS = 20;
const TEXT_EXT = new Set([
  "bat", "cmd", "py", "pyw", "js", "mjs", "cjs", "ps1", "psm1", "vbs", "vbe",
  "hta", "txt", "md", "xml", "ini", "cfg", "json", "yaml", "yml",
]);

const ARCHIVE_EXT = new Set(["zip", "jar"]);
const MODELS = new Map(CATALOG.models.map((model) => [model.id, model]));

export class ScanError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

export function sanitizeFilename(name) {
  const base = String(name || "").replace(/\\/g, "/").split("/").pop().replace(/[\u0000-\u001f\u007f]/g, "").trim().replace(/^\.+|\.+$/g, "");
  if (!base) throw new ScanError("invalid_filename", "Пустое имя файла");
  return base.slice(0, 180);
}

export function extensionFrom(name) {
  if (!name.includes(".")) return "";
  const ext = name.split(".").pop().toLowerCase();
  return /^[a-z0-9]{1,12}$/.test(ext) ? ext : "";
}

export function modelSupports(modelId, ext) {
  const model = MODELS.get(modelId);
  return Boolean(model && model.extensions.includes(ext));
}

export function modelExtensions(modelId) {
  return MODELS.get(modelId)?.extensions || [];
}

function node(name, data, ext, depth, entry, parent) {
  return {
    name,
    data,
    ext,
    depth,
    entry,
    parent,
    size: data.length,
    get text() {
      if (this._text === undefined) this._text = decodeText(data.subarray(0, MAX_TEXT_BYTES));
      return this._text;
    },
    get strings() {
      if (this._strings === undefined) this._strings = iterStrings(data);
      return this._strings;
    },
  };
}

function rulesFor(ext) {
  return SIGNATURES.filter((rule) => !rule.e || rule.e.includes(ext));
}

function haystackFor(rule, file) {
  if (rule.k === "text") return file.text;
  if (rule.k === "binary") return file.strings.join("\n");
  return TEXT_EXT.has(file.ext) ? file.text : file.strings.join("\n");
}

function matchRule(rule, file) {
  const haystack = haystackFor(rule, file);
  if (!haystack) return [];
  const patterns = rule.p || [];
  const out = [];
  const seen = new Set();

  const make = (match, evidence) => ({
    sig_id: rule.i,
    title: rule.t,
    severity: rule.s,
    description: rule.d,
    evidence,
    entry: file.entry,
    offset: rule.k !== "binary" && TEXT_EXT.has(file.ext) ? lineNumber(haystack, match.index) : null,
  });

  if ((rule.m || 1) > 1) {
    let matched = 0;
    let anchor = null;
    for (const pattern of patterns) {
      const match = buildRegex(pattern, rule.f?.[pattern] || "").exec(haystack);
      if (!match) continue;
      matched += 1;
      if (!anchor) anchor = match;
    }
    if (matched >= rule.m && anchor) out.push(make(anchor, safeEvidence(haystack, anchor.index, anchor.index + anchor[0].length)));
    return out;
  }

  for (const pattern of patterns) {
    const regex = buildRegex(pattern, (rule.f?.[pattern] || "") + "g");
    let match;
    while ((match = regex.exec(haystack)) !== null) {
      const evidence = safeEvidence(haystack, match.index, match.index + match[0].length);
      const key = evidence.toLowerCase();
      if (!key || seen.has(key)) {
        if (match[0] === "") regex.lastIndex++;
        continue;
      }
      seen.add(key);
      out.push(make(match, evidence));
      if (out.length >= (rule.x || 3)) return out;
      if (match[0] === "") regex.lastIndex++;
    }
  }
  return out;
}

async function scanNode(file, ctx, depth) {
  const findings = [];
  const notes = [];
  let entries = 1;

  if (ARCHIVE_EXT.has(file.ext)) {
    if (!looksLikeZip(file.data)) {
      findings.push({
        sig_id: `${file.ext}.not_archive`,
        title: "Не архив",
        severity: "medium",
        description: `Файл с расширением .${file.ext} не является ZIP-контейнером. Возможно, внутри другой формат или файл повреждён.`,
        evidence: "",
        entry: file.entry,
        offset: null,
      });
    } else {
      let report = null;
      try {
        report = await readZip(file.data, { inflate: depth < MAX_DEPTH });
      } catch (error) {
        notes.push(`архив не разобран: ${cleanText(error.message, 80)}`);
      }
      if (report) {
        const level = file.ext === "jar" ? jarFindings(report) : archiveFindings(report);
        findings.push(...level.map((item) => ({ ...item, entry: file.entry })));
        if (depth < MAX_DEPTH) {
          let skipped = 0;
          for (const entry of report.entries) {
            if (ctx.entries >= MAX_ENTRIES) {
              notes.push("вложения архива обрезаны по лимиту записей");
              break;
            }
            if (!entry.data || entry.data.length === 0) continue;
            if (entry.name.endsWith("/")) continue;
            const ext = extensionFrom(entry.name);
            if (!ext || ext === "class" || ext === "mf") continue;
            if (ctx.model && !modelSupports(ctx.model, ext)) {
              skipped += 1;
              continue;
            }
            ctx.entries += 1;
            const path = file.entry ? `${file.entry} → ${entry.name}` : entry.name;
            const nested = node(entry.name, entry.data, ext, depth + 1, path, file.entry || file.name);
            const result = await scanNode(nested, ctx, depth + 1);
            findings.push(...result.findings);
            notes.push(...result.notes);
            entries += result.entries;
          }
          if (skipped) {
            notes.push(`Вложений с расширениями вне тарифа пропущено: ${skipped}. Они не проверены — повысьте тариф или проверьте отдельно.`);
          }
        } else {
          notes.push("Глубже вложенные архивы не проверялись.");
        }
      }
    }
  }

  let pe = null;
  if (file.ext === "exe" || file.ext === "dll") pe = parsePE(file.data);
  if ((file.ext === "exe" || file.ext === "dll") && !pe) {
    findings.push({
      sig_id: `${file.ext}.invalid_pe`,
      title: "Не PE-файл",
      severity: "medium",
      description: `Файл с расширением .${file.ext} не является корректным PE-файлом. Возможно, это маскировка другого формата.`,
      evidence: "",
      entry: file.entry,
      offset: null,
    });
  }

  const ctxForFile = {
    text: file.text,
    strings: file.strings,
    data: file.data,
    ext: file.ext,
    entry: file.entry,
    pe,
  };

  for (const rule of rulesFor(file.ext)) {
    if (ctx.findings >= MAX_FINDINGS) break;
    if (pe === null && rule.k === "pe") continue;
    try {
      const found = rule.w ? runCheck(rule, ctxForFile) : matchRule(rule, file);
      for (const item of found) {
        findings.push(item);
        ctx.findings += 1;
        if (ctx.findings >= MAX_FINDINGS) break;
      }
    } catch (error) {
      notes.push(`Сигнатура ${rule.i} пропущена: ${cleanText(error.message, 60)}`);
    }
    if (ctx.findings >= MAX_FINDINGS) {
      notes.push("Список находок обрезан по лимиту отчёта.");
      break;
    }
  }

  return { findings, notes, entries };
}

async function readBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (typeof input.arrayBuffer === "function") return new Uint8Array(await input.arrayBuffer());
  // Старые браузеры: Blob без arrayBuffer().
  if (typeof FileReader !== "undefined") {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(new Uint8Array(reader.result));
      reader.onerror = () => reject(reader.error || new Error("не удалось прочитать файл"));
      reader.readAsArrayBuffer(input);
    });
  }
  return new Uint8Array(await new Response(input).arrayBuffer());
}

/** Сканирует файл (File/Blob или байты) и возвращает отчёт. */
export async function scanFile(input, filename, modelId, onProgress = () => {}) {
  const started = performance.now();
  const safeName = sanitizeFilename(filename || input?.name || "");
  const ext = extensionFrom(safeName);
  if (!ext) throw new ScanError("unsupported_extension", "Файл без расширения не поддерживается");
  if (!MODELS.has(modelId)) throw new ScanError("unknown_model", "Неизвестная модель");
  if (!modelSupports(modelId, ext)) {
    throw new ScanError("extension_not_allowed", `Модель не проверяет файлы .${ext}`);
  }

  const data = await readBytes(input);
  if (data.length === 0) throw new ScanError("empty_file", "Файл пустой");
  if (data.length > MAX_UPLOAD_BYTES) throw new ScanError("file_too_large", "Файл больше 64 МБ");

  onProgress(8);
  const ctx = { findings: 0, entries: 1, model: modelId };
  const root = node(safeName, data, ext, 0, null, null);
  const result = await scanNode(root, ctx, 0);
  onProgress(78);

  const deduped = [];
  const seen = new Set();
  for (const item of result.findings) {
    const key = `${item.sig_id}|${item.entry || ""}|${(item.evidence || "").toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push({
      ...item,
      title: cleanText(item.title, 120),
      description: cleanText(item.description, 400),
      evidence: cleanText(item.evidence, 180),
      severity_label: SEVERITY_LABEL[item.severity] || item.severity,
    });
    if (deduped.length >= MAX_FINDINGS) break;
  }

  const sha256 = await sha256Hex(data);
  onProgress(92);
  const elapsed = Math.max(Math.round(performance.now() - started), 1);
  const notes = [...new Set(result.notes)].slice(0, 24);

  return {
    filename: safeName,
    extension: ext,
    model: modelId,
    size: data.length,
    sha256,
    verdict: verdictFor(deduped),
    findings: deduped,
    scanned_entries: Math.max(result.entries, 1),
    analyzed_bytes: Math.min(data.length, ext === "exe" || ext === "dll" ? 2 * 1024 * 1024 : MAX_TEXT_BYTES),
    elapsed_ms: elapsed,
    notes,
  };
}

/** Сколько находок приходится на каждый уровень серьёзности. */
export function summarize(findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of findings) summary[item.severity] = (summary[item.severity] || 0) + 1;
  return summary;
}

export { CATALOG };
