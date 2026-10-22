/* Текст, строки, энтропия, редакция секретов и вердикт.
 * Зеркало xsafety/scan/textutil.py и xsafety/scan/sigutil.py.
 */

const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g;
const utf8 = new TextDecoder("utf-8", { fatal: false });
let cp1251 = null;

/** Убирает управляющие символы и обрезает строку. */
export function cleanText(value, limit = 200) {
  if (!value) return "";
  let text = String(value).replace(CONTROL, "").replace(/\s+/g, " ").trim();
  if (text.length > limit) text = text.slice(0, limit - 1).trimEnd() + "…";
  return text;
}

/** Декодирует байты с учётом BOM, UTF-8 и CP1251. */
export function decodeText(bytes) {
  if (!bytes || bytes.length === 0) return "";
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return utf8.decode(bytes.subarray(3));
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return new TextDecoder("utf-16le").decode(bytes.subarray(2));
  if (bytes[0] === 0xfe && bytes[1] === 0xff) {
    const swapped = new Uint8Array(bytes.length - 2);
    for (let i = 2; i + 1 < bytes.length; i += 2) {
      swapped[i - 2] = bytes[i + 1];
      swapped[i - 1] = bytes[i];
    }
    return new TextDecoder("utf-16le").decode(swapped);
  }
  const text = utf8.decode(bytes);
  const bad = (text.match(/\uFFFD/g) || []).length;
  if (bad > Math.max(4, text.length * 0.02)) {
    try {
      cp1251 = cp1251 || new TextDecoder("windows-1251");
      return cp1251.decode(bytes);
    } catch {
      return text;
    }
  }
  return text;
}

/** ASCII и UTF-16LE строки длиной не меньше `min`. */
export function iterStrings(bytes, min = 4, limit = 4000) {
  const out = [];
  let current = "";
  for (const byte of bytes) {
    if (byte >= 32 && byte < 127) current += String.fromCharCode(byte);
    else {
      if (current.length >= min) out.push(current);
      current = "";
      if (out.length >= limit) return out;
    }
  }
  if (current.length >= min) out.push(current);

  let wide = "";
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    const low = bytes[i];
    const high = bytes[i + 1];
    if (high === 0 && low >= 32 && low < 127) wide += String.fromCharCode(low);
    else {
      if (wide.length >= min) out.push(wide);
      wide = "";
      if (out.length >= limit) return out;
    }
  }
  if (wide.length >= min) out.push(wide);
  return out;
}

export function entropy(bytes) {
  if (!bytes || !bytes.length) return 0;
  const counts = new Float64Array(256);
  for (const byte of bytes) counts[byte] += 1;
  let result = 0;
  for (const count of counts) {
    if (!count) continue;
    const p = count / bytes.length;
    result -= p * Math.log2(p);
  }
  return result;
}

export function lineNumber(text, offset) {
  if (offset <= 0) return 1;
  let lines = 1;
  const end = Math.min(offset, text.length);
  for (let i = 0; i < end; i++) if (text.charCodeAt(i) === 10) lines++;
  return lines;
}

export function windowAround(text, start, end, pad = 48) {
  const left = Math.max(start - pad, 0);
  const right = Math.min(end + pad, text.length);
  return cleanText(text.slice(left, right), 180);
}

const KEY_VALUE = /\b(password|passwd|pwd|secret|token|api[_-]?key)(\s*[:=]\s*)(['"]?)([^'"\s]{3,64})/gi;
const BEARER = /\b(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})/g;
const URL_USERINFO = /\b([a-z][a-z0-9+.-]*:\/\/)([^/\s:@]{1,64}):[^/\s@]+@/gi;
const TOKEN_IN_URL = /([?&](?:token|key|api_key|apikey|access_token|password)=)([^&\s#]{3,})/gi;

function mask(value) {
  return value.length <= 8 ? "***" : value.slice(0, 2) + "***";
}

/** Вырезает пароли и токены из фрагмента перед показом пользователю. */
export function redact(text) {
  if (!text) return "";
  return text
    .replace(KEY_VALUE, (_, key, sep, quote, value) => `${key}${sep}${quote}${mask(value)}`)
    .replace(BEARER, (_, prefix, value) => `${prefix}${mask(value)}`)
    .replace(URL_USERINFO, (_, prefix, user) => `${prefix}${mask(user)}:***@`)
    .replace(TOKEN_IN_URL, (_, prefix) => `${prefix}***`);
}

export function safeEvidence(text, start, end) {
  return redact(windowAround(text, start, end));
}

const REGEX_CACHE = new Map();

/** Компилирует регулярку сигнатуры (Python-флаги перенесены в генераторе). */
export function buildRegex(pattern, flags = "") {
  const key = flags + "\u0000" + pattern;
  if (REGEX_CACHE.has(key)) return REGEX_CACHE.get(key);
  let final = flags;
  for (const required of ["i", "m"]) if (!final.includes(required)) final += required;
  const compiled = new RegExp(pattern, final);
  REGEX_CACHE.set(key, compiled);
  return compiled;
}

export function allMatches(regex, text, limit = 40) {
  const flags = regex.flags.includes("g") ? regex.flags : regex.flags + "g";
  const scanner = new RegExp(regex.source, flags);
  const out = [];
  let match;
  while ((match = scanner.exec(text)) !== null) {
    out.push(match);
    if (out.length >= limit) break;
    if (match[0] === "") scanner.lastIndex++;
  }
  return out;
}

const B64_SHAPE = /^[A-Za-z0-9+/=_-]{16,}$/;

/** Мягкое декодирование base64 в печатный текст (или null). */
export function tryB64(chunk, maxBytes = 65536) {
  const compact = String(chunk || "").replace(/\s+/g, "").slice(0, maxBytes * 2);
  if (!compact || !B64_SHAPE.test(compact)) return null;
  const normalized = compact.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch {
    return null;
  }
  if (!binary) return null;
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const bad = (text.match(/\uFFFD/g) || []).length;
  if (bad > text.length * 0.3) return null;
  const printable = text.replace(/[\x20-\x7e\u0400-\u04ff\r\n\t]/g, "").length;
  if (printable > text.length * 0.4) return null;
  return text;
}

const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export const SEVERITY_LABEL = { info: "Информация", low: "Низкая", medium: "Средняя", high: "Высокая", critical: "Критическая" };

export function verdictFor(findings) {
  let worst = "info";
  for (const finding of findings) {
    if ((RANK[finding.severity] ?? 0) > (RANK[worst] ?? 0)) worst = finding.severity;
  }
  if ((RANK[worst] ?? 0) >= RANK.high) return "malicious";
  if ((RANK[worst] ?? 0) >= RANK.low) return "suspicious";
  return "clean";
}

export async function sha256Hex(bytes) {
  try {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    let hash = 0;
    for (const byte of bytes) hash = (hash * 31 + byte) >>> 0;
    return "fallback-" + hash.toString(16).padStart(8, "0");
  }
}
