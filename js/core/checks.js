/* Исполнитель структурных проверок (PE, текст, обфускация).
 * Спецификации приходят из js/data/signatures/*.js: их генерирует
 * tools/build_web_data.py из тех же правил, что и Python-движок.
 */
import { importsAny } from "./pe.js";
import { allMatches, buildRegex, cleanText, entropy, redact, tryB64 } from "./text.js";

const TEXT_EXT = new Set([
  "bat", "cmd", "py", "pyw", "js", "mjs", "cjs", "ps1", "psm1", "vbs", "vbe",
  "hta", "txt", "md", "xml", "ini", "cfg", "json", "yaml", "yml",
]);

function finding(rule, overrides = {}) {
  return {
    sig_id: overrides.i || rule.i,
    title: overrides.t || rule.t,
    severity: overrides.s || rule.s,
    description: overrides.d || rule.d,
    evidence: cleanText(overrides.evidence || "", 180),
    offset: overrides.offset ?? null,
    entry: overrides.entry ?? null,
  };
}

function lower(text) {
  return text.toLowerCase();
}

function containsAny(text, needles) {
  return needles.filter((needle) => text.includes(String(needle).toLowerCase()));
}

function evidenceFor(spec, match, text) {
  if (!match) return "";
  if (spec.evidence === false) return "";
  return redact(text.slice(Math.max(match.index - 48, 0), match.index + match[0].length + 48));
}

function runText(rule, spec, ctx) {
  const text = ctx.text;
  const lowered = lower(text);
  const missing = (spec.all || []).filter((needle) => !lowered.includes(String(needle).toLowerCase()));
  if (missing.length) return [];
  if (spec.any_of && !containsAny(lowered, spec.any_of).length) return [];
  for (const pattern of spec.regex_all || []) {
    if (!buildRegex(pattern).test(text)) return [];
  }
  const anyHits = spec.any ? containsAny(lowered, spec.any) : [];
  if (spec.any && !anyHits.length) return [];

  let evidence = "";
  if (spec.regex_any) {
    for (const pattern of spec.regex_any) {
      const match = buildRegex(pattern).exec(text);
      if (match) {
        evidence = evidenceFor(spec, match, text);
        break;
      }
    }
  }
  if (!evidence && anyHits.length) evidence = cleanText(anyHits.slice(0, 3).join(", "), 160);
  return [finding(rule, { evidence, offset: offsetOf(ctx, 0) })];
}

function offsetOf(ctx, index) {
  if (!TEXT_EXT.has(ctx.ext) || index < 0) return null;
  const before = ctx.text.slice(0, index);
  return before.split("\n").length;
}

function runEicar(rule, spec, ctx) {
  const haystack = TEXT_EXT.has(ctx.ext) ? ctx.text : ctx.strings.join("\n");
  if (!haystack.includes(spec.needle)) return [];
  return [finding(rule, { evidence: spec.needle })];
}

function runB64(rule, spec, ctx) {
  const out = [];
  const regex = buildRegex(spec.regex || "[A-Za-z0-9+/=_-]{40,}");
  for (const match of allMatches(regex, ctx.text)) {
    const decoded = tryB64(match[0]);
    if (!decoded) continue;
    const lowered = decoded.toLowerCase();
    if (!spec.needles.some((needle) => lowered.includes(String(needle).toLowerCase()))) continue;
    out.push(finding(rule, { evidence: cleanText(decoded, 180) }));
    if (out.length >= (spec.max || 2)) break;
  }
  return out;
}

function runRegexHit(rule, spec, ctx) {
  for (const pattern of spec.regexes || []) {
    const match = buildRegex(pattern).exec(ctx.text);
    if (!match) continue;
    return [finding(rule, { evidence: match[0], offset: offsetOf(ctx, match.index) })];
  }
  return [];
}

function runMulti(rule, spec, ctx) {
  const out = [];
  for (const item of spec.items || []) {
    const matcher = item.m || {};
    let evidence = "";
    let hit = false;
    if (matcher.regex) {
      const regex = buildRegex(matcher.regex);
      if (matcher.min_hits) {
        const matches = allMatches(regex, ctx.text);
        hit = matches.length >= matcher.min_hits;
      } else {
        const match = regex.exec(ctx.text);
        hit = Boolean(match);
        if (match) evidence = matcher.evidence === "raw" ? match[0] : match[0].slice(0, 180);
      }
    } else if (matcher.all) {
      hit = matcher.all.every((needle) => ctx.text.toLowerCase().includes(String(needle).toLowerCase()));
      evidence = matcher.all[0] || "";
    }
    if (!hit) continue;
    out.push(finding(rule, { ...item, evidence: evidence || item.e || "" }));
  }
  return out;
}

function runPE(rule, spec, ctx) {
  const pe = ctx.pe;
  if (!pe) return [];

  switch (spec.kind) {
    case "pe_rwx": {
      if (!pe.rwxSections.length) return [];
      return [finding(rule, { evidence: pe.rwxSections.map((s) => s.name).join(", ") })];
    }
    case "pe_imports": {
      const found = importsAny(pe, spec.imports);
      if (found.length < spec.min) return [];
      let severity = rule.s;
      for (const [count, level] of Object.entries(spec.severity_at || {})) {
        if (found.length >= Number(count)) severity = level;
      }
      return [finding(rule, { severity, evidence: found.join(", ") })];
    }
    case "pe_packer": {
      const names = new Set(pe.sections.map((s) => s.name.toLowerCase()));
      const hit = spec.names.filter((name) => names.has(String(name).toLowerCase()));
      if (!hit.length) return [];
      return [finding(rule, { evidence: hit.join(", ") })];
    }
    case "pe_entropy": {
      for (const section of pe.sections) {
        if (section.rawSize < spec.min_raw || section.rawSize > spec.max_raw) continue;
        const chunk = ctx.data.subarray(section.rawOffset, section.rawOffset + section.rawSize);
        if (chunk.length < spec.min_raw) continue;
        const value = entropy(chunk);
        if (value < spec.threshold) continue;
        const evidence = spec.evidence === "entropy"
          ? `${section.name}: энтропия ${value.toFixed(2)}`
          : section.name;
        return [finding(rule, { evidence })];
      }
      return [];
    }
    case "pe_unsigned":
      return pe.hasSignature ? [] : [finding(rule)];
    case "pe_tls":
      return pe.hasTls ? [finding(rule)] : [];
    case "pe_dotnet":
      return pe.isDotnet ? [finding(rule)] : [];
    case "pe_entry": {
      if (!pe.sections.length || pe.entryPoint === 0) return [];
      for (const section of pe.sections) {
        const span = Math.max(section.virtualSize, section.rawSize);
        if (pe.entryPoint >= section.virtualAddress && pe.entryPoint < section.virtualAddress + span) {
          const isCode = spec.code_names.includes(section.name.toLowerCase());
          return isCode ? [] : [finding(rule, { evidence: section.name })];
        }
      }
      return [finding(rule, { ...spec.outside, evidence: "" })];
    }
    case "pe_strings": {
      const joined = pe.strings || ctx.strings.join("\n").toLowerCase();
      const out = [];
      for (const group of spec.groups || []) {
        const hit = group.tokens.filter((token) => joined.includes(String(token).toLowerCase()));
        if (!hit.length || hit.length < (group.min || 1)) continue;
        if (group.i === "dll.embedded_urls") {
          out.push(finding(rule, { ...group, evidence: "(адреса скрыты в отчёте)" }));
          continue;
        }
        out.push(finding(rule, { ...group, evidence: hit.slice(0, 4).join(", ") }));
      }
      return out;
    }
    case "pe_network_urls": {
      const imports = importsAny(pe, spec.imports);
      if (!imports.length) return [];
      const joined = ctx.strings.join("\n").toLowerCase();
      if (!spec.urls.some((url) => joined.includes(String(url).toLowerCase()))) return [];
      return [finding(rule, { evidence: imports.join(", ") })];
    }
    case "pe_overlay": {
      if (!pe.sections.length) return [];
      const end = Math.max(...pe.sections.map((s) => s.rawOffset + s.rawSize));
      if (end <= 0 || end >= ctx.data.length) return [];
      const overlay = ctx.data.length - end;
      if (overlay < spec.min_bytes) return [];
      return [finding(rule, { evidence: `${overlay} байт` })];
    }
    default:
      return [];
  }
}

/** Запускает одну структурную проверку. */
export function runCheck(rule, ctx) {
  const spec = rule.w;
  if (!spec) return [];
  switch (spec.kind) {
    case "eicar":
      return runEicar(rule, spec, ctx);
    case "b64_exec":
      return runB64(rule, spec, ctx);
    case "regex_hit":
      return runRegexHit(rule, spec, ctx);
    case "text_require":
      return runText(rule, spec, ctx);
    case "multi":
      return runMulti(rule, spec, ctx);
    default:
      if (String(spec.kind).startsWith("pe_")) return runPE(rule, spec, ctx);
      return [];
  }
}

export { finding, offsetOf };
