/* Сканирует набор образцов браузерным движком и пишет результат в JSON.
 * Запускается из pytest (tests/test_web_parity.py), чтобы сверять движки.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { scanFile } from "../../js/core/engine.js";

const [, , casesPath, outPath] = process.argv;
if (!casesPath || !outPath) {
  console.error("usage: node tests/web/scan_cases.mjs <cases.json> <out.json>");
  process.exit(2);
}

const cases = JSON.parse(readFileSync(casesPath, "utf8"));
const results = [];

for (const item of cases) {
  const bytes = Uint8Array.from(Buffer.from(item.data, "base64"));
  try {
    const result = await scanFile(bytes, item.name, item.model);
    results.push({
      name: item.name,
      ok: true,
      verdict: result.verdict,
      sig_ids: [...new Set(result.findings.map((finding) => finding.sig_id))].sort(),
      findings: result.findings.length,
      notes: result.notes,
      sha256: result.sha256,
      extension: result.extension,
      size: result.size,
    });
  } catch (error) {
    results.push({ name: item.name, ok: false, code: error.code || "error", message: error.message });
  }
}

writeFileSync(outPath, JSON.stringify(results, null, 2));
console.log(`просканировано: ${results.length}`);
