/* Автогенерация: python3 tools/build_web_data.py — не редактировать вручную. */
import bat from "./bat.js";
import cjs from "./cjs.js";
import cmd from "./cmd.js";
import dll from "./dll.js";
import exe from "./exe.js";
import hta from "./hta.js";
import jar from "./jar.js";
import js from "./js.js";
import mjs from "./mjs.js";
import ps1 from "./ps1.js";
import psm1 from "./psm1.js";
import py from "./py.js";
import pyw from "./pyw.js";
import vbe from "./vbe.js";
import vbs from "./vbs.js";
import zip from "./zip.js";

const GROUPS = [bat, cjs, cmd, dll, exe, hta, jar, js, mjs, ps1, psm1, py, pyw, vbe, vbs, zip];

// Правило может относиться к нескольким расширениям — оставляем по одному экземпляру.
const registry = new Map();
for (const group of GROUPS) {
  for (const rule of group) if (!registry.has(rule.i)) registry.set(rule.i, rule);
}

export const SIGNATURES = [...registry.values()];
export const RULE_COUNT = 127;
export const COUNTS = {"bat": 30, "cjs": 18, "cmd": 23, "dll": 18, "exe": 19, "hta": 44, "jar": 7, "js": 25, "mjs": 18, "ps1": 29, "psm1": 22, "py": 27, "pyw": 20, "vbe": 14, "vbs": 21, "zip": 7};
