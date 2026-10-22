/* LDR — декодер сигнатур XSafety.
 *
 * Паттерны правил и тексты хранятся в репозитории в виде токенов
 * (urlsafe-base64 от XOR с ключом) и разворачиваются при загрузке модуля.
 * Это обфускация, а не шифрование: ключ лежит здесь же.
 */
const KEY = Uint8Array.from("f5bb863795b026ba6c956c5e844c0cb9d4d5d1fbf0330651220dbde9189aaf77".match(/../g), h => parseInt(h, 16));
const decoder = new TextDecoder("utf-8", { fatal: false });

function xor(bytes) {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ KEY[i % KEY.length];
  return out;
}

function toBytes(token) {
  const normalized = token.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return xor(bytes);
}

/** Декодирует текстовый LDR-маркер. */
export function L(token) {
  return decoder.decode(toBytes(token));
}

/** Декодирует бинарный LDR-маркер. */
export function B(token) {
  return toBytes(token);
}

/** Декодирует LDR-маркер с JSON-полезной нагрузкой. */
export function D(token) {
  return JSON.parse(L(token));
}

/** Кодирует строку (используется тестами и отладкой). */
export function encodeText(value) {
  const raw = new TextEncoder().encode(value);
  const mixed = xor(raw);
  let binary = "";
  for (const byte of mixed) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
