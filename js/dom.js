/* Мелкие помощники DOM. Только textContent и свойства — никакого innerHTML
 * с данными из файлов (защита от XSS, см. SECURITY.md).
 */
export const $ = (selector, scope = document) => scope.querySelector(selector);
export const $$ = (selector, scope = document) => [...scope.querySelectorAll(selector)];

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key === "style") Object.assign(node.style, value);
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else if (value === true) node.setAttribute(key, "");
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

export function bytes(value) {
  if (!Number.isFinite(value) || value < 0) return "—";
  if (value < 1024) return `${value} Б`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} КБ`;
  return `${(value / (1024 * 1024)).toFixed(2)} МБ`;
}

export function timeLeft(timestamp, now = Date.now()) {
  if (!timestamp) return "—";
  const diff = timestamp - now;
  if (diff <= 0) return "обновляется";
  const total = Math.floor(diff / 1000);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  return `${hours} ч ${String(minutes).padStart(2, "0")} мин ${String(seconds).padStart(2, "0")} с`;
}

export function formatDate(timestamp) {
  if (!timestamp) return "—";
  return new Date(timestamp).toLocaleString("ru-RU", {
    day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ESCAPES[char]);

let toastTimer = null;
export function toast(message, ok = true) {
  const node = $("#toast");
  if (!node) return;
  node.textContent = message;
  node.className = `toast show ${ok ? "ok" : "err"}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.className = "toast"; }, 4200);
}

let modalResolve = null;
export function modal({ title, body, ok = "Подтвердить", cancel = "Отмена" }) {
  const root = $("#modal");
  $("#modalTitle").textContent = title;
  const bodyNode = clear($("#modalBody"));
  if (typeof body === "string") bodyNode.textContent = body;
  else if (body instanceof Node) bodyNode.append(body);
  $("#modalOk").textContent = ok;
  $("#modalCancel").textContent = cancel;
  root.classList.remove("hidden");
  return new Promise((resolve) => {
    modalResolve = resolve;
  });
}

export function closeModal(result) {
  $("#modal").classList.add("hidden");
  if (modalResolve) {
    const resolve = modalResolve;
    modalResolve = null;
    resolve(result);
  }
}

export function initModal() {
  $("#modalOk").addEventListener("click", () => closeModal(true));
  $("#modalCancel").addEventListener("click", () => closeModal(false));
  $("#modal").addEventListener("click", (event) => {
    if (event.target.id === "modal") closeModal(false);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !$("#modal").classList.contains("hidden")) closeModal(false);
  });
}

export function severityLabel(severity) {
  return {
    critical: "Критическая", high: "Высокая", medium: "Средняя",
    low: "Низкая", info: "Информация",
  }[severity] || severity;
}

export function verdictLabel(verdict) {
  return { malicious: "Опасно", suspicious: "Подозрительно", clean: "Чисто" }[verdict] || verdict;
}
