/* Firebase Auth + Realtime Database: аккаунты и история XSafety.
 * Все операции проходят через правила базы (database.rules.json).
 */
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import {
  createUserWithEmailAndPassword, getAuth, onAuthStateChanged,
  sendPasswordResetEmail, signInWithEmailAndPassword, signOut,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import {
  get, getDatabase, onValue, push, ref, runTransaction, set, update,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-database.js";
import { ADMIN_EMAIL, firebaseConfig } from "./firebase-config.js";

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getDatabase(app);

export {
  onAuthStateChanged, signInWithEmailAndPassword, createUserWithEmailAndPassword,
  signOut, sendPasswordResetEmail, ref, get, set, update, push, onValue, runTransaction,
};

export const isAdminEmail = (email) => (email || "").toLowerCase() === ADMIN_EMAIL.toLowerCase();

const LEET = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s" };

export function normalizeName(value) {
  return (value || "").toLowerCase().split("").map((char) => LEET[char] || char).join("").replace(/[^a-z]/g, "");
}

/** Запрет регистрации имён, похожих на владельца (кроме самого владельца). */
export function isBlockedName(localPart, fullEmail) {
  if (isAdminEmail(fullEmail)) return false;
  const name = normalizeName(localPart);
  return ["koteyca", "koteuca", "koteyka", "koteika"].some((needle) => name.includes(needle));
}

/** «ivan.petrov» → ivan.petrov@gmail.com; полный адрес тоже принимается. */
export function toGmail(raw) {
  let value = (raw || "").trim().toLowerCase();
  if (value.includes("@")) value = value.split("@")[0];
  return { local: value, email: `${value}@gmail.com` };
}

export function authErrorMessage(error) {
  const messages = {
    "auth/email-already-in-use": "Такой аккаунт уже есть — войдите",
    "auth/invalid-credential": "Неверный логин или пароль",
    "auth/invalid-login-credentials": "Неверный логин или пароль",
    "auth/wrong-password": "Неверный пароль",
    "auth/user-not-found": "Аккаунт не найден",
    "auth/weak-password": "Слишком простой пароль",
    "auth/too-many-requests": "Слишком много попыток, попробуйте позже",
    "auth/network-request-failed": "Нет связи с Firebase",
    "auth/operation-not-allowed": "Вход по паролю отключён в Firebase",
  };
  return messages[error?.code] || error?.message || "Неизвестная ошибка";
}

const DEFAULT_USAGE = {};

/** Создаёт профиль при первом входе и приводит старую схему к новой. */
export async function ensureUserDoc(user) {
  const reference = ref(db, `users/${user.uid}`);
  const snapshot = await get(reference);
  if (!snapshot.exists()) {
    const profile = {
      email: user.email,
      plan: "default",
      planUntil: null,
      planOffer: null,
      banned: false,
      createdAt: Date.now(),
      usage: {},
      extra: { m1: 0, m2: 0, m3_lite: 0, m3_pro: 0 },
    };
    await set(reference, profile);
    return profile;
  }
  const profile = snapshot.val() || {};
  const patch = {};
  if (!profile.usage || typeof profile.usage !== "object") patch.usage = {};
  if (!profile.extra) patch.extra = { m1: 0, m2: 0, m3_lite: 0, m3_pro: 0 };
  if (typeof profile.banned !== "boolean") patch.banned = false;
  if (profile.plan !== "default" && profile.plan !== "pro" && profile.plan !== "premium") patch.plan = "default";
  if (Object.keys(patch).length) await update(reference, patch);
  return { ...profile, ...patch };
}

export async function loadProfile(uid) {
  const snapshot = await get(ref(db, `users/${uid}`));
  return snapshot.exists() ? snapshot.val() : null;
}

/** Атомарно списывает запрос и объём; возвращает актуальный счётчик. */
export async function consumeUsage(uid, modelId, period, bytes, limit) {
  const reference = ref(db, `users/${uid}/usage/${modelId}`);
  const result = await runTransaction(reference, (current) => {
    const state = current && typeof current === "object"
      ? current
      : { count: Number(current) || 0, bytes: 0, period };
    const normalized = state.period === period ? state : { count: 0, bytes: 0, period };
    if (limit !== null && normalized.count >= limit) return; // лимит исчерпан — отменяем
    return { count: normalized.count + 1, bytes: (normalized.bytes || 0) + bytes, period };
  });
  return result.committed ? result.snapshot.val() : null;
}

export async function saveScan(uid, result) {
  const reference = push(ref(db, `scans/${uid}`));
  const payload = { ...result, scannedAt: Date.now() };
  await set(reference, payload);
  return { id: reference.key, ...payload };
}

export async function loadScans(uid, limit = 100) {
  const snapshot = await get(ref(db, `scans/${uid}`));
  if (!snapshot.exists()) return [];
  const items = Object.entries(snapshot.val()).map(([id, value]) => ({ id, ...value }));
  items.sort((a, b) => (b.scannedAt || 0) - (a.scannedAt || 0));
  return items.slice(0, limit);
}

export async function deleteScan(uid, id) {
  const { remove } = await import("https://www.gstatic.com/firebasejs/10.12.2/firebase-database.js");
  await remove(ref(db, `scans/${uid}/${id}`));
}

export async function savePurchase(uid, purchase) {
  await push(ref(db, `purchases/${uid}`), { ...purchase, createdAt: Date.now() });
}

export async function applyPlan(uid, plan, planUntil, planOffer) {
  await update(ref(db, `users/${uid}`), { plan, planUntil: planUntil ?? null, planOffer: planOffer ?? null });
}

export async function resetUsage(uid) {
  await update(ref(db, `users/${uid}`), { usage: DEFAULT_USAGE });
}

export async function setBanned(uid, banned) {
  await update(ref(db, `users/${uid}`), { banned: Boolean(banned) });
}
