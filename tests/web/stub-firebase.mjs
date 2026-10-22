/* Заглушки Firebase для тестов интерфейса в Node (jsdom).
 * Повторяют только те функции, которые использует сайт.
 */
export const store = { data: {} };
export const listeners = {};
export let currentUser = null;

function split(path) {
  return String(path).split("/").filter(Boolean);
}

function readPath(path) {
  let node = store.data;
  for (const key of split(path)) {
    if (node === undefined || node === null) return undefined;
    node = node[key];
  }
  return node;
}

function writePath(path, value) {
  const keys = split(path);
  if (!keys.length) {
    store.data = value ?? {};
    return;
  }
  let node = store.data;
  for (const key of keys.slice(0, -1)) {
    if (!node[key] || typeof node[key] !== "object") node[key] = {};
    node = node[key];
  }
  const last = keys[keys.length - 1];
  if (value === null || value === undefined) delete node[last];
  else node[last] = value;
}

export const initializeApp = () => ({});
export const getAuth = () => ({});
export const getDatabase = () => ({});
export const ref = (_db, path) => ({ path });
export const push = (reference) => {
  const key = `key${Math.random().toString(36).slice(2, 8)}`;
  return { path: `${reference.path}/${key}`, key };
};
export const get = async (reference) => {
  const value = readPath(reference.path);
  return { exists: () => value !== undefined, val: () => value ?? null };
};
export const set = async (reference, value) => writePath(reference.path, value);
export const remove = async (reference) => writePath(reference.path, null);
export const update = async (reference, patch) => {
  for (const [key, value] of Object.entries(patch)) writePath(`${reference.path}/${key}`, value);
};
export const onValue = (reference, callback) => {
  callback(awaitValue(reference));
};
function awaitValue(reference) {
  const value = readPath(reference.path);
  return { exists: () => value !== undefined, val: () => value ?? null };
}
export const runTransaction = async (reference, handler) => {
  const current = readPath(reference.path) ?? null;
  const next = handler(current);
  if (next === undefined) return { committed: false, snapshot: { val: () => current } };
  writePath(reference.path, next);
  return { committed: true, snapshot: { val: () => next } };
};

export const auth = {};
export const db = {};

export const onAuthStateChanged = (_auth, callback) => {
  listeners.auth = callback;
  queueMicrotask(() => callback(currentUser));
  return () => {};
};

export function signInForTest(user) {
  currentUser = user;
  if (listeners.auth) listeners.auth(user);
}

export function signOutForTest() {
  currentUser = null;
  if (listeners.auth) listeners.auth(null);
}

export const signInWithEmailAndPassword = async () => ({ user: currentUser });
export const createUserWithEmailAndPassword = async () => ({ user: currentUser });
export const signOut = async () => signOutForTest();
export const sendPasswordResetEmail = async () => true;
