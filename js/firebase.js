import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, signOut, onAuthStateChanged }
  from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import { getDatabase, ref, get, set, update, push, onValue }
  from "https://www.gstatic.com/firebasejs/10.12.2/firebase-database.js";
import { firebaseConfig, ADMIN_EMAIL } from "./firebase-config.js";

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getDatabase(app);
export { ref, get, set, update, push, onValue, createUserWithEmailAndPassword, signInWithEmailAndPassword, signOut, onAuthStateChanged, ADMIN_EMAIL };
export const isAdminEmail = e => (e||"").toLowerCase() === ADMIN_EMAIL.toLowerCase();

const LEET = {"0":"o","1":"i","3":"e","4":"a","5":"s","7":"t","@":"a","$":"s"};
export function normalizeName(s){ return (s||"").toLowerCase().split("").map(c=>LEET[c]||c).join("").replace(/[^a-z]/g,""); }
// Запрет регистрации «похожих на Koteyca». Точный админский адрес — исключение (это сам владелец).
export function isBlockedName(localPart, fullEmail){
  if (isAdminEmail(fullEmail)) return false;
  const n = normalizeName(localPart);
  return n.includes("Koteyca") || n.includes("koteuca") || n.includes("koteyka");
}
export function toGmail(raw){
  let v = (raw||"").trim().toLowerCase();
  if (v.includes("@")) v = v.split("@")[0];           // если ввели полный адрес — отрежем домен
  return { local: v, email: v + "@gmail.com" };        // Gmail подставляется автоматически
}
export async function ensureUserDoc(user){
  const r = ref(db, `users/${user.uid}`); const snap = await get(r);
  if (!snap.exists()){
    await set(r, { email:user.email, plan:"default", banned:false, createdAt:Date.now(),
      usage:{v1:0,v2:0,lite:0,pro:0}, extra:{v1:0,v2:0,lite:0,pro:0} });
    return (await get(r)).val();
  }
  return snap.val();
}
