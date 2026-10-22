import { PLANS, MODELS } from "./plans.js";
// Админ-панель: пользователи, подписки, бан/разбан, лимиты
export function renderAdmin(db, ref, get, update, toast){
  const box = document.getElementById("adminList");
  async function load(){
    let snap;
    try{ snap = await get(ref(db, "users")); }
    catch(e){ console.warn("[XSafety] admin:", e.code||e.message); box.innerHTML="<p>⚠️ Админка не может прочитать пользователей: в Firebase не опубликованы правила из <b>firebase.rules.json</b> (Realtime Database → Rules → Publish). Доступ к списку есть только у Koteyca@gmail.com.</p>"; return; }
    if(!snap.exists()){ box.innerHTML="<p>Пользователей нет</p>"; return; }
    const users = Object.entries(snap.val());
    box.innerHTML = users.map(([uid,u])=>`<div class="admin-row">
      <div><b>${u.email}</b> ${u.banned?'⛔ <span class="red">ЗАБАНЕН</span>':""}<br>
      <small>Подписка: <b>${PLANS[u.plan]?.name||u.plan}</b> • Использовано: ${Object.entries(u.usage||{}).map(([m,c])=>`${MODELS[m]?.name||m}: ${c}`).join(", ")||"0"} • Доп. лимиты: ${Object.entries(u.extra||{}).filter(([,v])=>v>0).map(([m,c])=>`${m}:+${c}`).join(", ")||"нет"}</small></div>
      <div class="admin-actions">
        <select data-plan="${uid}">${Object.keys(PLANS).map(p=>`<option value="${p}" ${p===u.plan?"selected":""}>${PLANS[p].name}</option>`).join("")}</select>
        <button data-setplan="${uid}">💎 Выдать подписку</button>
        <button data-add="${uid}">➕ +5 запросов (модель из списка ниже)</button>
        <select data-addmodel="${uid}">${Object.keys(MODELS).map(m=>`<option value="${m}">${MODELS[m].name}</option>`).join("")}</select>
        <button data-reset="${uid}">♻️ Сбросить лимиты</button>
        <button data-ban="${uid}" class="${u.banned?"":"danger"}">${u.banned?"✅ Разбанить":"⛔ Забанить"}</button>
      </div></div>`).join("");
    box.querySelectorAll("[data-setplan]").forEach(b=>b.onclick=async()=>{ const uid=b.dataset.setplan; const plan=box.querySelector(`[data-plan="${uid}"]`).value; await update(ref(db,`users/${uid}`),{plan}); toast(`Подписка ${PLANS[plan].name} выдана`); load(); });
    box.querySelectorAll("[data-add]").forEach(b=>b.onclick=async()=>{ const uid=b.dataset.add; const m=box.querySelector(`[data-addmodel="${uid}"]`).value; const snap2=await get(ref(db,`users/${uid}/extra/${m}`)); await update(ref(db,`users/${uid}/extra`),{[m]:(snap2.val()||0)+5}); toast("+5 запросов добавлено"); load(); });
    box.querySelectorAll("[data-reset]").forEach(b=>b.onclick=async()=>{ await update(ref(db,`users/${b.dataset.reset}`),{usage:{v1:0,v2:0,lite:0,pro:0}}); toast("Лимиты сброшены"); load(); });
    box.querySelectorAll("[data-ban]").forEach(b=>b.onclick=async()=>{ const uid=b.dataset.ban; const s=await get(ref(db,`users/${uid}/banned`)); await update(ref(db,`users/${uid}`),{banned:!s.val()}); toast(s.val()?"Пользователь разбанен":"Пользователь забанен"); load(); });
  }
  load();
  document.getElementById("adminRefresh").onclick=load;
}
