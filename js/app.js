import { auth, db, ref, get, set, push, update, createUserWithEmailAndPassword, signInWithEmailAndPassword, signOut, onAuthStateChanged, ensureUserDoc, isBlockedName, toGmail, isAdminEmail } from "./firebase.js";
import { MODELS, PLANS, modelAllowsFile, limitFor, extOf } from "./plans.js";
import { scanFile } from "./engines/scanner.js";
import { renderAdmin } from "./admin.js";

const $ = s => document.querySelector(s);
let currentUser=null, userDoc=null;

function toast(msg, ok=true){ const t=$("#toast"); t.textContent=msg; t.className="toast show "+(ok?"ok":"err"); setTimeout(()=>t.className="toast",3200); }

// ---------- AUTH ----------
async function doAuth(mode){
  const { local, email } = toGmail($("#loginInput").value);
  const pass = $("#passInput").value;
  if(!/^[a-z0-9.]{3,30}$/.test(local)) return toast("Логин: 3–30 символов (a-z, 0-9, точка)", false);
  if(pass.length<6) return toast("Пароль минимум 6 символов", false);
  try{
    if(mode==="register"){
      if(isBlockedName(local, email)) return toast("Это имя пользователя запрещено 🚫", false);
      const cred = await createUserWithEmailAndPassword(auth, email, pass);
      await ensureUserDoc(cred.user); toast("Аккаунт создан! Добро пожаловать в XSafety ✅");
    } else {
      await signInWithEmailAndPassword(auth, email, pass); toast("Вход выполнен ✅");
    }
  }catch(e){ toast(authErr(e), false); }
}
function authErr(e){ const m={"auth/email-already-in-use":"Такой аккаунт уже есть","auth/invalid-credential":"Неверный логин или пароль","auth/wrong-password":"Неверный пароль","auth/user-not-found":"Аккаунт не найден","auth/too-many-requests":"Слишком много попыток, подожди","auth/network-request-failed":"Нет сети"}; return m[e.code]||e.message; }

onAuthStateChanged(auth, async user=>{
  currentUser=user;
  document.querySelectorAll(".view").forEach(v=>v.classList.add("hidden"));
  if(!user){ $("#authView").classList.remove("hidden"); $("#userBar").classList.add("hidden"); return; }
  userDoc = await ensureUserDoc(user);
  if(userDoc.banned){ await signOut(auth); $("#authView").classList.remove("hidden"); return toast("⛔ Ваш аккаунт заблокирован администратором", false); }
  $("#userBar").classList.remove("hidden");
  $("#userEmail").textContent=user.email;
  $("#userPlan").textContent = PLANS[userDoc.plan]?.name || "Default";
  const adminBtn=$("#adminBtn");
  const admin=isAdminEmail(user.email);
  adminBtn.classList.remove("hidden");
  adminBtn.disabled=!admin;
  adminBtn.classList.toggle("admin-disabled",!admin);
  adminBtn.title=admin?"":"Доступно только администратору";
  showView("scanView"); renderModels(); renderHistory();
  if(admin) renderAdmin(db, ref, get, update, toast);
});

// ---------- VIEWS ----------
function showView(id){ document.querySelectorAll(".view").forEach(v=>v.classList.add("hidden")); $("#"+id).classList.remove("hidden"); }
$("#navScan").onclick=()=>showView("scanView");
$("#navPlans").onclick=()=>showView("plansView");
$("#navHistory").onclick=()=>{showView("historyView"); renderHistory();};
$("#adminBtn").onclick=()=>{ if(!isAdminEmail((currentUser||{}).email)){ toast("Это только для администратора", false); return; } showView("adminView"); };
$("#logoutBtn").onclick=()=>signOut(auth);
$("#loginBtn").onclick=()=>doAuth("login");
$("#registerBtn").onclick=()=>doAuth("register");

// ---------- СКАНЕР ----------
let selectedModel="v1";
function remaining(modelId){
  const lim=limitFor(userDoc.plan, modelId); if(!lim) return -1;
  return lim.requests + (userDoc.extra?.[modelId]||0) - (userDoc.usage?.[modelId]||0);
}
function renderModels(){
  $("#modelGrid").innerHTML = Object.values(MODELS).map(m=>{
    const lim=limitFor(userDoc.plan, m.id); const rem=lim?remaining(m.id):-1;
    const locked=!lim;
    return `<button class="model-card ${selectedModel===m.id?"sel":""} ${locked?"locked":""}" data-model="${m.id}" ${locked?"disabled":""}>
      <h3>${m.name} ${locked?"🔒":""}</h3><p>${m.desc}</p>
      <span>${locked?`Недоступно на тарифе ${PLANS[userDoc.plan].name}`:`Осталось запросов: ${rem} • до ${lim.maxMB} МБ`}</span></button>`;
  }).join("");
  document.querySelectorAll("[data-model]").forEach(b=>b.onclick=()=>{selectedModel=b.dataset.model; renderModels();});
}
async function runScan(){
  const file=$("#fileInput").files[0]; if(!file) return toast("Выбери файл", false);
  const lim=limitFor(userDoc.plan, selectedModel); if(!lim) return toast("Модель недоступна на вашем тарифе 🔒", false);
  if(!modelAllowsFile(selectedModel, file.name)) return toast(`❌ ${MODELS[selectedModel].name} не сканирует .${extOf(file.name)}`, false);
  if(file.size > lim.maxMB*1024*1024) return toast(`❌ Файл больше лимита ${lim.maxMB} МБ для вашего тарифа`, false);
  if(remaining(selectedModel)<=0) return toast("❌ Запросы по этой модели закончились. Нужен тариф выше или лимиты от админа", false);
  $("#scanBtn").disabled=true; $("#result").innerHTML="";
  try{
    const res = await scanFile(file, selectedModel, p=>{ $("#progress").style.width=p+"%"; });
    // Списываем запрос и сохраняем результат в Realtime Database (если база отклонит — вердикт всё равно покажем)
    try{
      await update(ref(db,`users/${currentUser.uid}/usage`), { [selectedModel]:(userDoc.usage?.[selectedModel]||0)+1 });
      userDoc.usage[selectedModel]=(userDoc.usage?.[selectedModel]||0)+1;
      await push(ref(db,`scans/${currentUser.uid}`), res);
    }catch(e){ dbFail(e); }
    const cls = res.verdict==="ОПАСНО"?"bad":res.verdict==="ПОДОЗРИТЕЛЬНО"?"warn":"good";
    $("#result").innerHTML=`<div class="verdict ${cls}"><h2>${res.verdict==="ЧИСТО"?"✅":res.verdict==="ОПАСНО"?"🦠":"⚠️"} ${res.verdict} — ${res.score}/100</h2>
      <p>${escapeHtml(res.fileName)} • ${(res.size/1024).toFixed(1)} КБ • ${MODELS[selectedModel].name} • реальный тип: <b>${res.magic||'?'}</b> • энтропия ${res.entropy}</p>
      <p class="hash">SHA-256: ${res.sha256}</p>
      ${res.findings.length?`<ul>${res.findings.map(f=>`<li><b>[+${f.score}] ${f.cat}</b> — <code>${escapeHtml(f.detail)}</code></li>`).join("")}</ul>`:"<p>Опасных сигнатур не найдено.</p>"}</div>`;
    renderModels(); toast("Сканирование завершено");
  }catch(e){ toast("Ошибка сканирования: "+e.message, false); }
  finally{ $("#scanBtn").disabled=false; }
}
const escapeHtml=s=>s.replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
$("#scanBtn").onclick=runScan;

async function renderHistory(){
  if(!currentUser) return; const snap=await get(ref(db,`scans/${currentUser.uid}`));
  const items=snap.exists()?Object.values(snap.val()).sort((a,b)=>b.scannedAt-a.scannedAt):[];
  $("#historyList").innerHTML = items.length? items.map(r=>`<div class="hist"><b>${escapeHtml(r.fileName)}</b> — ${r.verdict} (${r.score}/100) • ${MODELS[r.model]?.name||r.model} • ${new Date(r.scannedAt).toLocaleString()}</div>`).join("") : "<p>История пуста</p>";
}
// Тарифы (статичный рендер)
$("#plansGrid").innerHTML = Object.entries(PLANS).map(([id,p])=>`<div class="plan"><h3>${p.name}</h3>${Object.entries(p.limits).map(([m,l])=>`<p>${MODELS[m].name}: ${l.requests} запросов, до ${l.maxMB} МБ</p>`).join("")||""}${id==="default"?"<p>Только XSafety 1 (.bat, .py)</p>":""}${id==="premium"?"<p>+ XSafety 3 Pro — любые файлы</p>":""}<small>Смена тарифа — через админа</small></div>`).join("");
