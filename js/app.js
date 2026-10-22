/* XSafety — интерфейс статической версии.
 * Всё выполняется в браузере: файл читается локально, в Firebase уходят
 * только метаданные отчёта (имя, хэш, вердикт, находки).
 */
import {
  applyPlan, auth, consumeUsage, createUserWithEmailAndPassword, deleteScan, ensureUserDoc,
  isAdminEmail, isBlockedName, loadProfile, loadScans, onAuthStateChanged, savePurchase,
  saveScan, signInWithEmailAndPassword, signOut, toGmail, authErrorMessage,
} from "./firebase.js";
import { renderAdmin } from "./admin.js";
import { scanFile, ScanError } from "./core/engine.js";
import {
  $, $$, bytes, clear, el, escapeHtml, formatDate, initModal, modal, severityLabel,
  timeLeft, toast, verdictLabel,
} from "./dom.js";
import {
  CATALOG, MODELS, MODELS_BY_ID, PLANS, REFILL_HOURS, formatMoney, modelState,
  nextReset, periodStart, planInfo, quotaSnapshot, validateFile,
} from "./plans.js";

const state = {
  user: null,
  profile: null,
  selectedModel: "m1",
  file: null,
  busy: false,
  lastResult: null,
  lastRefillRefresh: 0,
  scans: [],
};

initModal();

/* ---------------------------------------------------------------- auth --- */

function showView(id) {
  $$(".view").forEach((view) => view.classList.toggle("hidden", view.id !== id));
  $$(".nav-btn").forEach((button) => {
    button.classList.toggle("is-active", button.id === { scanView: "navScan", plansView: "navPlans", historyView: "navHistory", adminView: "adminBtn" }[id]);
  });
  if (location.hash !== `#${id.replace("View", "")}`) history.replaceState(null, "", `#${id.replace("View", "")}`);
}

async function doAuth(mode) {
  const { local, email } = toGmail($("#loginInput").value);
  const password = $("#passInput").value;
  if (!/^[a-z0-9.]{3,30}$/.test(local)) return toast("Логин: 3–30 символов, латиница, цифры и точка", false);
  if (password.length < 6) return toast("Пароль минимум 6 символов", false);
  try {
    if (mode === "register") {
      if (isBlockedName(local, email)) return toast("Это имя пользователя запрещено", false);
      const credentials = await createUserWithEmailAndPassword(auth, email, password);
      await ensureUserDoc(credentials.user);
      toast("Аккаунт создан — добро пожаловать в XSafety");
    } else {
      await signInWithEmailAndPassword(auth, email, password);
      toast("Вход выполнен");
    }
  } catch (error) {
    toast(authErrorMessage(error), false);
  }
}

$("#loginBtn").addEventListener("click", () => doAuth("login"));
$("#registerBtn").addEventListener("click", () => doAuth("register"));
$("#authForm").addEventListener("submit", (event) => {
  event.preventDefault();
  doAuth("login");
});
$("#logoutBtn").addEventListener("click", () => signOut(auth));

function planExpired(profile) {
  return Boolean(profile?.planUntil && profile.planUntil < Date.now());
}

async function applyExpiry(profile) {
  if (!planExpired(profile) || profile.plan === "default") return profile;
  await applyPlan(profile.uid, "default", null, null);
  return { ...profile, plan: "default", planUntil: null, planOffer: null };
}

onAuthStateChanged(auth, async (user) => {
  state.user = user;
  if (!user) {
    state.profile = null;
    $("#userBar").classList.add("hidden");
    $("#accountBar").classList.add("hidden");
    showView("authView");
    return;
  }
  try {
    let profile = await ensureUserDoc(user);
    profile = await applyExpiry({ ...profile, uid: user.uid });
    if (profile.banned) {
      await signOut(auth);
      toast("Аккаунт заблокирован администратором", false);
      return;
    }
    state.profile = { ...profile, uid: user.uid };
    $("#userBar").classList.remove("hidden");
    $("#accountBar").classList.remove("hidden");
    $("#userEmail").textContent = user.email;
    $("#userPlan").textContent = planInfo(profile.plan).name;
    const admin = isAdminEmail(user.email);
    const adminBtn = $("#adminBtn");
    adminBtn.classList.toggle("hidden", !admin);
    adminBtn.disabled = !admin;
    renderModels();
    renderPricing();
    renderModelInfo();
    showView("scanView");
    const hash = (location.hash || "").replace("#", "");
    if (hash === "plans") showView("plansView");
    else if (hash === "history") {
      showView("historyView");
      loadHistory();
    } else if (hash === "admin" && admin) {
      showView("adminView");
      renderAdminPanel();
    }
  } catch (error) {
    toast(`Не удалось загрузить профиль: ${error.message}`, false);
  }
});

/* -------------------------------------------------------------- scanner --- */

function modelCard(model) {
  const snapshot = modelState(state.profile, model.id);
  const percent = snapshot.requests_limit
    ? Math.min((snapshot.requests_used / snapshot.requests_limit) * 100, 100)
    : 0;
  const barClass = percent >= 100 ? "bad" : percent >= 70 ? "warn" : "";
  const limitText = snapshot.available
    ? `Осталось ${snapshot.requests_left} из ${snapshot.requests_limit}${snapshot.mb_limit ? ` · до ${snapshot.mb_limit} МБ` : ""}`
    : "Не входит в тариф";

  const card = el("button", {
    type: "button",
    class: `model-card${state.selectedModel === model.id ? " sel" : ""}${snapshot.blocked ? " locked" : ""}`,
    dataset: { model: model.id },
    "aria-pressed": state.selectedModel === model.id ? "true" : "false",
    "aria-disabled": snapshot.blocked ? "true" : "false",
  },
    el("h3", {}, model.name, snapshot.blocked ? el("span", { class: "tag lock", text: "нет лимитов" }) : null),
    el("span", { class: "exts", text: model.extensions.map((ext) => `.${ext}`).join(" ") }),
    el("span", { class: "limit", text: limitText }),
    snapshot.available
      ? el("span", { class: "bar" }, el("i", { class: barClass, style: { width: `${percent}%` } }))
      : el("span", { class: "tag lock", text: "лимиты не начисляются" }),
  );
  card.addEventListener("click", () => {
    if (snapshot.blocked) {
      toast(`Модель ${model.name} доступна на тарифе ${planNameFor(model.id)}`, false);
      return;
    }
    state.selectedModel = model.id;
    renderModels();
    updateDropHint();
  });
  return card;
}

function planNameFor(modelId) {
  const plans = CATALOG.plans.filter((plan) => plan.limits[modelId]);
  if (!plans.length) return "выше";
  return plans.map((plan) => plan.name).join(" или ");
}

function renderModels() {
  if (!state.profile) return;
  const grid = clear($("#modelGrid"));
  for (const model of MODELS) grid.append(modelCard(model));
  const current = modelState(state.profile, state.selectedModel);
  if (current.blocked) {
    const first = MODELS.map((model) => modelState(state.profile, model.id)).find((item) => item.available);
    if (first) {
      state.selectedModel = first.model_id;
      renderModels();
      return;
    }
  }
  $("#refillTime").textContent = timeLeft(nextReset());
  updateDropHint();
}

function updateDropHint() {
  const snapshot = modelState(state.profile, state.selectedModel);
  const model = MODELS_BY_ID.get(state.selectedModel);
  $("#dropHint").textContent = snapshot.blocked
    ? "Модель недоступна на тарифе"
    : `${model.name}: ${model.extensions.map((ext) => `.${ext}`).join(", ")}${snapshot.mb_limit ? ` · до ${snapshot.mb_limit} МБ` : ""}`;
}

function pickFile(file) {
  state.file = file || null;
  $("#fileName").textContent = file ? `${file.name} · ${bytes(file.size)}` : "";
}

$("#dropZone").addEventListener("click", () => $("#fileInput").click());
$("#dropZone").addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    $("#fileInput").click();
  }
});
$("#fileInput").addEventListener("change", (event) => pickFile(event.target.files[0]));
for (const type of ["dragenter", "dragover"]) {
  $("#dropZone").addEventListener(type, (event) => {
    event.preventDefault();
    $("#dropZone").classList.add("drag");
  });
}
for (const type of ["dragleave", "drop"]) {
  $("#dropZone").addEventListener(type, (event) => {
    event.preventDefault();
    $("#dropZone").classList.remove("drag");
  });
}
$("#dropZone").addEventListener("drop", (event) => {
  const file = event.dataTransfer?.files?.[0];
  if (file) pickFile(file);
});

function progress(value) {
  $("#progress").style.width = `${value}%`;
}

function findingCard(finding) {
  return el("li", { class: `finding ${finding.severity}` },
    el("div", { class: "head" },
      el("strong", { text: finding.title }),
      el("span", { class: "sev", text: severityLabel(finding.severity) }),
    ),
    finding.entry ? el("p", { text: `Внутри: ${finding.entry}` }) : null,
    el("p", { text: finding.description }),
    finding.evidence ? el("code", { text: finding.evidence }) : null,
    finding.offset ? el("p", { class: "meta", text: `Строка ${finding.offset}` }) : null,
  );
}

function renderResult(result) {
  const box = clear($("#result"));
  if (!result) return;
  const counts = result.findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, {});
  const summary = Object.entries(counts)
    .sort((a, b) => ["critical", "high", "medium", "low", "info"].indexOf(a[0]) - ["critical", "high", "medium", "low", "info"].indexOf(b[0]))
    .map(([severity, count]) => `${severityLabel(severity)}: ${count}`)
    .join(" · ");

  box.append(
    el("div", { class: `verdict ${result.verdict === "malicious" ? "bad" : result.verdict === "suspicious" ? "warn" : "good"}` },
      el("h3", { text: `${verdictLabel(result.verdict)} · ${result.filename}` }),
      el("p", { class: "meta", text: `${MODELS_BY_ID.get(result.model)?.name || result.model} · ${bytes(result.size)} · ${result.elapsed_ms} мс · файлов внутри: ${result.scanned_entries}` }),
      summary ? el("p", { class: "meta", text: summary }) : null,
      el("p", { class: "hash", text: `SHA-256: ${result.sha256}` }),
      result.findings.length
        ? el("ul", { class: "findings" }, result.findings.map(findingCard))
        : el("p", { text: "Опасных сигнатур не найдено. Это не гарантия безопасности: проверяйте происхождение файла." }),
      result.notes?.length
        ? el("div", { class: "hint" }, result.notes.map((note) => el("p", { text: note })))
        : null,
      el("div", { class: "row" },
        el("button", { class: "ghost", type: "button", onclick: () => downloadReport(result), text: "Скачать HTML-отчёт" }),
        el("button", { class: "ghost", type: "button", onclick: () => { pickFile(null); $("#fileInput").value = ""; $("#fileInput").click(); }, text: "Проверить ещё" }),
      ),
    ),
  );
  box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function playScan() {
  if (state.busy || !state.profile) return;
  const snapshot = modelState(state.profile, state.selectedModel);
  const check = validateFile(snapshot, state.file);
  if (!check.ok) return toast(check.error, false);

  state.busy = true;
  $("#scanBtn").disabled = true;
  progress(3);
  $("#result").replaceChildren();

  try {
    const result = await scanFile(state.file, state.file.name, state.selectedModel, progress);
    progress(96);

    const period = periodStart();
    const bytesUsed = state.file.size;
    let counter = null;
    let quotaFailed = false;
    try {
      counter = await consumeUsage(state.user.uid, state.selectedModel, period, bytesUsed, snapshot.requests_limit);
    } catch (error) {
      quotaFailed = true;
      toast(`Firebase отклонил запись лимита: ${error.message}. Проверьте, что применены правила database.rules.json.`, false);
    }
    if (counter === null && !quotaFailed) {
      progress(0);
      toast("Лимит исчерпан: другой запрос уже израсходовал остаток", false);
      state.profile = await loadProfile(state.user.uid);
      renderModels();
      return;
    }
    if (counter) state.profile.usage = { ...(state.profile.usage || {}), [state.selectedModel]: counter };

    try {
      await saveScan(state.user.uid, result);
    } catch (error) {
      toast(`Отчёт не сохранён в истории: ${error.message}. Проверьте правила базы.`, false);
    }

    state.lastResult = result;
    renderResult(result);
    renderModels();
    progress(100);
    toast(result.verdict === "clean" ? "Проверка завершена: чисто" : `Проверка завершена: ${verdictLabel(result.verdict).toLowerCase()}`, result.verdict === "clean");
  } catch (error) {
    progress(0);
    const message = error instanceof ScanError ? error.message : `Ошибка сканирования: ${error.message}`;
    toast(message, false);
  } finally {
    state.busy = false;
    $("#scanBtn").disabled = false;
    setTimeout(() => progress(0), 900);
  }
}

$("#scanBtn").addEventListener("click", playScan);

/* --------------------------------------------------------------- pricing --- */

function offerButton(plan, offer) {
  const discount = offer.discount_label ? `−${offer.discount_label}%` : "";
  return el("button", {
    type: "button",
    class: "offer",
    dataset: { plan: plan.id, offer: offer.id },
  },
    el("div", { class: "offer-top" },
      el("span", { class: "price" }, `${formatMoney(offer.price)} `, el("small", { text: CATALOG.currency })),
      offer.old_price > offer.price ? el("span", { class: "old", text: `${formatMoney(offer.old_price)} ${CATALOG.currency}` }) : null,
      discount ? el("span", { class: "discount", text: discount }) : null,
    ),
    offer.saving > 0 ? el("span", { class: "saving", text: `Экономия ${formatMoney(offer.saving)} ${CATALOG.currency}` }) : null,
    el("span", { class: "cta", text: `${offer.label} · активировать` }),
  );
}

function renderPricing() {
  const grid = clear($("#plansGrid"));
  if (!state.profile) return;
  const activePlan = planInfo(state.profile.plan).id;
  for (const plan of CATALOG.plans) {
    const current = plan.id === activePlan;
    const card = el("article", { class: `plan${current ? " current" : ""}` },
      el("header", {},
        el("h3", {}, plan.name, current ? el("span", { class: "badge", text: "ваш тариф" }) : null),
        el("p", { class: "tagline", text: plan.tagline }),
      ),
      plan.offers.length
        ? el("div", { class: "offers" }, plan.offers.map((offer) => offerButton(plan, offer)))
        : el("p", { class: "badge", text: "Бесплатно навсегда" }),
      el("ul", {}, plan.features.map((feature) => el("li", { text: feature }))),
      el("p", { class: "hint", text: limitsText(plan) }),
    );
    grid.append(card);
  }
  for (const button of $$(".offer", grid)) {
    button.addEventListener("click", () => buy(button.dataset.plan, button.dataset.offer));
  }
  if (state.profile.planUntil) {
    grid.append(el("p", { class: "hint", text: `Тариф действует до ${formatDate(state.profile.planUntil)}` }));
  }
}

function limitsText(plan) {
  const parts = MODELS
    .filter((model) => plan.limits[model.id])
    .map((model) => `${model.name}: ${plan.limits[model.id].requests} запросов${plan.limits[model.id].mb ? ` · ${plan.limits[model.id].mb} МБ` : ""}`);
  return parts.join("; ");
}

async function buy(planId, offerId) {
  const plan = planInfo(planId);
  const offer = plan.offers.find((item) => item.id === offerId);
  if (!offer) return;
  const confirmed = await modal({
    title: `${plan.name} · ${offer.label}`,
    body: `${formatMoney(offer.price)} ${CATALOG.currency} вместо ${formatMoney(offer.old_price)} ${CATALOG.currency}. `
      + `Скидка ${offer.discount_label}%. Это демо-режим: оплата не списывается, тариф активируется сразу.`,
    ok: "Активировать",
  });
  if (!confirmed) return;

  const now = Date.now();
  const samePlan = state.profile.plan === planId && state.profile.planUntil;
  const base = samePlan ? Math.max(state.profile.planUntil, now) : now;
  const durationDays = { "7d": 7, "1m": 30, forever: null }[offer.id];
  const planUntil = durationDays === null ? null : base + durationDays * 24 * 3600 * 1000;

  try {
    await applyPlan(state.user.uid, planId, planUntil, offer.id);
    await savePurchase(state.user.uid, { plan: planId, offer: offer.id, price: offer.price, oldPrice: offer.old_price, currency: CATALOG.currency });
    state.profile = { ...state.profile, plan: planId, planUntil, planOffer: offer.id };
    $("#userPlan").textContent = plan.name;
    renderPricing();
    renderModels();
    toast(`Тариф ${plan.name} активирован (${offer.label})`);
  } catch (error) {
    toast(`Не удалось активировать тариф: ${error.message}`, false);
  }
}

function renderModelInfo() {
  const box = clear($("#modelInfo"));
  for (const model of MODELS) {
    box.append(el("article", {},
      el("h4", { text: model.name }),
      el("p", { class: "exts", text: model.extensions.map((ext) => `.${ext}`).join(" · ") }),
      el("p", { class: "hint", text: `Доступна на тарифах: ${planNameFor(model.id)}. Сигнатур в модели: ${model.signatures}.` }),
    ));
  }
}

/* --------------------------------------------------------------- history --- */

async function loadHistory() {
  if (!state.user) return;
  const list = clear($("#historyList"));
  list.append(el("p", { class: "hint", text: "Загружаем историю…" }));
  try {
    state.scans = await loadScans(state.user.uid, 100);
  } catch (error) {
    list.replaceChildren(el("p", { class: "hint", text: `Не удалось прочитать историю: ${error.message}` }));
    return;
  }
  list.replaceChildren();
  if (!state.scans.length) {
    list.append(el("p", { class: "hint", text: "История пуста — проверьте первый файл." }));
    return;
  }
  for (const scan of state.scans) {
    const item = el("div", { class: "hist-item" },
      el("div", { class: "hist-head" },
        el("div", {},
          el("div", { class: "hist-name", text: scan.filename || "без имени" }),
          el("div", { class: "hist-meta", text: `${modelName(scan.model)} · ${bytes(scan.size)} · ${formatDate(scan.scannedAt)}` }),
        ),
        el("span", { class: `verdict-pill ${scan.verdict}`, text: verdictLabel(scan.verdict) }),
      ),
      el("div", { class: "hist-actions" },
        el("button", { class: "ghost", type: "button", text: "Подробнее", onclick: () => toggleDetails(item, scan) }),
        el("button", { class: "ghost", type: "button", text: "HTML-отчёт", onclick: () => downloadReport(scan) }),
        el("button", { class: "ghost", type: "button", text: "Удалить", onclick: () => removeScan(scan.id) }),
      ),
    );
    list.append(item);
  }
}

function modelName(id) {
  const legacy = { v1: "m1", v2: "m2", lite: "m3_lite", pro: "m3_pro" };
  return MODELS_BY_ID.get(legacy[id] || id)?.name || id;
}

function toggleDetails(item, scan) {
  const existing = item.querySelector(".findings");
  if (existing) {
    existing.remove();
    return;
  }
  if (!scan.findings?.length) {
    item.append(el("p", { class: "hint", text: "Находок нет." }));
    return;
  }
  item.append(el("ul", { class: "findings" }, scan.findings.map(findingCard)));
}

async function removeScan(id) {
  const confirmed = await modal({ title: "Удалить отчёт?", body: "Он исчезнет из истории и не восстановится.", ok: "Удалить" });
  if (!confirmed) return;
  try {
    await deleteScan(state.user.uid, id);
    toast("Отчёт удалён");
    loadHistory();
  } catch (error) {
    toast(`Не удалось удалить: ${error.message}`, false);
  }
}

/* ---------------------------------------------------------------- report --- */

function buildReportHtml(result) {
  const rows = (result.findings || []).map((finding) => `
      <tr class="${escapeHtml(finding.severity)}">
        <td>${escapeHtml(finding.title)}</td>
        <td>${escapeHtml(severityLabel(finding.severity))}</td>
        <td>${escapeHtml(finding.entry || "")}</td>
        <td>${escapeHtml(finding.evidence || "")}</td>
        <td>${escapeHtml(finding.description)}</td>
      </tr>`).join("");
  return `<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">
<title>XSafety — отчёт: ${escapeHtml(result.filename)}</title>
<style>
body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0b0f16;color:#e8eef8;margin:0;padding:32px}
h1{font-size:22px;margin:0 0 6px}.meta{color:#93a3bb;font-size:13px;margin:2px 0}
.card{background:#141c2b;border:1px solid #253247;border-radius:12px;padding:18px;margin-top:16px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}
th,td{text-align:left;padding:8px;border-bottom:1px solid #253247;vertical-align:top}
th{color:#93a3bb;font-weight:600}
.critical td:first-child{color:#ff3d6e}.high td:first-child{color:#ef5350}
.medium td:first-child{color:#f0b429}.low td:first-child{color:#4f9cf9}
code{font-family:ui-monospace,Menlo,monospace;font-size:12px}
</style></head><body>
<h1>${escapeHtml(result.filename)}</h1>
<p class="meta">Вердикт: <b>${escapeHtml(verdictLabel(result.verdict))}</b> · модель ${escapeHtml(result.model || "")} · ${bytes(result.size)}</p>
<p class="meta">SHA-256: <code>${escapeHtml(result.sha256 || "")}</code></p>
<p class="meta">Проверено: ${escapeHtml(formatDate(result.scannedAt || Date.now()))} · сигнатур сработало: ${(result.findings || []).length}</p>
<div class="card">
${rows ? `<table><thead><tr><th>Правило</th><th>Серьёзность</th><th>Внутри</th><th>Фрагмент</th><th>Что значит</th></tr></thead><tbody>${rows}</tbody></table>` : "<p>Опасных сигнатур не найдено.</p>"}
${(result.notes || []).length ? `<p class="meta">${(result.notes || []).map(escapeHtml).join(" · ")}</p>` : ""}
</div>
<p class="meta">Статический анализ не заменяет песочницу: файл не запускается, а подозрительные элементы стоит проверить отдельно.</p>
</body></html>`;
}

function downloadReport(result) {
  const html = buildReportHtml(result);
  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = el("a", { href: url, download: `xsafety-${(result.filename || "report").replace(/[^\w.-]+/g, "_")}.html` });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

/* ----------------------------------------------------------------- admin --- */

async function renderAdminPanel() {
  if (!state.user || !isAdminEmail(state.user.email)) return;
  await renderAdmin({
    list: $("#adminList"),
    search: $("#adminSearch").value.trim().toLowerCase(),
    currentUid: state.user.uid,
    onChanged: async () => {
      state.profile = await loadProfile(state.user.uid);
      renderModels();
      renderPricing();
    },
    toast,
    modal,
  });
}

$("#adminRefresh").addEventListener("click", renderAdminPanel);
$("#adminSearch").addEventListener("input", () => {
  clearTimeout(renderAdminPanel.timer);
  renderAdminPanel.timer = setTimeout(renderAdminPanel, 250);
});

/* ------------------------------------------------------------------- nav --- */

$("#navScan").addEventListener("click", () => showView("scanView"));
$("#navPlans").addEventListener("click", () => showView("plansView"));
$("#navHistory").addEventListener("click", () => { showView("historyView"); loadHistory(); });
$("#adminBtn").addEventListener("click", () => {
  if (!isAdminEmail(state.user?.email)) return toast("Только для владельца", false);
  showView("adminView");
  renderAdminPanel();
});
$("#historyRefresh").addEventListener("click", loadHistory);

/* ------------------------------------------------------------------ clock --- */

setInterval(() => {
  if (!state.profile) return;
  $("#refillTime").textContent = timeLeft(nextReset());
  const diff = nextReset() - Date.now();
  if (diff <= 1000 && Date.now() - state.lastRefillRefresh > 30000) {
    state.lastRefillRefresh = Date.now();
    loadProfile(state.user.uid).then((profile) => {
      if (!profile) return;
      state.profile = { ...profile, uid: state.user.uid };
      renderModels();
      renderPricing();
    });
  }
}, 1000);

updateDropHint();
