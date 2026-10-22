/* Админ-панель: тарифы, лимиты, баны. Доступ проверяют и интерфейс,
 * и правила Realtime Database (по email владельца).
 */
import { db, get, ref } from "./firebase.js";
import { MODELS, PLANS } from "./plans.js";
import { bytes, clear, el, formatDate } from "./dom.js";

const DURATIONS = [
  { id: "7d", label: "7 дней", days: 7 },
  { id: "1m", label: "30 дней", days: 30 },
  { id: "forever", label: "Навсегда", days: null },
  { id: "keep", label: "Не менять срок", days: undefined },
];

async function updatePath(path, value) {
  const { update } = await import("./firebase.js");
  await update(ref(db, path), value);
}

function usageText(profile) {
  const parts = MODELS.map((model) => {
    const raw = profile.usage?.[model.id];
    const count = raw && typeof raw === "object" ? Number(raw.count) || 0 : Number(raw) || 0;
    if (!count) return null;
    return `${model.name}: ${count}`;
  }).filter(Boolean);
  if (!parts.length) return "запросов сегодня нет";
  const used = MODELS.reduce((total, model) => {
    const raw = profile.usage?.[model.id];
    return total + (raw && typeof raw === "object" ? Number(raw.count) || 0 : Number(raw) || 0);
  }, 0);
  const size = MODELS.reduce((total, model) => {
    const raw = profile.usage?.[model.id];
    return total + (raw && typeof raw === "object" ? Number(raw.bytes) || 0 : 0);
  }, 0);
  return `${parts.join(" · ")} · всего ${used} запросов и ${bytes(size)}`;
}

function userRow(uid, profile, ctx) {
  const planSelect = el("select", { "aria-label": "Тариф" },
    [...PLANS.values()].map((plan) => el("option", {
      value: plan.id,
      text: plan.name,
      selected: plan.id === profile.plan,
    })),
  );
  const durationSelect = el("select", { "aria-label": "Срок" },
    DURATIONS.map((duration) => el("option", { value: duration.id, text: duration.label, selected: duration.id === "keep" })),
  );

  const save = el("button", { class: "primary", type: "button", text: "Сохранить" });
  save.addEventListener("click", async () => {
    save.disabled = true;
    try {
      const plan = planSelect.value;
      const duration = DURATIONS.find((item) => item.id === durationSelect.value);
      let planUntil = profile.planUntil ?? null;
      if (duration.days !== undefined) {
        planUntil = duration.days === null ? null : Date.now() + duration.days * 24 * 3600 * 1000;
      }
      await updatePath(`users/${uid}`, { plan, planUntil, planOffer: duration.id });
      ctx.toast(`Тариф ${PLANS.get(plan)?.name || plan} сохранён (демо-режим)`);
      await ctx.onChanged?.();
      await renderAdmin(ctx);
    } catch (error) {
      ctx.toast(`Не удалось сохранить: ${error.message}`, false);
    } finally {
      save.disabled = false;
    }
  });

  const reset = el("button", { class: "ghost", type: "button", text: "Сбросить лимиты" });
  reset.addEventListener("click", async () => {
    reset.disabled = true;
    try {
      await updatePath(`users/${uid}`, { usage: {} });
      ctx.toast("Счётчики обнулены");
      await renderAdmin(ctx);
    } catch (error) {
      ctx.toast(`Не удалось сбросить: ${error.message}`, false);
    } finally {
      reset.disabled = false;
    }
  });

  const ban = el("button", { class: "ghost", type: "button", text: profile.banned ? "Разбанить" : "Забанить" });
  ban.addEventListener("click", async () => {
    ban.disabled = true;
    try {
      await updatePath(`users/${uid}`, { banned: !profile.banned });
      ctx.toast(profile.banned ? "Пользователь разбанен" : "Пользователь забанен");
      await renderAdmin(ctx);
    } catch (error) {
      ctx.toast(`Не удалось изменить бан: ${error.message}`, false);
    } finally {
      ban.disabled = false;
    }
  });

  return el("div", { class: "admin-row" },
    el("div", { class: "admin-top" },
      el("div", {},
        el("div", { class: "admin-email", text: profile.email || uid }),
        el("div", { class: "admin-usage", text: `${usageText(profile)}${profile.planUntil ? ` · до ${formatDate(profile.planUntil)}` : ""}${profile.banned ? " · забанен" : ""}` }),
        uid === ctx.currentUid ? el("div", { class: "admin-usage", text: "это вы" }) : null,
      ),
      el("span", { class: "badge", text: PLANS.get(profile.plan)?.name || "Default" }),
    ),
    el("div", { class: "admin-controls" }, planSelect, durationSelect, save, reset, ban),
  );
}

export async function renderAdmin(ctx) {
  const list = clear(ctx.list);
  list.append(el("p", { class: "hint", text: "Загружаем пользователей…" }));
  let snapshot;
  try {
    snapshot = await get(ref(db, "users"));
  } catch (error) {
    list.replaceChildren(el("p", { class: "hint", text: `Нет доступа к списку: ${error.message}` }));
    return;
  }
  const users = Object.entries(snapshot.val() || {})
    .map(([uid, profile]) => ({ uid, profile }))
    .filter(({ profile }) => !ctx.search || String(profile.email || "").toLowerCase().includes(ctx.search))
    .sort((a, b) => (b.profile.createdAt || 0) - (a.profile.createdAt || 0));

  list.replaceChildren();
  if (!users.length) {
    list.append(el("p", { class: "hint", text: "Пользователи не найдены." }));
    return;
  }
  for (const { uid, profile } of users) list.append(userRow(uid, profile, ctx));
  list.append(el("p", { class: "hint", text: `Всего пользователей: ${users.length}. Смена тарифа здесь — демо-операция без оплаты.` }));
}
