/* Тарифы, модели и суточные лимиты на клиенте.
 * Источник чисел — js/data/catalog.js (сгенерирован из xsafety/config.py),
 * поэтому цены и квоты не расходятся с серверной версией.
 */
import CATALOG from "./data/catalog.js";

export { CATALOG };

export const MODELS = CATALOG.models;
export const MODELS_BY_ID = new Map(MODELS.map((model) => [model.id, model]));
export const PLANS = new Map(CATALOG.plans.map((plan) => [plan.id, plan]));
export const CURRENCY = CATALOG.currency;
export const REFILL_HOURS = CATALOG.refill_hours;

/** Начало текущих суток в UTC (как в серверной версии). */
export function periodStart(now = Date.now()) {
  const date = new Date(now);
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
}

export function nextReset(now = Date.now()) {
  return periodStart(now) + REFILL_HOURS * 3600 * 1000;
}

export function planInfo(planId) {
  return PLANS.get(planId) || PLANS.get(CATALOG.default_plan);
}

export function allowance(planId, modelId) {
  const plan = planInfo(planId);
  return plan?.limits?.[modelId] || null;
}

export function plansFor(modelId) {
  return CATALOG.plans.filter((plan) => plan.limits[modelId]).map((plan) => plan.id);
}

/** Нормализует запись usage из базы (в старых профилях там было число). */
export function usageEntry(profile, modelId, period) {
  const raw = profile?.usage?.[modelId];
  if (raw && typeof raw === "object") {
    if (raw.period === period) {
      return { count: Number(raw.count) || 0, bytes: Number(raw.bytes) || 0, period };
    }
    return { count: 0, bytes: 0, period };
  }
  if (typeof raw === "number") return { count: raw, bytes: 0, period };
  return { count: 0, bytes: 0, period };
}

/** Полное состояние модели: доступность, счётчики, время сброса. */
export function modelState(profile, modelId, now = Date.now()) {
  const plan = planInfo(profile?.plan || CATALOG.default_plan);
  const limit = plan?.limits?.[modelId] || null;
  const period = periodStart(now);
  const usage = usageEntry(profile, modelId, period);
  const extra = Number(profile?.extra?.[modelId] || 0);
  const requestsLimit = limit ? limit.requests + extra : 0;
  const bytesLimit = limit && limit.mb ? limit.mb * 1024 * 1024 : null;
  const model = MODELS_BY_ID.get(modelId);
  const state = {
    model_id: modelId,
    name: model?.name || modelId,
    extensions: model?.extensions || [],
    available: Boolean(limit),
    blocked: !limit,
    blocked_reason: limit ? null : "not_in_plan",
    refill_scheduled: Boolean(limit),
    plan_id: plan?.id || CATALOG.default_plan,
    plan_name: plan?.name || "Default",
    requests_used: usage.count,
    requests_limit: requestsLimit,
    requests_left: limit ? Math.max(requestsLimit - usage.count, 0) : 0,
    bytes_used: usage.bytes,
    bytes_limit: bytesLimit,
    mb_limit: limit?.mb ?? null,
    exhausted: Boolean(limit) && usage.count >= requestsLimit,
    period_start: period,
    resets_at: limit ? nextReset(now) : null,
    note: limit ? null : "Модель не входит в тариф — лимиты на неё не начисляются.",
  };
  return state;
}

export function quotaSnapshot(profile, now = Date.now()) {
  return {
    plan: planInfo(profile?.plan || CATALOG.default_plan).id,
    plan_name: planInfo(profile?.plan || CATALOG.default_plan).name,
    plan_until: profile?.planUntil || null,
    plan_offer: profile?.planOffer || null,
    period_start: periodStart(now),
    resets_at: nextReset(now),
    period_hours: REFILL_HOURS,
    models: MODELS.map((model) => modelState(profile, model.id, now)),
  };
}

/** Проверяет файл до сканирования: расширение, размер, остаток запросов. */
export function validateFile(state, file) {
  if (!file) return { ok: false, error: "Выберите файл" };
  const ext = (file.name.split(".").pop() || "").toLowerCase();
  if (!state.extensions.includes(ext)) {
    return { ok: false, error: `${state.name} не проверяет .${ext}` };
  }
  if (state.blocked) {
    return { ok: false, error: `Модель ${state.name} не входит в тариф «${state.plan_name}»` };
  }
  if (state.exhausted) {
    return { ok: false, error: `Лимит ${state.name} на сегодня исчерпан — обновится в 00:00 UTC` };
  }
  if (state.mb_limit && file.size > state.mb_limit * 1024 * 1024) {
    return { ok: false, error: `Файл больше ${state.mb_limit} МБ — лимит тарифа` };
  }
  if (file.size > 64 * 1024 * 1024) {
    return { ok: false, error: "Файл больше технического предела 64 МБ" };
  }
  return { ok: true, ext };
}

/** Заголовок оффера: «7 дней», «1 месяц», «Навсегда». */
export function offerTitle(planId, offerId) {
  const offer = planInfo(planId)?.offers?.find((item) => item.id === offerId);
  return offer?.label || offerId;
}

export function formatMoney(value) {
  return new Intl.NumberFormat("ru-RU").format(value);
}
