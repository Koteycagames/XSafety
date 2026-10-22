"""Расчёт скидок и сериализация каталога тарифов для API/UI.

Скидка никогда не хранится как число: она всегда выводится из пары
(старая цена, новая цена). Это исключает расхождение «−31%» на витрине
и списание не той суммы.
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal

from .config import CURRENCY, MODELS, PLANS, PRICING, Offer, Plan


def discount_percent(old_price: int, price: int) -> Decimal:
    """Скидка в процентах с разумным округлением.

    * больше 1% — один знак после запятой (31,0 → 31);
    * меньше 1% — два знака (0,06);
    * некорректные значения (old <= 0, price < 0, price > old) → 0.
    """
    if old_price <= 0 or price < 0 or price > old_price:
        return Decimal("0")
    raw = (Decimal(old_price - price) * Decimal(100)) / Decimal(old_price)
    if raw < Decimal("1"):
        return raw.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return raw.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)


def format_percent(value: Decimal) -> str:
    """Строка для витрины: без хвостовых нулей, с запятой как разделителем."""
    normalized = value.normalize()
    text = format(normalized, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text.replace(".", ",")


def offer_payload(item: Offer) -> dict[str, object]:
    percent = discount_percent(item.old_price, item.price)
    return {
        "id": item.id,
        "label": item.label,
        "price": item.price,
        "old_price": item.old_price,
        "currency": CURRENCY,
        "saving": item.saving,
        "discount_percent": float(percent),
        "discount_label": format_percent(percent),
        "has_discount": item.old_price > item.price,
    }


def plan_payload(plan: Plan) -> dict[str, object]:
    allowances = []
    for model in sorted(MODELS, key=lambda m: m.order):
        allowance = plan.allowance(model.id)
        allowances.append(
            {
                "model_id": model.id,
                "model_name": model.name,
                "available": allowance is not None,
                "requests": allowance.requests if allowance else 0,
                "mb": allowance.mb if allowance else None,
                "extensions": list(model.extensions) if allowance else [],
            }
        )
    return {
        "id": plan.id,
        "name": plan.name,
        "tagline": plan.tagline,
        "features": list(plan.features),
        "highlighted": plan.highlighted,
        "allowances": allowances,
        "offers": [offer_payload(o) for o in PRICING.get(plan.id, ())],
        "is_free": plan.id == "default",
    }


def plans_catalog() -> list[dict[str, object]]:
    return [plan_payload(PLANS[key]) for key in ("default", "pro", "premium")]


def subscription_total(plan_id: str, offer_id: str) -> tuple[Offer, Decimal] | None:
    """Валидирует покупку и возвращает (оффер, скидка).

    Используется сервером при демо-активации: цена и период берутся из
    конфигурации, а не из тела запроса.
    """
    for item in PRICING.get(plan_id, ()):
        if item.id == offer_id:
            return item, discount_percent(item.old_price, item.price)
    return None
