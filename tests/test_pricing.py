"""Цены, скидки и каталог тарифов."""

from __future__ import annotations

from decimal import Decimal

from xsafety.config import PLANS, PRICING
from xsafety.pricing import discount_percent, format_percent, offer_payload, plans_catalog


def test_offer_prices_match_requirement():
    pro = {offer.id: offer for offer in PRICING["pro"]}
    assert (pro["7d"].price, pro["7d"].old_price) == (89, 129)
    assert (pro["1m"].price, pro["1m"].old_price) == (249, 420)
    assert (pro["forever"].price, pro["forever"].old_price) == (1299, 2900)

    premium = {offer.id: offer for offer in PRICING["premium"]}
    assert (premium["7d"].price, premium["7d"].old_price) == (175, 200)
    assert (premium["1m"].price, premium["1m"].old_price) == (499, 700)
    assert (premium["forever"].price, premium["forever"].old_price) == (1699, 1700)


def test_discount_percent_values():
    assert discount_percent(129, 89) == Decimal("31.0")
    assert discount_percent(420, 249) == Decimal("40.7")
    assert discount_percent(2900, 1299) == Decimal("55.2")
    assert discount_percent(200, 175) == Decimal("12.5")
    assert discount_percent(700, 499) == Decimal("28.7")
    assert discount_percent(1700, 1699) == Decimal("0.06")
    assert discount_percent(0, 10) == Decimal("0")
    assert discount_percent(100, 150) == Decimal("0")


def test_percent_format_uses_comma():
    assert format_percent(Decimal("40.7")) == "40,7"
    assert format_percent(Decimal("31.0")) == "31"
    assert format_percent(Decimal("0.06")) == "0,06"


def test_offer_payload_has_discount_flag():
    pro = {offer.id: offer for offer in PRICING["pro"]}
    payload = offer_payload(pro["forever"])
    assert payload["discount_label"] == "55,2"
    assert payload["has_discount"] is True
    assert payload["saving"] == 1601


def test_catalog_includes_every_model_in_every_plan():
    catalog = {plan["id"]: plan for plan in plans_catalog()}
    assert set(catalog) == {"default", "pro", "premium"}
    for plan in catalog.values():
        assert len(plan["allowances"]) == 4
    default_models = [item for item in catalog["default"]["allowances"] if item["available"]]
    assert [item["model_id"] for item in default_models] == ["m1"]


def test_plan_limits_exact_values():
    assert PLANS["default"].allowance("m1").requests == 10
    assert PLANS["default"].allowance("m1").mb == 10
    assert PLANS["pro"].allowance("m1").requests == 20
    assert PLANS["pro"].allowance("m2").requests == 10
    assert PLANS["pro"].allowance("m3_lite").requests == 1
    assert PLANS["pro"].allowance("m3_pro") is None
    assert PLANS["premium"].allowance("m1").requests == 30
    assert PLANS["premium"].allowance("m2").requests == 20
    assert PLANS["premium"].allowance("m3_lite").requests == 15
    assert PLANS["premium"].allowance("m3_pro").requests == 10
