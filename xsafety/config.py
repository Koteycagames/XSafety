"""Единый источник правды: модели, расширения, тарифы, цены и лимиты.

Менять цифры лимитов/цен нужно ТОЛЬКО здесь. Ни API, ни фронтенд не
принимают цены или лимиты от клиента — они всегда вычисляются на сервере
из этих таблиц (см. SECURITY.md, цикл 2, V-08).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from types import MappingProxyType
from typing import Mapping

# ---------------------------------------------------------------------------
# Технические предохранители (не зависят от тарифа)
# ---------------------------------------------------------------------------

#: Абсолютный потолок размера загружаемого файла. Действует даже там,
#: где тариф не задаёт лимит в мегабайтах.
MAX_UPLOAD_BYTES: int = 64 * 1024 * 1024

#: Сколько байт текста анализируется сигнатурами (остальное — только хэш).
MAX_TEXT_ANALYZE_BYTES: int = 512 * 1024

#: Сколько байт бинарного файла уходит на строковые/структурные эвристики.
MAX_BINARY_ANALYZE_BYTES: int = 2 * 1024 * 1024

#: Ограничения на результаты, чтобы отчёт не раздувался.
MAX_FINDINGS: int = 200
MAX_FINDINGS_PER_SIG: int = 5

#: Предохранители разбора ZIP (zip-slip / zip-bomb).
MAX_ZIP_ENTRIES: int = 512
MAX_ZIP_TOTAL_UNCOMPRESSED: int = 32 * 1024 * 1024
MAX_ZIP_ENTRY_BYTES: int = 8 * 1024 * 1024
MAX_ZIP_RATIO: int = 150
MAX_ZIP_DEPTH: int = 2

#: Период начисления лимитов.
REFILL_PERIOD: timedelta = timedelta(hours=24)

#: Срок жизни "покупки" в демо-режиме (для тарифных периодов).
DURATION_DAYS: Mapping[str, int | None] = MappingProxyType(
    {"7d": 7, "1m": 30, "forever": None}
)


# ---------------------------------------------------------------------------
# Модели сканирования и расширения
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Model:
    """Модель (движок) сканирования.

    ``extensions`` — полный (кумулятивный) список расширений, которые
    модель умеет проверять.
    """

    id: str
    name: str
    tagline: str
    extensions: tuple[str, ...]
    order: int

    @property
    def extension_set(self) -> frozenset[str]:
        return frozenset(self.extensions)


MODELS: tuple[Model, ...] = (
    Model(
        id="m1",
        name="XSafety 1",
        tagline="Скрипты Windows и Python",
        extensions=("bat", "py"),
        order=1,
    ),
    Model(
        id="m2",
        name="XSafety 2",
        tagline="Всё из модели 1 + JavaScript и PowerShell",
        extensions=("bat", "py", "js", "ps1"),
        order=2,
    ),
    Model(
        id="m3_lite",
        name="XSafety 3 Lite",
        tagline="Всё из модели 2 + VBS, HTA, DLL и ZIP",
        extensions=("bat", "py", "js", "ps1", "vbs", "hta", "dll", "zip"),
        order=3,
    ),
    Model(
        id="m3_pro",
        name="XSafety 3 Pro",
        tagline="Всё из модели 3 Lite + EXE и JAR",
        extensions=("bat", "py", "js", "ps1", "vbs", "hta", "dll", "zip", "exe", "jar"),
        order=4,
    ),
)

MODELS_BY_ID: Mapping[str, Model] = MappingProxyType({m.id: m for m in MODELS})

#: Полный список поддерживаемых расширений (для валидации и UI).
ALL_EXTENSIONS: tuple[str, ...] = MODELS_BY_ID["m3_pro"].extensions


def model_supports(model_id: str, extension: str) -> bool:
    """Поддерживает ли модель расширение (без учёта регистра)."""
    model = MODELS_BY_ID.get(model_id)
    if model is None:
        return False
    return extension.lower().lstrip(".") in model.extension_set


def model_extensions(model_id: str) -> tuple[str, ...]:
    model = MODELS_BY_ID.get(model_id)
    return model.extensions if model else ()


# ---------------------------------------------------------------------------
# Тарифы и суточные лимиты
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Allowance:
    """Суточная норма модели в рамках тарифа.

    ``mb is None`` означает, что тариф не задаёт ограничение по объёму;
    при этом всегда действует общий технический лимит ``MAX_UPLOAD_BYTES``.
    """

    requests: int
    mb: int | None = None

    @property
    def max_bytes(self) -> int | None:
        return None if self.mb is None else self.mb * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Plan:
    id: str
    name: str
    tagline: str
    allowances: Mapping[str, Allowance]
    features: tuple[str, ...] = field(default_factory=tuple)
    highlighted: bool = False

    def allowance(self, model_id: str) -> Allowance | None:
        return self.allowances.get(model_id)

    @property
    def models(self) -> tuple[str, ...]:
        """Модели тарифа в порядке возрастания."""
        return tuple(
            m.id for m in sorted(MODELS, key=lambda m: m.order) if m.id in self.allowances
        )


#: Единственное место, где живут суточные лимиты.
#:
#: default — 10 запросов и 10 МБ только на модель 1;
#: pro     — 20/30 МБ на модель 1, 10/30 МБ на модель 2, 1 запрос на 3 Lite;
#: premium — 30 на модель 1, 20 на модель 2, 15 на 3 Lite, 10 на 3 Pro.
#: Для моделей без указанного объёма лимит по МБ не применяется.
PLANS: Mapping[str, Plan] = MappingProxyType(
    {
        "default": Plan(
            id="default",
            name="Default",
            tagline="Бесплатный старт",
            allowances={"m1": Allowance(requests=10, mb=10)},
            features=(
                "Модель XSafety 1: .bat и .py",
                "10 проверок и 10 МБ каждые 24 часа",
                "История проверок и отчёт по сигнатурам",
            ),
        ),
        "pro": Plan(
            id="pro",
            name="Pro",
            tagline="Для ежедневной работы",
            allowances={
                "m1": Allowance(requests=20, mb=30),
                "m2": Allowance(requests=10, mb=30),
                "m3_lite": Allowance(requests=1, mb=None),
            },
            features=(
                "Модели XSafety 1 и 2, 3 Lite",
                "20 и 10 запросов на модели 1–2, по 30 МБ",
                "1 запрос на 3 Lite: DLL, архивы, VBS/HTA",
                "История проверок и экспорт HTML-отчёта",
            ),
            highlighted=True,
        ),
        "premium": Plan(
            id="premium",
            name="Premium",
            tagline="Максимум моделей и лимитов",
            allowances={
                "m1": Allowance(requests=30, mb=None),
                "m2": Allowance(requests=20, mb=None),
                "m3_lite": Allowance(requests=15, mb=None),
                "m3_pro": Allowance(requests=10, mb=None),
            },
            features=(
                "Все 4 модели, включая 3 Pro",
                "30 / 20 / 15 / 10 запросов каждые 24 часа",
                "Проверка .exe и .jar",
                "История проверок и экспорт HTML-отчёта",
            ),
        ),
    }
)

DEFAULT_PLAN_ID = "default"
PLAN_ORDER: tuple[str, ...] = ("default", "pro", "premium")


# ---------------------------------------------------------------------------
# Цены
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Offer:
    """Цена за период.

    ``price`` — сколько платит пользователь, ``old_price`` — зачёркнутая
    «обычная» цена. Скидка всегда вычисляется, а не хранится числом,
    чтобы её нельзя было подделать с клиента.
    """

    id: str
    label: str
    price: int
    old_price: int

    @property
    def saving(self) -> int:
        return max(self.old_price - self.price, 0)


PRICING: Mapping[str, tuple[Offer, ...]] = MappingProxyType(
    {
        "pro": (
            Offer(id="7d", label="7 дней", price=89, old_price=129),
            Offer(id="1m", label="1 месяц", price=249, old_price=420),
            Offer(id="forever", label="Навсегда", price=1299, old_price=2900),
        ),
        "premium": (
            Offer(id="7d", label="7 дней", price=175, old_price=200),
            Offer(id="1m", label="1 месяц", price=499, old_price=700),
            Offer(id="forever", label="Навсегда", price=1699, old_price=1700),
        ),
    }
)

CURRENCY = "грн"


def offer(plan_id: str, offer_id: str) -> Offer | None:
    for item in PRICING.get(plan_id, ()):
        if item.id == offer_id:
            return item
    return None
