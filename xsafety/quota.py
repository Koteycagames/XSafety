"""Суточные лимиты: расчёт состояния и атомарное списание.

Окно — календарные 24 часа UTC. Для каждой модели считается своя пара
(запросы, байты). Модели, которых нет в тарифе, помечаются как
``blocked``: они не «серые до завтра», а вообще не получают новых лимитов
каждые 24 часа — это отдельный статус в API и UI.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .config import ALL_EXTENSIONS, MAX_UPLOAD_BYTES, MODELS, PLAN_ORDER, PLANS, REFILL_PERIOD, Plan
from .storage import Storage, User, iso, utcnow


class QuotaError(Exception):
    """Отказ по лимитам с машинным кодом и HTTP-статусом."""

    def __init__(self, code: str, message: str, status: int = 429, details: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details or {}

    def to_dict(self) -> dict[str, object]:
        return {"code": self.code, "message": self.message, "details": self.details}


def period_start(now: datetime | None = None) -> datetime:
    moment = (now or utcnow()).astimezone(timezone.utc)
    return moment.replace(hour=0, minute=0, second=0, microsecond=0)


def next_reset(now: datetime | None = None) -> datetime:
    return period_start(now) + REFILL_PERIOD


def plan_for(user: User) -> Plan:
    return PLANS.get(user.plan, PLANS["default"])


@dataclass(slots=True)
class Reservation:
    model_id: str
    size: int
    period: datetime


def reserve(storage: Storage, user: User, model_id: str, size: int, now: datetime | None = None) -> Reservation:
    """Списывает одну проверку и байты, либо бросает QuotaError."""
    moment = now or utcnow()
    plan = plan_for(user)
    allowance = plan.allowance(model_id)
    reset_at = iso(next_reset(moment))
    if allowance is None or allowance.requests <= 0:
        raise QuotaError(
            "model_not_in_plan",
            "Модель недоступна в вашем тарифе. Лимиты на неё не начисляются.",
            status=403,
            details={"model": model_id, "refill_scheduled": False, "resets_at": reset_at},
        )

    limit_bytes = allowance.max_bytes if allowance.max_bytes is not None else MAX_UPLOAD_BYTES
    if size > limit_bytes:
        raise QuotaError(
            "file_too_large",
            f"Файл больше лимита тарифа для этой модели ({_mb(limit_bytes)}).",
            status=413,
            details={"model": model_id, "limit_bytes": limit_bytes, "resets_at": reset_at},
        )

    period = period_start(moment)
    ok, reason, requests, used_bytes = storage.reserve_usage(
        user.id,
        model_id,
        size,
        period,
        allowance.requests,
        allowance.max_bytes,
    )
    if not ok:
        if reason == "bytes":
            message = (
                f"Исчерпан объём на модели {model_id} на эти сутки "
                f"({_mb(allowance.max_bytes)}). Новый объём — после сброса."
            )
        else:
            message = (
                f"Исчерпан лимит запросов на модели {model_id} "
                f"({allowance.requests} в сутки). Новые запросы — после сброса."
            )
        raise QuotaError(
            "daily_limit",
            message,
            status=429,
            details={
                "model": model_id,
                "requests_limit": allowance.requests,
                "requests_used": requests,
                "bytes_used": used_bytes,
                "bytes_limit": allowance.max_bytes,
                "resets_at": reset_at,
                "refill_scheduled": True,
            },
        )
    return Reservation(model_id=model_id, size=size, period=period)


def refund(storage: Storage, user: User, reservation: Reservation) -> None:
    storage.refund_usage(user.id, reservation.model_id, reservation.size, reservation.period)


def _mb(value: int | None) -> str:
    if value is None:
        return "без ограничения"
    if value % (1024 * 1024) == 0:
        return f"{value // (1024 * 1024)} МБ"
    return f"{value / (1024 * 1024):.1f} МБ"


def model_state(user: User, model_id: str, used: tuple[int, int] | None, now: datetime | None = None) -> dict[str, object]:
    """Состояние одной модели: доступ, остаток, дата сброса, блокировка."""
    moment = now or utcnow()
    plan = plan_for(user)
    allowance = plan.allowance(model_id)
    model = next((m for m in MODELS if m.id == model_id), None)
    reset_at = iso(next_reset(moment))
    base: dict[str, object] = {
        "model_id": model_id,
        "name": model.name if model else model_id,
        "extensions": list(model.extensions) if model else [],
        "resets_at": reset_at,
        "period_hours": int(REFILL_PERIOD.total_seconds() // 3600),
    }
    if model is None or allowance is None:
        base.update(
            {
                "available": False,
                "blocked": True,
                "blocked_reason": "not_in_plan",
                "refill_scheduled": False,
                "requests_used": 0,
                "requests_limit": 0,
                "requests_left": 0,
                "bytes_used": 0,
                "bytes_limit": None,
                "mb_limit": None,
                "exhausted": False,
                "note": "Модель недоступна на этом тарифе — новые лимиты не начисляются.",
            }
        )
        return base

    requests_used, bytes_used = used or (0, 0)
    exhausted = requests_used >= allowance.requests or (
        allowance.max_bytes is not None and bytes_used >= allowance.max_bytes
    )
    base.update(
        {
            "available": True,
            "blocked": False,
            "blocked_reason": None,
            "refill_scheduled": True,
            "requests_used": requests_used,
            "requests_limit": allowance.requests,
            "requests_left": max(allowance.requests - requests_used, 0),
            "bytes_used": bytes_used,
            "bytes_limit": allowance.max_bytes,
            "mb_limit": allowance.mb,
            "exhausted": exhausted,
            "note": (
                "Лимиты исчерпаны — новые начислятся при сбросе."
                if exhausted
                else f"Доступно {allowance.requests - requests_used} запросов до сброса."
            ),
        }
    )
    return base


def snapshot(storage: Storage, user: User, now: datetime | None = None) -> dict[str, object]:
    moment = now or utcnow()
    plan = plan_for(user)
    usage = storage.usage_snapshot(user.id, period_start(moment))
    models = [model_state(user, model.id, usage.get(model.id), moment) for model in MODELS]
    return {
        "plan": plan.id,
        "plan_name": plan.name,
        "plan_until": iso(user.plan_until) if user.plan_until else None,
        "plan_offer": user.plan_offer,
        "period_start": iso(period_start(moment)),
        "resets_at": iso(next_reset(moment)),
        "period_hours": int(REFILL_PERIOD.total_seconds() // 3600),
        "models": models,
        "all_extensions": list(ALL_EXTENSIONS),
        "plans_order": list(PLAN_ORDER),
    }


def can_scan(user: User, model_id: str) -> bool:
    plan = plan_for(user)
    return plan.allowance(model_id) is not None


__all__ = [
    "QuotaError",
    "Reservation",
    "can_scan",
    "model_state",
    "next_reset",
    "period_start",
    "plan_for",
    "refund",
    "reserve",
    "snapshot",
]
