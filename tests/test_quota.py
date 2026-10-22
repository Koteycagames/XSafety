"""Суточные лимиты: значения, блокировки, сброс и атомарность."""

from __future__ import annotations

import concurrent.futures
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from xsafety import quota
from xsafety.config import MAX_UPLOAD_BYTES
from xsafety.quota import QuotaError
from xsafety.storage import Storage

NOW = datetime(2026, 5, 12, 15, 30, tzinfo=timezone.utc)
MB = 1024 * 1024


def make_user(storage: Storage, plan: str = "default", until: datetime | None = None):
    user = storage.create_user(f"{plan}-{uuid.uuid4().hex[:10]}@example.com", "hash")
    if plan != "default":
        user = storage.set_plan(user.id, plan, until, "1m")
    assert user is not None
    return user


def test_default_plan_only_first_model():
    storage = Storage()
    user = make_user(storage)
    state = quota.snapshot(storage, user, NOW)
    by_id = {model["model_id"]: model for model in state["models"]}

    assert by_id["m1"]["available"] is True
    assert by_id["m1"]["requests_limit"] == 10
    assert by_id["m1"]["mb_limit"] == 10
    for model_id in ("m2", "m3_lite", "m3_pro"):
        assert by_id[model_id]["available"] is False
        assert by_id[model_id]["blocked"] is True
        # Ключевое требование: на недоступные модели лимиты не начисляются.
        assert by_id[model_id]["refill_scheduled"] is False
        assert by_id[model_id]["blocked_reason"] == "not_in_plan"


def test_blocked_model_cannot_be_reserved():
    storage = Storage()
    user = make_user(storage)
    with pytest.raises(QuotaError) as error:
        quota.reserve(storage, user, "m2", 100, NOW)
    assert error.value.code == "model_not_in_plan"
    assert error.value.status == 403
    assert error.value.details["refill_scheduled"] is False


def test_default_request_limit():
    storage = Storage()
    user = make_user(storage)
    for _ in range(10):
        quota.reserve(storage, user, "m1", 1024, NOW)
    with pytest.raises(QuotaError) as error:
        quota.reserve(storage, user, "m1", 1024, NOW)
    assert error.value.code == "daily_limit"
    assert error.value.status == 429
    assert error.value.details["refill_scheduled"] is True
    assert error.value.details["resets_at"].endswith("00:00:00+00:00")


def test_next_period_refills():
    storage = Storage()
    user = make_user(storage)
    for _ in range(10):
        quota.reserve(storage, user, "m1", 1024, NOW)
    with pytest.raises(QuotaError):
        quota.reserve(storage, user, "m1", 1024, NOW)
    # Следующие сутки — новый период и снова 10 запросов.
    tomorrow = NOW + timedelta(days=1)
    quota.reserve(storage, user, "m1", 1024, tomorrow)


def test_byte_limit_default_10mb():
    storage = Storage()
    user = make_user(storage)
    with pytest.raises(QuotaError) as error:
        quota.reserve(storage, user, "m1", 10 * MB + 1, NOW)
    assert error.value.code == "file_too_large"
    assert error.value.status == 413

    quota.reserve(storage, user, "m1", 10 * MB, NOW)
    with pytest.raises(QuotaError) as error:
        quota.reserve(storage, user, "m1", 1, NOW)
    assert error.value.code == "daily_limit"
    assert error.value.details["bytes_limit"] == 10 * MB


def test_pro_limits():
    storage = Storage()
    user = make_user(storage, "pro")
    state = {model["model_id"]: model for model in quota.snapshot(storage, user, NOW)["models"]}
    assert state["m1"]["requests_limit"] == 20
    assert state["m2"]["requests_limit"] == 10
    assert state["m3_lite"]["requests_limit"] == 1
    assert state["m3_pro"]["available"] is False
    assert state["m1"]["mb_limit"] == 30
    assert state["m2"]["mb_limit"] == 30

    quota.reserve(storage, user, "m3_lite", 1024, NOW)
    with pytest.raises(QuotaError) as error:
        quota.reserve(storage, user, "m3_lite", 1024, NOW)
    assert error.value.code == "daily_limit"


def test_premium_limits_and_unlimited_bytes():
    storage = Storage()
    user = make_user(storage, "premium")
    state = {model["model_id"]: model for model in quota.snapshot(storage, user, NOW)["models"]}
    assert [state[m]["requests_limit"] for m in ("m1", "m2", "m3_lite", "m3_pro")] == [30, 20, 15, 10]
    for model in state.values():
        assert model["available"] is True
        assert model["refill_scheduled"] is True
        assert model["mb_limit"] is None
        assert model["bytes_limit"] is None

    # Без лимита МБ действует только технический предел загрузки.
    quota.reserve(storage, user, "m3_pro", MAX_UPLOAD_BYTES, NOW)


def test_plan_expiry_falls_back_to_default():
    storage = Storage()
    user = make_user(storage, "pro", until=datetime(2026, 5, 10, tzinfo=timezone.utc))
    refreshed = storage.get_user(user.id)
    assert refreshed is not None
    assert refreshed.plan == "default"
    assert refreshed.plan_until is None


def test_usage_is_atomic_under_concurrency(tmp_path):
    storage = Storage(tmp_path / "atomic.db")
    user = make_user(storage)

    def attempt(_: int) -> bool:
        try:
            quota.reserve(storage, user, "m1", 10, NOW)
            return True
        except QuotaError:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(attempt, range(40)))

    assert sum(results) == 10
    used, _size = storage.usage_snapshot(user.id, quota.period_start(NOW))["m1"]
    assert used == 10


def test_refund_returns_quota():
    storage = Storage()
    user = make_user(storage)
    reservation = quota.reserve(storage, user, "m1", 500, NOW)
    quota.refund(storage, user, reservation)
    used, size = storage.usage_snapshot(user.id, quota.period_start(NOW))["m1"]
    assert used == 0
    assert size == 0


def test_snapshot_countdown_fields():
    storage = Storage()
    user = make_user(storage)
    state = quota.snapshot(storage, user, NOW)
    assert state["period_hours"] == 24
    assert state["resets_at"] == "2026-05-13T00:00:00+00:00"
    model = next(item for item in state["models"] if item["model_id"] == "m1")
    assert model["resets_at"] == state["resets_at"]
    assert model["requests_left"] == 10
