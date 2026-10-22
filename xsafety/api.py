"""HTTP API XSafety (FastAPI).

Все ответы с ошибками имеют единый формат:
``{"error": {"code", "message", "details"}}``.

Безопасность:
* пароли — PBKDF2, сессии — случайный токен, в БД только хеш;
* CSRF-заголовок для всех изменяющих запросов;
* лимиты и цены считаются только на сервере из ``config.py``;
* файлы не сохраняются на диск и не исполняются.
"""

from __future__ import annotations

import os
import secrets
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from . import __version__
from .auth import (
    SESSION_TTL_SECONDS,
    burn_password_check,
    csrf_equal,
    hash_password,
    login_throttle,
    new_csrf_token,
    new_session_token,
    normalize_email,
    scan_limiter,
    token_fingerprint,
    valid_email,
    validate_password,
    verify_password,
)
from .config import (
    CURRENCY,
    MAX_UPLOAD_BYTES,
    MODELS,
    MODELS_BY_ID,
    PLAN_ORDER,
    PLANS,
    REFILL_PERIOD,
    model_supports,
)
from .pricing import plans_catalog, subscription_total
from .quota import QuotaError, next_reset, plan_for, refund, reserve, snapshot
from .report import build_html_report, result_from_dict
from .scan.engine import ScanError, extension_from, sanitize_filename, scan_bytes
from .scan.signatures import signature_count
from .storage import DuplicateEmail, Storage, User, utcnow

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"
SESSION_COOKIE = "xsafety_session"
CSRF_COOKIE = "xsafety_xsrf"
CSRF_HEADER = "x-csrf-token"
SECURE_COOKIES = os.environ.get("XSAFETY_SECURE_COOKIES", "0") == "1"
ADMIN_TOKEN = os.environ.get("XSAFETY_ADMIN_TOKEN", "")
MAX_REQUEST_BYTES = MAX_UPLOAD_BYTES + 2 * 1024 * 1024


class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class PurchaseRequest(BaseModel):
    plan: str = Field(pattern=r"^(pro|premium)$")
    offer: str = Field(pattern=r"^(7d|1m|forever)$")


def _error(status: int, code: str, message: str, details: dict[str, object] | None = None) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message, "details": details or {}}})


def client_ip(request: Request) -> str:
    if os.environ.get("XSAFETY_TRUST_PROXY", "0") == "1":
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",", 1)[0].strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]


def _set_session(response: Response, token: str, csrf: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        secure=SECURE_COOKIES,
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf,
        max_age=SESSION_TTL_SECONDS,
        httponly=False,
        samesite="lax",
        secure=SECURE_COOKIES,
        path="/",
    )


def _clear_session(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


async def _current_user(request: Request) -> User | None:
    storage: Storage = request.app.state.storage
    cached = getattr(request.state, "user", "unset")
    if cached != "unset":
        return cached
    token = request.cookies.get(SESSION_COOKIE, "")
    user = storage.user_for_session(token_fingerprint(token)) if token else None
    request.state.user = user
    return user


async def require_user(user: Annotated[User | None, Depends(_current_user)]) -> User:
    if user is None:
        raise QuotaError("unauthorized", "Нужно войти в аккаунт.", status=401)
    return user


def _user_payload(user: User) -> dict[str, object]:
    return user.to_dict()


def create_app(storage: Storage | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.storage.purge_sessions()
        yield

    app = FastAPI(
        title="XSafety",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.storage = storage or Storage()
    app.state.started_at = utcnow()

    # ------------------------------------------------------------------
    # middleware
    # ------------------------------------------------------------------
    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > MAX_REQUEST_BYTES:
            return _error(413, "payload_too_large", "Запрос слишком большой.")

        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path.startswith("/api/"):
            if not request.url.path.startswith("/api/admin/"):
                cookie = request.cookies.get(CSRF_COOKIE, "")
                header = request.headers.get(CSRF_HEADER, "")
                if not cookie or not header or not csrf_equal(cookie, header):
                    return _error(403, "csrf_failed", "Недействительный CSRF-токен. Обновите страницу.")

        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Robots-Tag", "noindex, nofollow")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'self' https:",
        )
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        set_cookies = response.headers.getlist("set-cookie")
        already_set = any(header.startswith(f"{CSRF_COOKIE}=") for header in set_cookies)
        if not already_set and not request.cookies.get(CSRF_COOKIE):
            response.set_cookie(
                CSRF_COOKIE,
                new_csrf_token(),
                max_age=SESSION_TTL_SECONDS,
                httponly=False,
                samesite="lax",
                secure=SECURE_COOKIES,
                path="/",
            )
        return response

    @app.exception_handler(QuotaError)
    async def quota_handler(request: Request, exc: QuotaError):
        return _error(exc.status, exc.code, exc.message, exc.details)

    @app.exception_handler(ScanError)
    async def scan_error_handler(request: Request, exc: ScanError):
        return _error(exc.status, exc.code, exc.message)

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception):
        # Внутренние подробности не уходят клиенту.
        try:
            request.app.state.storage.audit("error", ip=client_ip(request), detail=type(exc).__name__)
        except Exception:
            pass
        return _error(500, "internal_error", "Внутренняя ошибка. Попробуйте позже.")

    # ------------------------------------------------------------------
    # страницы и служебные
    # ------------------------------------------------------------------
    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html", headers={"Cache-Control": "no-store"})

    @app.get("/favicon.svg", include_in_schema=False)
    async def favicon() -> FileResponse:
        return FileResponse(WEB_DIR / "favicon.svg", media_type="image/svg+xml")

    @app.get("/api/health")
    async def health() -> dict[str, object]:
        return {"ok": True, "version": __version__, "refill_hours": int(REFILL_PERIOD.total_seconds() // 3600)}

    @app.get("/api/plans")
    async def plans() -> dict[str, object]:
        models = [
            {
                "id": model.id,
                "name": model.name,
                "tagline": model.tagline,
                "extensions": list(model.extensions),
                "order": model.order,
                "signatures": signature_count(model.extensions),
            }
            for model in MODELS
        ]
        return {
            "plans": plans_catalog(),
            "models": models,
            "currency": CURRENCY,
            "refill_hours": int(REFILL_PERIOD.total_seconds() // 3600),
            "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
            "plan_order": list(PLAN_ORDER),
        }

    # ------------------------------------------------------------------
    # аккаунт
    # ------------------------------------------------------------------
    @app.get("/api/me")
    async def me(request: Request, user: Annotated[User | None, Depends(_current_user)]):
        if user is None:
            return {"user": None, "quota": None}
        return {"user": _user_payload(user), "quota": snapshot(request.app.state.storage, user)}

    @app.post("/api/auth/register")
    async def register(request: Request, payload: Credentials):
        storage: Storage = request.app.state.storage
        email = normalize_email(payload.email)
        if not valid_email(email):
            return _error(422, "invalid_email", "Проверьте формат e-mail.")
        password_error = validate_password(payload.password)
        if password_error:
            return _error(422, "weak_password", password_error)
        try:
            user = await run_in_threadpool(storage.create_user, email, hash_password(payload.password))
        except DuplicateEmail:
            return _error(409, "email_taken", "Аккаунт с таким e-mail уже существует.")
        except Exception:
            return _error(500, "internal_error", "Не удалось создать аккаунт.")

        token = new_session_token()
        await run_in_threadpool(
            storage.create_session,
            user.id,
            token_fingerprint(token),
            utcnow() + timedelta(seconds=SESSION_TTL_SECONDS),
            request.headers.get("user-agent", ""),
        )
        await run_in_threadpool(storage.audit, "register", user.id, client_ip(request))
        response = JSONResponse(
            {"user": _user_payload(user), "quota": snapshot(storage, user)},
            status_code=201,
        )
        _set_session(response, token, new_csrf_token())
        return response

    @app.post("/api/auth/login")
    async def login(request: Request, payload: Credentials):
        storage: Storage = request.app.state.storage
        email = normalize_email(payload.email)
        key = f"{client_ip(request)}|{email}"
        if login_throttle.blocked(key):
            return _error(429, "too_many_attempts", "Слишком много попыток. Повторите через 5 минут.")
        if not valid_email(email):
            return _error(401, "invalid_credentials", "Неверный e-mail или пароль.")

        record = await run_in_threadpool(storage.get_user_by_email, email)
        if record is None:
            await run_in_threadpool(burn_password_check, payload.password)
            login_throttle.fail(key)
            return _error(401, "invalid_credentials", "Неверный e-mail или пароль.")

        user, password_hash = record
        if not verify_password(payload.password, password_hash):
            login_throttle.fail(key)
            await run_in_threadpool(storage.audit, "login_failed", user.id, client_ip(request))
            return _error(401, "invalid_credentials", "Неверный e-mail или пароль.")

        login_throttle.reset(key)
        token = new_session_token()
        await run_in_threadpool(
            storage.create_session,
            user.id,
            token_fingerprint(token),
            utcnow() + timedelta(seconds=SESSION_TTL_SECONDS),
            request.headers.get("user-agent", ""),
        )
        await run_in_threadpool(storage.audit, "login", user.id, client_ip(request))
        response = JSONResponse({"user": _user_payload(user), "quota": snapshot(storage, user)})
        _set_session(response, token, new_csrf_token())
        return response

    @app.post("/api/auth/logout")
    async def logout(request: Request, user: Annotated[User | None, Depends(_current_user)]):
        storage: Storage = request.app.state.storage
        token = request.cookies.get(SESSION_COOKIE, "")
        if token:
            await run_in_threadpool(storage.delete_session, token_fingerprint(token))
        if user is not None:
            await run_in_threadpool(storage.audit, "logout", user.id, client_ip(request))
        response = JSONResponse({"ok": True})
        _clear_session(response)
        return response

    # ------------------------------------------------------------------
    # тарифы
    # ------------------------------------------------------------------
    @app.post("/api/billing/purchase")
    async def purchase(request: Request, payload: PurchaseRequest, user: Annotated[User, Depends(require_user)]):
        storage: Storage = request.app.state.storage
        offer = subscription_total(payload.plan, payload.offer)
        if offer is None:
            return _error(400, "invalid_offer", "Такого предложения нет.")
        item, discount = offer
        now = utcnow()
        # Продление того же тарифа — от текущей даты окончания, смена тарифа — с сегодня.
        if user.plan == payload.plan and user.plan_until and user.plan_until > now:
            base = user.plan_until
        else:
            base = now
        if payload.offer == "forever":
            until = None
        else:
            days = {"7d": 7, "1m": 30}[payload.offer]
            until = base + timedelta(days=days)

        await run_in_threadpool(storage.set_plan, user.id, payload.plan, until, payload.offer)
        await run_in_threadpool(
            storage.add_purchase,
            user.id,
            payload.plan,
            payload.offer,
            item.price,
            str(discount),
            until,
        )
        await run_in_threadpool(
            storage.audit,
            "purchase",
            user.id,
            client_ip(request),
            f"{payload.plan}/{payload.offer}",
        )
        updated = await run_in_threadpool(storage.get_user, user.id)
        assert updated is not None
        return {
            "user": _user_payload(updated),
            "quota": snapshot(storage, updated),
            "demo": True,
            "message": "Демо-режим: оплата не списывается, тариф активирован сразу.",
        }

    # ------------------------------------------------------------------
    # сканирование
    # ------------------------------------------------------------------
    @app.post("/api/scan")
    async def scan(
        request: Request,
        file: Annotated[UploadFile, File()],
        model: Annotated[str, Form()],
        user: Annotated[User, Depends(require_user)],
    ):
        storage: Storage = request.app.state.storage
        if not scan_limiter.allow(user.id):
            return _error(429, "rate_limited", "Слишком много проверок подряд. Подождите минуту.")
        if model not in MODELS_BY_ID:
            return _error(400, "unknown_model", "Неизвестная модель сканирования.")

        try:
            filename = sanitize_filename(file.filename or "file")
        except ScanError as exc:
            return _error(exc.status, exc.code, exc.message)
        extension = extension_from(filename)
        if not extension:
            return _error(422, "unsupported_extension", "Файл без расширения не поддерживается.")
        if not model_supports(model, extension):
            return _error(
                403,
                "extension_not_allowed",
                f"Модель {MODELS_BY_ID[model].name} не проверяет файлы .{extension}.",
            )

        plan = plan_for(user)
        allowance = plan.allowance(model)
        if allowance is None:
            raise QuotaError(
                "model_not_in_plan",
                "Модель недоступна в вашем тарифе. Лимиты на неё не начисляются.",
                status=403,
                details={"model": model, "refill_scheduled": False, "resets_at": next_reset().isoformat()},
            )
        limit_bytes = allowance.max_bytes if allowance.max_bytes is not None else MAX_UPLOAD_BYTES
        data = await file.read(limit_bytes + 1)
        if len(data) > limit_bytes:
            return _error(
                413,
                "file_too_large",
                f"Файл больше лимита тарифа для этой модели ({limit_bytes // (1024 * 1024)} МБ).",
                {"limit_bytes": limit_bytes},
            )
        if not data:
            return _error(400, "empty_file", "Файл пустой.")

        reservation = await run_in_threadpool(reserve, storage, user, model, len(data))
        try:
            result = await run_in_threadpool(scan_bytes, filename, data, model)
        except ScanError as exc:
            await run_in_threadpool(refund, storage, user, reservation)
            return _error(exc.status, exc.code, exc.message)
        except Exception:
            await run_in_threadpool(refund, storage, user, reservation)
            raise

        payload = result.to_dict()
        scan_id = await run_in_threadpool(storage.add_scan, user.id, payload)
        await run_in_threadpool(
            storage.audit,
            "scan",
            user.id,
            client_ip(request),
            f"{extension}/{result.verdict}",
        )
        return {
            "scan_id": scan_id,
            "result": payload,
            "quota": snapshot(storage, user),
        }

    @app.get("/api/scans")
    async def history(request: Request, user: Annotated[User, Depends(require_user)], limit: int = 30):
        storage: Storage = request.app.state.storage
        return {"scans": await run_in_threadpool(storage.list_scans, user.id, limit)}

    @app.get("/api/scans/{scan_id}")
    async def scan_details(request: Request, scan_id: str, user: Annotated[User, Depends(require_user)]):
        if not scan_id.isalnum() or len(scan_id) > 64:
            return _error(404, "not_found", "Проверка не найдена.")
        storage: Storage = request.app.state.storage
        payload = await run_in_threadpool(storage.get_scan, user.id, scan_id)
        if payload is None:
            return _error(404, "not_found", "Проверка не найдена.")
        return {"result": payload}

    @app.get("/api/scans/{scan_id}/report.html", response_class=HTMLResponse)
    async def scan_report(
        request: Request,
        scan_id: str,
        user: Annotated[User, Depends(require_user)],
        download: int = 0,
    ):
        if not scan_id.isalnum() or len(scan_id) > 64:
            return _error(404, "not_found", "Проверка не найдена.")
        storage: Storage = request.app.state.storage
        payload = await run_in_threadpool(storage.get_scan, user.id, scan_id)
        if payload is None:
            return _error(404, "not_found", "Проверка не найдена.")
        result = result_from_dict(payload)
        if result is None:
            return _error(404, "not_found", "Отчёт недоступен.")
        html = build_html_report(result, plan_name=plan_for(user).name)
        disposition = "attachment" if download else "inline"
        return HTMLResponse(
            html,
            headers={
                "Content-Disposition": f'{disposition}; filename="xsafety-report-{scan_id[:12]}.html"',
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'",
                "Cache-Control": "no-store",
            },
        )

    @app.delete("/api/scans/{scan_id}")
    async def scan_delete(request: Request, scan_id: str, user: Annotated[User, Depends(require_user)]):
        storage: Storage = request.app.state.storage
        deleted = await run_in_threadpool(storage.delete_scan, user.id, scan_id)
        if not deleted:
            return _error(404, "not_found", "Проверка не найдена.")
        return {"ok": True}

    # ------------------------------------------------------------------
    # служебное демо
    # ------------------------------------------------------------------
    @app.post("/api/admin/reset-usage")
    async def admin_reset(request: Request):
        if not ADMIN_TOKEN:
            return _error(404, "not_found", "Не найдено.")
        provided = request.headers.get("x-admin-token", "")
        if not provided or not secrets.compare_digest(provided, ADMIN_TOKEN):
            return _error(403, "forbidden", "Недостаточно прав.")
        storage: Storage = request.app.state.storage
        count = await run_in_threadpool(storage.reset_usage)
        await run_in_threadpool(storage.audit, "admin_reset_usage", None, client_ip(request), str(count))
        return {"ok": True, "rows": count, "resets_at": next_reset().isoformat()}

    @app.get("/api/admin/usage")
    async def admin_usage(request: Request):
        if not ADMIN_TOKEN:
            return _error(404, "not_found", "Не найдено.")
        provided = request.headers.get("x-admin-token", "")
        if not provided or not secrets.compare_digest(provided, ADMIN_TOKEN):
            return _error(403, "forbidden", "Недостаточно прав.")
        return {"ok": True, "plans": {key: plan.id for key, plan in PLANS.items()}}

    if WEB_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")
    return app


app = create_app()

__all__ = ["app", "create_app", "SESSION_COOKIE", "CSRF_COOKIE", "CSRF_HEADER"]
