"""Пароли, сессии, CSRF и защита от перебора.

Пароли хранятся как PBKDF2-HMAC-SHA256 с солью. Токен сессии выдаётся
клиенту один раз, в базе лежит только его SHA-256: утечка базы не даёт
войти в чужие аккаунты (см. SECURITY.md, V-10/V-11).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from collections import defaultdict, deque

PBKDF2_ITERATIONS = 210_000
PASSWORD_MIN = 8
PASSWORD_MAX = 128
SESSION_TTL_SECONDS = 30 * 24 * 3600

_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")
_DUMMY_HASH = (
    "pbkdf2_sha256$210000$"
    + "0" * 32
    + "$"
    + "0" * 64
)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def valid_email(email: str) -> bool:
    return bool(_EMAIL.match(email)) and len(email) <= 254


def validate_password(password: str) -> str | None:
    if len(password) < PASSWORD_MIN:
        return f"Пароль короче {PASSWORD_MIN} символов."
    if len(password) > PASSWORD_MAX:
        return f"Пароль длиннее {PASSWORD_MAX} символов."
    return None


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def burn_password_check(password: str) -> None:
    """Тратит столько же времени, сколько реальная проверка.

    Нужно, чтобы по времени ответа нельзя было определить, существует ли
    аккаунт с таким e-mail.
    """
    hashlib.pbkdf2_hmac("sha256", password[:PASSWORD_MAX].encode("utf-8"), b"\x00" * 16, PBKDF2_ITERATIONS)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_csrf_token() -> str:
    return secrets.token_urlsafe(24)


def csrf_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class LoginThrottle:
    """Простое окно попыток входа: 5 неудач за 5 минут по ключу ip|email."""

    def __init__(self, limit: int = 5, window: float = 300.0) -> None:
        self.limit = limit
        self.window = window
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        bucket = self._events[key]
        while bucket and now - bucket[0] > self.window:
            bucket.popleft()
        return bucket

    def blocked(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            return len(self._prune(key, now)) >= self.limit

    def fail(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._prune(key, now).append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)


class RateLimiter:
    """Лимит действий в минуту (защита от злоупотребления сканером)."""

    def __init__(self, limit: int = 30, window: float = 60.0) -> None:
        self.limit = limit
        self.window = window
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._events[key]
            while bucket and now - bucket[0] > self.window:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True


login_throttle = LoginThrottle()
scan_limiter = RateLimiter(limit=40, window=60.0)


__all__ = [
    "LoginThrottle",
    "RateLimiter",
    "SESSION_TTL_SECONDS",
    "burn_password_check",
    "csrf_equal",
    "hash_password",
    "login_throttle",
    "new_csrf_token",
    "new_session_token",
    "normalize_email",
    "scan_limiter",
    "token_fingerprint",
    "valid_email",
    "validate_password",
    "verify_password",
]
