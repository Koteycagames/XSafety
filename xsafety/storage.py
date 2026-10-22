"""SQLite-хранилище: пользователи, сессии, лимиты, история проверок.

Соединение одно на процесс и защищено блокировкой: этого достаточно для
демо-развёртывания. Все запросы параметризованы (никакой сборки SQL
строками) — см. SECURITY.md, цикл 2, V-09.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "var" / "xsafety.db"
MAX_HISTORY = 100

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    plan          TEXT NOT NULL DEFAULT 'default',
    plan_until    TEXT,
    plan_offer    TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS usage (
    user_id      TEXT NOT NULL,
    model_id     TEXT NOT NULL,
    period_start TEXT NOT NULL,
    requests     INTEGER NOT NULL DEFAULT 0,
    bytes        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, model_id, period_start)
);

CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    filename    TEXT NOT NULL,
    extension   TEXT NOT NULL,
    model       TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    findings    INTEGER NOT NULL,
    size        INTEGER NOT NULL,
    sha256      TEXT NOT NULL,
    report_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS purchases (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    plan       TEXT NOT NULL,
    offer      TEXT NOT NULL,
    price      INTEGER NOT NULL,
    discount   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    plan_until TEXT
);
CREATE INDEX IF NOT EXISTS idx_purchases_user ON purchases(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    event   TEXT NOT NULL,
    user_id TEXT,
    ip      TEXT,
    detail  TEXT
);
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(slots=True)
class User:
    id: str
    email: str
    plan: str
    plan_until: datetime | None
    plan_offer: str | None
    created_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "email": self.email,
            "plan": self.plan,
            "plan_until": iso(self.plan_until) if self.plan_until else None,
            "plan_offer": self.plan_offer,
            "created_at": iso(self.created_at),
        }


class DuplicateEmail(Exception):
    pass


class Storage:
    def __init__(self, path: str | Path | None = None) -> None:
        db_path = Path(path or os.environ.get("XSAFETY_DB") or DEFAULT_DB)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock, self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)

    # ------------------------------------------------------------------
    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    def create_user(self, email: str, password_hash: str) -> User:
        user_id = uuid.uuid4().hex
        created = utcnow()
        try:
            with self.transaction() as conn:
                conn.execute(
                    "INSERT INTO users (id, email, password_hash, plan, created_at) VALUES (?, ?, ?, 'default', ?)",
                    (user_id, email, password_hash, iso(created)),
                )
        except sqlite3.IntegrityError as exc:
            raise DuplicateEmail(email) from exc
        return User(user_id, email, "default", None, None, created)

    def _row_to_user(self, row: sqlite3.Row) -> User:
        return User(
            id=row["id"],
            email=row["email"],
            plan=row["plan"],
            plan_until=parse_iso(row["plan_until"]),
            plan_offer=row["plan_offer"],
            created_at=parse_iso(row["created_at"]) or utcnow(),
        )

    def _expire_plan(self, conn: sqlite3.Connection, row: sqlite3.Row) -> sqlite3.Row:
        """Ленивое истечение подписки: просроченный тариф становится default."""
        until = parse_iso(row["plan_until"])
        if row["plan"] != "default" and until is not None and until <= utcnow():
            conn.execute(
                "UPDATE users SET plan='default', plan_until=NULL, plan_offer=NULL WHERE id=?",
                (row["id"],),
            )
            updated = conn.execute("SELECT * FROM users WHERE id=?", (row["id"],)).fetchone()
            return updated if updated is not None else row
        return row

    def get_user(self, user_id: str) -> User | None:
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if row is None:
                return None
            return self._row_to_user(self._expire_plan(conn, row))

    def get_user_by_email(self, email: str) -> tuple[User, str] | None:
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if row is None:
                return None
            user = self._row_to_user(self._expire_plan(conn, row))
            return user, row["password_hash"]

    # ------------------------------------------------------------------
    def set_plan(self, user_id: str, plan: str, until: datetime | None, offer: str) -> User | None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE users SET plan=?, plan_until=?, plan_offer=? WHERE id=?",
                (plan, iso(until) if until else None, offer, user_id),
            )
        return self.get_user(user_id)

    def add_purchase(self, user_id: str, plan: str, offer: str, price: int, discount: str, until: datetime | None) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO purchases (id, user_id, plan, offer, price, discount, created_at, plan_until) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (uuid.uuid4().hex, user_id, plan, offer, price, discount, iso(utcnow()), iso(until) if until else None),
            )

    # ------------------------------------------------------------------
    def create_session(self, user_id: str, token_hash: str, expires_at: datetime, user_agent: str = "") -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, user_agent) VALUES (?, ?, ?, ?, ?)",
                (token_hash, user_id, iso(utcnow()), iso(expires_at), user_agent[:160]),
            )

    def user_for_session(self, token_hash: str) -> User | None:
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash=? AND s.expires_at > ?",
                (token_hash, iso(utcnow())),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_user(self._expire_plan(conn, row))

    def delete_session(self, token_hash: str) -> None:
        with self.transaction() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))

    def purge_sessions(self) -> None:
        with self.transaction() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (iso(utcnow()),))

    # ------------------------------------------------------------------
    def usage_snapshot(self, user_id: str, period_start: datetime) -> dict[str, tuple[int, int]]:
        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT model_id, requests, bytes FROM usage WHERE user_id=? AND period_start=?",
                (user_id, iso(period_start)),
            ).fetchall()
        return {row["model_id"]: (int(row["requests"]), int(row["bytes"])) for row in rows}

    def reserve_usage(
        self,
        user_id: str,
        model_id: str,
        size: int,
        period_start: datetime,
        max_requests: int,
        max_bytes: int | None,
    ) -> tuple[bool, str, int, int]:
        """Атомарно проверяет и списывает квоту.

        Возвращает ``(ok, reason, requests, bytes)``. Проверка и запись
        выполняются в одной транзакции, поэтому параллельные загрузки не
        могут превысить суточный лимит.
        """
        period = iso(period_start)
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO usage (user_id, model_id, period_start, requests, bytes)
                VALUES (?, ?, ?, 0, 0)
                ON CONFLICT(user_id, model_id, period_start) DO NOTHING
                """,
                (user_id, model_id, period),
            )
            row = conn.execute(
                "SELECT requests, bytes FROM usage WHERE user_id=? AND model_id=? AND period_start=?",
                (user_id, model_id, period),
            ).fetchone()
            requests = int(row["requests"])
            used_bytes = int(row["bytes"])
            if requests + 1 > max_requests:
                return False, "requests", requests, used_bytes
            if max_bytes is not None and used_bytes + size > max_bytes:
                return False, "bytes", requests, used_bytes
            conn.execute(
                "UPDATE usage SET requests = requests + 1, bytes = bytes + ? WHERE user_id=? AND model_id=? AND period_start=?",
                (size, user_id, model_id, period),
            )
        return True, "ok", requests + 1, used_bytes + size

    def refund_usage(self, user_id: str, model_id: str, size: int, period_start: datetime) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE usage SET requests = MAX(requests - 1, 0), bytes = MAX(bytes - ?, 0)
                WHERE user_id=? AND model_id=? AND period_start=?
                """,
                (size, user_id, model_id, iso(period_start)),
            )

    def reset_usage(self, user_id: str | None = None) -> int:
        with self.transaction() as conn:
            if user_id:
                cursor = conn.execute("DELETE FROM usage WHERE user_id=?", (user_id,))
            else:
                cursor = conn.execute("DELETE FROM usage")
        return cursor.rowcount

    def purge_usage(self, older_than: timedelta = timedelta(days=30)) -> None:
        cutoff = iso(utcnow() - older_than)
        with self.transaction() as conn:
            conn.execute("DELETE FROM usage WHERE period_start < ?", (cutoff,))

    # ------------------------------------------------------------------
    def add_scan(self, user_id: str, payload: dict[str, object]) -> str:
        scan_id = uuid.uuid4().hex
        findings = payload.get("findings") or []
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO scans (id, user_id, created_at, filename, extension, model, verdict, severity, findings, size, sha256, report_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    user_id,
                    iso(utcnow()),
                    str(payload.get("filename", ""))[:180],
                    str(payload.get("extension", ""))[:16],
                    str(payload.get("model", ""))[:16],
                    str(payload.get("verdict", "suspicious"))[:16],
                    str(payload.get("worst_severity", "info"))[:16],
                    len(findings) if isinstance(findings, list) else 0,
                    int(payload.get("size", 0) or 0),
                    str(payload.get("sha256", ""))[:64],
                    json.dumps(payload, ensure_ascii=False)[:400_000],
                ),
            )
            conn.execute(
                """
                DELETE FROM scans WHERE user_id=? AND id NOT IN (
                    SELECT id FROM scans WHERE user_id=? ORDER BY rowid DESC LIMIT ?
                )
                """,
                (user_id, user_id, MAX_HISTORY),
            )
        return scan_id

    def list_scans(self, user_id: str, limit: int = 30) -> list[dict[str, object]]:
        limit = max(1, min(limit, 100))
        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT id, created_at, filename, extension, model, verdict, severity, findings, size FROM scans WHERE user_id=? ORDER BY rowid DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_scan(self, user_id: str, scan_id: str) -> dict[str, object] | None:
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id=? AND user_id=?",
                (scan_id, user_id),
            ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(row["report_json"])
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        payload["scan_id"] = row["id"]
        payload["created_at"] = row["created_at"]
        return payload

    def delete_scan(self, user_id: str, scan_id: str) -> bool:
        with self.transaction() as conn:
            cursor = conn.execute("DELETE FROM scans WHERE id=? AND user_id=?", (scan_id, user_id))
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    def audit(self, event: str, user_id: str | None = None, ip: str = "", detail: str = "") -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO audit_log (ts, event, user_id, ip, detail) VALUES (?, ?, ?, ?, ?)",
                (iso(utcnow()), event[:48], user_id, ip[:64], detail[:240]),
            )


__all__ = [
    "DuplicateEmail",
    "Storage",
    "User",
    "iso",
    "parse_iso",
    "utcnow",
    "MAX_HISTORY",
]
