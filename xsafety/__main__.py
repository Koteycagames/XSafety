"""Запуск сервера: ``python -m xsafety``."""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.environ.get("XSAFETY_HOST", "0.0.0.0")
    port = int(os.environ.get("XSAFETY_PORT", "8000"))
    reload_enabled = os.environ.get("XSAFETY_RELOAD", "0") == "1"
    uvicorn.run(
        "xsafety.api:app",
        host=host,
        port=port,
        reload=reload_enabled,
        proxy_headers=True,
        forwarded_allow_ips="*",
        log_level=os.environ.get("XSAFETY_LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    main()
