"""
main.py
-------
Точка входа для SIEM Web UI (FastAPI).

Запуск под uvicorn:
    /opt/siem/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000

Используемые переменные окружения:
см. app.config.CONFIG
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import CONFIG
from app.routes import alerts, auth, events, health, root

logger = logging.getLogger("siem_web")


def create_app() -> FastAPI:
    app = FastAPI(
        title="SIEM Web UI",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Сохраняем немного информации в state, чтобы удобно использовать в шаблонах
    app.state.instance_name = CONFIG.instance_name
    app.state.env = CONFIG.env

    # CORS можно зажать сильнее, пока открываем только base_url
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[CONFIG.base_url],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Подключаем роутеры
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(alerts.router)
    app.include_router(events.router)
    app.include_router(root.router)

    return app


app = create_app()
