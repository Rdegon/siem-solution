"""
main.py
-------
Entry point for the Rdegon SIEM web UI (FastAPI).
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import CONFIG
from app.routes import alerts, auth, console, events, health

logger = logging.getLogger('siem_web')


def create_app() -> FastAPI:
    app = FastAPI(
        title='SIEM Web UI',
        version='0.2.0',
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.instance_name = CONFIG.instance_name
    app.state.env = CONFIG.env
    app.state.base_url = CONFIG.base_url
    app.state.hot_retention_hours = CONFIG.hot_retention_hours
    app.state.cold_retention_days = CONFIG.cold_retention_days
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[CONFIG.base_url],
        allow_credentials=True,
        allow_methods=['GET', 'POST'],
        allow_headers=['*'],
    )
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(console.router)
    app.include_router(alerts.router)
    app.include_router(events.router)
    return app


app = create_app()
