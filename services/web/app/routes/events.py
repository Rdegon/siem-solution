from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from ..config import CONFIG
from ..deps import fetch_events, fetch_events_timeseries
from ..security import CurrentUser

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
logger = logging.getLogger("siem_web.events")


@router.get("/events", include_in_schema=False)
async def events_page(
    request: Request,
    user: CurrentUser,
):
    """
    Страница событий (таблица + график).
    При ошибке ClickHouse не падаем 500, а показываем сообщение.
    """
    events = []
    error: str | None = None

    try:
        events = fetch_events(limit=200)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to fetch events from ClickHouse: %s", exc)
        error = "Ошибка обращения к ClickHouse при чтении событий. См. логи сервиса siem-web."

    return templates.TemplateResponse(
        "events.html",
        {
            "request": request,
            "user": user,
            "events": events,
            "error": error,
            "base_url": CONFIG.base_url,
        },
    )


@router.get("/api/events_timeseries", include_in_schema=False)
async def events_timeseries_api(
    user: CurrentUser,
):
    """
    API для таймсерии events per minute (последние 60 минут).
    При ошибке ClickHouse возвращаем пустой массив вместо 500.
    """
    try:
        data = fetch_events_timeseries(minutes=60)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to fetch events timeseries from ClickHouse: %s", exc)
        return JSONResponse([], status_code=200)

    return JSONResponse(data)
