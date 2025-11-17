from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from app.routes.auth import get_current_user
from ..deps import fetch_events, fetch_events_timeseries
from ..templates import templates

router = APIRouter()


@router.get("/events", response_class=HTMLResponse)
async def events_page(
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
) -> HTMLResponse:
    """
    Страница последних событий + график Events per minute (последние 60 минут).
    При ошибке ClickHouse показываем текст ошибки и пустые данные.
    """
    error: Optional[str] = None
    events: List[Dict[str, Any]] = []
    timeseries: List[Dict[str, Any]] = []

    try:
        events = fetch_events(limit=200)
        timeseries = fetch_events_timeseries(minutes=60)
    except Exception as exc:  # noqa: BLE001
        error = f"Ошибка обращения к ClickHouse при чтении событий: {exc!s}"

    return templates.TemplateResponse(
        "events.html",
        {
            "request": request,
            "user": user,
            "events": events,
            "timeseries": timeseries,
            "error": error,
        },
    )
