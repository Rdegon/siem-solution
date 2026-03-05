from typing import List, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from .auth import get_current_user
from ..deps import fetch_events, fetch_events_timeseries
from ..templates import templates

router = APIRouter()


@router.get("/events", response_class=HTMLResponse)
async def events_page(
    request: Request,
    user = Depends(get_current_user),
) -> HTMLResponse:
    error: Optional[str] = None
    events: List[dict] = []
    timeseries: List[dict] = []

    try:
        events = fetch_events(limit=200)
        timeseries = fetch_events_timeseries(minutes=60)
    except Exception as exc:  # noqa: BLE001
        error = f"?????? ????????? ? ClickHouse ??? ?????? ???????: {exc!s}"

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
