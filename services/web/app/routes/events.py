from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from ..config import CONFIG
from ..deps import fetch_events, fetch_events_timeseries
from ..security import CurrentUser

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/events", include_in_schema=False)
async def events_page(
    request: Request,
    user: CurrentUser = Depends(),
):
    events = fetch_events(limit=200)
    return templates.TemplateResponse(
        "events.html",
        {
            "request": request,
            "user": user,
            "events": events,
            "base_url": CONFIG.base_url,
        },
    )


@router.get("/api/events_timeseries", include_in_schema=False)
async def events_timeseries_api(
    _: CurrentUser = Depends(),
):
    data = fetch_events_timeseries(minutes=60)
    return JSONResponse(data)
