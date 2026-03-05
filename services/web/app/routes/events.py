from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .auth import get_current_user
from ..deps import fetch_events, fetch_events_timeseries
from ..templates import templates

router = APIRouter()


@router.get('/events', response_class=HTMLResponse)
async def events_page(
    request: Request,
    q: str = Query('', description='SQL-like search string'),
    auto_refresh: str = Query('off'),
    window: str = Query('24h'),
    user=Depends(get_current_user),
) -> HTMLResponse:
    error = None
    events = []
    timeseries = []
    try:
        events = fetch_events(limit=500)
        timeseries = fetch_events_timeseries(hours=24, bucket_minutes=30)
    except Exception as exc:  # noqa: BLE001
        error = f'?? ??????? ????????? ??????? ?? ClickHouse: {exc!s}'
    return templates.TemplateResponse(
        'events.html',
        {
            'request': request,
            'user': user,
            'active_page': 'events',
            'events': events,
            'timeseries': timeseries,
            'initial_query': q,
            'initial_window': window,
            'initial_auto_refresh': auto_refresh,
            'error': error,
        },
    )


@router.get('/api/events_timeseries', response_class=JSONResponse)
async def events_timeseries_api(user=Depends(get_current_user)) -> JSONResponse:
    return JSONResponse(fetch_events_timeseries(hours=24, bucket_minutes=30))
