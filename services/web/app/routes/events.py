
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .auth import get_current_user
from ..security import require_permissions
from ..deps import EVENT_ROW_LIMIT_DEFAULT, execute_event_query
from ..templates import templates
from ..ui_text import ui_context

router = APIRouter()


@router.get('/events', response_class=HTMLResponse)
async def events_page(
    request: Request,
    q: str = Query('', description='SQL query or expression for events_view'),
    window: str = Query('24h'),
    storage: str = Query('hot'),
    auto_refresh: str = Query('off'),
    limit: int = Query(EVENT_ROW_LIMIT_DEFAULT, ge=25, le=1000),
    user=Depends(get_current_user),
) -> HTMLResponse:
    return templates.TemplateResponse(
        'events.html',
        ui_context(
            request,
            user,
            'events',
            initial_query=q,
            initial_window=window,
            initial_storage=storage,
            initial_auto_refresh=auto_refresh,
            initial_limit=limit,
        ),
    )


@router.post('/api/events/query', response_class=JSONResponse)
async def events_query_api(payload: dict = Body(default={}), user=Depends(require_permissions('events:query'))) -> JSONResponse:
    query_text = str(payload.get('query', '') or '')
    window = str(payload.get('window', '24h') or '24h')
    storage = str(payload.get('storage', 'hot') or 'hot')
    limit = int(payload.get('limit', EVENT_ROW_LIMIT_DEFAULT) or EVENT_ROW_LIMIT_DEFAULT)
    offset = int(payload.get('offset', 0) or 0)
    try:
        return JSONResponse(execute_event_query(query_text=query_text, window=window, limit=limit, storage=storage, offset=offset))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({'error': str(exc)}, status_code=400)
