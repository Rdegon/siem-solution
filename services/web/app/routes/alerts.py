
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .auth import get_current_user
from ..security import require_permissions
from ..deps import (
    INCIDENT_STATUS_TRANSITIONS,
    fetch_alert_history,
    fetch_alert_metrics,
    fetch_alerts_agg,
    fetch_alerts_raw,
    update_alert_assignment,
)
from ..templates import templates
from ..ui_text import ui_context

router = APIRouter()


@router.get('/alerts', response_class=HTMLResponse)
async def alerts_page(
    request: Request,
    view: str = Query('agg'),
    focus: str = Query(''),
    user=Depends(get_current_user),
) -> HTMLResponse:
    error = None
    alerts_agg = []
    alerts_raw = []
    metrics = {}
    try:
        alerts_agg = fetch_alerts_agg(limit=200)
        alerts_raw = fetch_alerts_raw(limit=200)
        metrics = fetch_alert_metrics()
    except Exception as exc:  # noqa: BLE001
        error = f'Unable to load incidents and alert queue: {exc!s}'
    return templates.TemplateResponse(
        'alerts.html',
        ui_context(
            request,
            user,
            'alerts',
            alerts_agg=alerts_agg,
            alerts_raw=alerts_raw,
            metrics=metrics,
            view='raw' if view == 'raw' else 'agg',
            focus=focus,
            status_transitions={key: sorted(values) for key, values in INCIDENT_STATUS_TRANSITIONS.items()},
            error=error,
        ),
    )


@router.get('/alerts_raw', include_in_schema=False)
async def alerts_raw_redirect(request: Request, user=Depends(get_current_user)):
    return RedirectResponse(url='/alerts?view=raw', status_code=307)


@router.get('/alerts_agg', include_in_schema=False)
async def alerts_agg_redirect(request: Request, user=Depends(get_current_user)):
    return RedirectResponse(url='/alerts?view=agg', status_code=307)


@router.post('/api/alerts/{view}/{record_id}', response_class=JSONResponse)
async def update_alert_api(
    view: str,
    record_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions('incidents:update')),
) -> JSONResponse:
    if view not in {'raw', 'agg'}:
        return JSONResponse({'error': 'Unsupported alert view'}, status_code=400)
    try:
        result = update_alert_assignment(
            view,
            record_id,
            status=str(payload.get('status', 'new') or 'new'),
            assignee=str(payload.get('assignee', '') or ''),
            changed_by=str(getattr(user, 'username', 'web') or 'web'),
            note=str(payload.get('note', '') or ''),
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({'error': str(exc)}, status_code=400)
    return JSONResponse(result)


@router.get('/api/alerts/{view}/{record_id}/history', response_class=JSONResponse)
async def alert_history_api(view: str, record_id: str, user=Depends(get_current_user)) -> JSONResponse:
    if view not in {'raw', 'agg'}:
        return JSONResponse({'error': 'Unsupported alert view'}, status_code=400)
    try:
        return JSONResponse({'history': fetch_alert_history(view, record_id)})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({'error': str(exc)}, status_code=400)
