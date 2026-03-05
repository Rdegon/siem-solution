from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .auth import get_current_user
from ..deps import (
    fetch_assets,
    fetch_dashboard_metrics,
    fetch_events_timeseries,
    fetch_recent_alerts,
    fetch_resource_overview,
    fetch_severity_breakdown,
    fetch_top_sources,
)
from ..templates import templates

router = APIRouter()


@router.get('/', include_in_schema=False)
async def index(request: Request, user=Depends(get_current_user)):
    return RedirectResponse(url='/dashboards', status_code=307)


@router.get('/dashboards', response_class=HTMLResponse)
async def dashboard_page(request: Request, user=Depends(get_current_user)) -> HTMLResponse:
    context = {
        'request': request,
        'user': user,
        'active_page': 'dashboards',
        'metrics': {},
        'timeline': [],
        'severity_breakdown': [],
        'top_sources': [],
        'recent_alerts': [],
        'error': None,
    }
    try:
        context['metrics'] = fetch_dashboard_metrics()
        context['timeline'] = fetch_events_timeseries(hours=24, bucket_minutes=30)
        context['severity_breakdown'] = fetch_severity_breakdown(hours=24)
        context['top_sources'] = fetch_top_sources(limit=8, hours=24)
        context['recent_alerts'] = fetch_recent_alerts(limit=10)
    except Exception as exc:  # noqa: BLE001
        context['error'] = f'?? ??????? ????????? dashboard ??????: {exc!s}'
    return templates.TemplateResponse('dashboard.html', context)


@router.get('/assets', response_class=HTMLResponse)
async def assets_page(request: Request, user=Depends(get_current_user)) -> HTMLResponse:
    assets = []
    error = None
    try:
        assets = fetch_assets(limit=50, hours=24)
    except Exception as exc:  # noqa: BLE001
        error = f'?? ??????? ????????? inventory ???????: {exc!s}'
    return templates.TemplateResponse(
        'assets.html',
        {
            'request': request,
            'user': user,
            'active_page': 'assets',
            'assets': assets,
            'error': error,
        },
    )


@router.get('/resources', response_class=HTMLResponse)
async def resources_page(request: Request, user=Depends(get_current_user)) -> HTMLResponse:
    overview = {}
    sources = []
    error = None
    try:
        overview = fetch_resource_overview()
        sources = fetch_top_sources(limit=10, hours=24)
    except Exception as exc:  # noqa: BLE001
        error = f'?? ??????? ????????? ????????? ?????: {exc!s}'
    return templates.TemplateResponse(
        'resources.html',
        {
            'request': request,
            'user': user,
            'active_page': 'resources',
            'overview': overview,
            'sources': sources,
            'error': error,
        },
    )
