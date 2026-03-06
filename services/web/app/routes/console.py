
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .auth import get_current_user
from ..deps import (
    fetch_alert_severity_breakdown,
    fetch_alert_status_breakdown,
    fetch_asset_categories,
    fetch_assets,
    fetch_dashboard_metrics,
    fetch_detection_rules,
    fetch_events_timeseries,
    fetch_recent_alerts,
    fetch_resource_overview,
    fetch_severity_breakdown,
    save_sigma_rule,
    test_detection_rule,
    fetch_top_categories,
    fetch_top_sources,
)
from ..templates import templates

router = APIRouter()

DEFAULT_SIGMA_RULE_YAML = """
title: Linux Custom Auditd Rule
id: sigma-linux-custom-auditd
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: audit_execve
    process.command_line|contains: curl
  condition: selection
level: medium
tags:
  - attack.execution
  - custom
""".strip()
RULE_ENTITY_FIELDS = [
    'log_source',
    'source.ip',
    'user.name',
    'user.target.name',
]


def _render_assets_page(
    request: Request,
    user: dict,
    *,
    error: str | None = None,
    status: str | None = None,
    rule_form: dict | None = None,
) -> HTMLResponse:
    assets = []
    asset_categories = []
    detection_rules = []
    load_error = error
    try:
        assets = fetch_assets(limit=50, hours=24)
        asset_categories = fetch_asset_categories()
        detection_rules = fetch_detection_rules(limit=200)
    except Exception as exc:  # noqa: BLE001
        load_error = load_error or f'Unable to load assets and detection catalog: {exc!s}'
    draft = {
        'sigma_yaml': DEFAULT_SIGMA_RULE_YAML,
        'threshold': 1,
        'window_s': 300,
        'entity_field': 'log_source',
    }
    if rule_form:
        draft.update(rule_form)
    return templates.TemplateResponse(
        'assets.html',
        {
            'request': request,
            'user': user,
            'active_page': 'assets',
            'assets': assets,
            'asset_categories': asset_categories,
            'detection_rules': detection_rules,
            'entity_fields': RULE_ENTITY_FIELDS,
            'rule_form': draft,
            'error': load_error,
            'status': status,
        },
    )


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
        'alert_severity_breakdown': [],
        'alert_status_breakdown': [],
        'top_sources': [],
        'top_categories': [],
        'recent_alerts': [],
        'error': None,
    }
    try:
        context['metrics'] = fetch_dashboard_metrics()
        context['timeline'] = fetch_events_timeseries(hours=24, bucket_minutes=60)
        context['severity_breakdown'] = fetch_severity_breakdown(hours=24)
        context['alert_severity_breakdown'] = fetch_alert_severity_breakdown(hours=24)
        context['alert_status_breakdown'] = fetch_alert_status_breakdown(hours=24)
        context['top_sources'] = fetch_top_sources(limit=8, hours=24)
        context['top_categories'] = fetch_top_categories(limit=8, hours=24)
        context['recent_alerts'] = fetch_recent_alerts(limit=10)
    except Exception as exc:  # noqa: BLE001
        context['error'] = f'Unable to load dashboard data from ClickHouse: {exc!s}'
    return templates.TemplateResponse('dashboard.html', context)


@router.get('/assets', response_class=HTMLResponse)
async def assets_page(
    request: Request,
    created_rule_id: int | None = None,
    user=Depends(get_current_user),
) -> HTMLResponse:
    status = None
    if created_rule_id is not None:
        status = f'Detection rule #{created_rule_id} was saved and synchronized to stream correlation.'
    return _render_assets_page(request, user, status=status)


@router.post('/assets/rules', response_class=HTMLResponse)
async def create_sigma_rule(
    request: Request,
    sigma_yaml: str = Form(...),
    threshold: int = Form(1),
    window_s: int = Form(300),
    entity_field: str = Form('log_source'),
    user=Depends(get_current_user),
) -> HTMLResponse:
    try:
        rule = save_sigma_rule(
            sigma_yaml=sigma_yaml,
            threshold=max(1, threshold),
            window_s=max(60, window_s),
            entity_field=entity_field,
            author=str(getattr(user, 'username', 'web') or 'web'),
        )
    except Exception as exc:  # noqa: BLE001
        return _render_assets_page(
            request,
            user,
            error=f'Unable to save Sigma rule: {exc!s}',
            rule_form={
                'sigma_yaml': sigma_yaml,
                'threshold': threshold,
                'window_s': window_s,
                'entity_field': entity_field,
            },
        )
    return RedirectResponse(
        url=f"/assets?created_rule_id={int(rule['id'])}",
        status_code=303,
    )


@router.post('/api/rules/{rule_id}/test', response_class=JSONResponse)
async def test_rule_api(rule_id: int, user=Depends(get_current_user)) -> JSONResponse:
    try:
        return JSONResponse(test_detection_rule(rule_id))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({'error': str(exc)}, status_code=400)


@router.get('/resources', response_class=HTMLResponse)
async def resources_page(request: Request, user=Depends(get_current_user)) -> HTMLResponse:
    overview = {}
    sources = []
    error = None
    try:
        overview = fetch_resource_overview()
        sources = fetch_top_sources(limit=10, hours=24)
    except Exception as exc:  # noqa: BLE001
        error = f'Unable to load platform resources: {exc!s}'
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
