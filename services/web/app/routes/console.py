
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .auth import get_current_user
from ..config import CONFIG
from ..deps import (
    archive_events_to_cold,
    fetch_alert_severity_breakdown,
    fetch_alert_status_breakdown,
    fetch_active_list_items,
    fetch_asset_categories,
    fetch_assets,
    fetch_cmdb_assets,
    fetch_dashboard_metrics,
    fetch_detection_rules,
    fetch_collector_inventory,
    fetch_events_timeseries,
    fetch_normalizer_rules,
    fetch_recent_alerts,
    fetch_resource_overview,
    fetch_severity_breakdown,
    fetch_source_inventory,
    import_cmdb_assets,
    import_threat_intel_entries,
    sync_observed_assets_to_cmdb,
    fetch_threat_intel_entries,
    fetch_top_target_ports,
    save_active_list_item,
    save_cmdb_asset,
    save_sigma_rule,
    save_threat_intel_indicator,
    test_detection_rule,
    fetch_top_categories,
    fetch_top_sources,
)
from ..security import require_permissions
from ..templates import templates
from ..ui_text import investigation_playbooks, ui_context

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
    normalizer_rules = []
    active_list_items = []
    cmdb_assets = []
    threat_intel_entries = []
    load_error = error
    try:
        assets = fetch_assets(limit=50, hours=24)
        asset_categories = fetch_asset_categories()
        detection_rules = fetch_detection_rules(limit=200)
        normalizer_rules = fetch_normalizer_rules(limit=120)
        active_list_items = fetch_active_list_items(limit=200)
        cmdb_assets = fetch_cmdb_assets(limit=200)
        threat_intel_entries = fetch_threat_intel_entries(limit=200)
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
        ui_context(
            request,
            user,
            'assets',
            assets=assets,
            asset_categories=asset_categories,
            detection_rules=detection_rules,
            normalizer_rules=normalizer_rules,
            active_list_items=active_list_items,
            cmdb_assets=cmdb_assets,
            threat_intel_entries=threat_intel_entries,
            entity_fields=RULE_ENTITY_FIELDS,
            rule_form=draft,
            error=load_error,
            status=status,
        ),
    )


@router.get('/', include_in_schema=False)
async def index(request: Request, user=Depends(get_current_user)):
    return RedirectResponse(url='/dashboards', status_code=307)


@router.get('/dashboards', response_class=HTMLResponse)
async def dashboard_page(request: Request, user=Depends(get_current_user)) -> HTMLResponse:
    context = ui_context(
        request,
        user,
        'dashboards',
        metrics={},
        timeline=[],
        severity_breakdown=[],
        alert_severity_breakdown=[],
        alert_status_breakdown=[],
        top_sources=[],
        top_target_ports=[],
        top_categories=[],
        recent_alerts=[],
        error=None,
    )
    try:
        context['metrics'] = fetch_dashboard_metrics()
        context['timeline'] = fetch_events_timeseries(hours=24, bucket_minutes=60)
        context['severity_breakdown'] = fetch_severity_breakdown(hours=24)
        context['alert_severity_breakdown'] = fetch_alert_severity_breakdown(hours=24)
        context['alert_status_breakdown'] = fetch_alert_status_breakdown(hours=24)
        context['top_sources'] = fetch_top_sources(limit=8, hours=24)
        context['top_target_ports'] = fetch_top_target_ports(limit=10, hours=24)
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
    user=Depends(require_permissions('rules:write')),
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


@router.post('/assets/active-lists', response_class=HTMLResponse)
async def create_active_list_item(
    request: Request,
    list_name: str = Form(...),
    list_kind: str = Form('watch'),
    item_type: str = Form(...),
    item_value: str = Form(...),
    item_label: str = Form(''),
    tags: str = Form(''),
    user=Depends(require_permissions('active_lists:write')),
) -> HTMLResponse:
    try:
        item = save_active_list_item(
            list_name=list_name,
            list_kind=list_kind,
            item_type=item_type,
            item_value=item_value,
            item_label=item_label,
            tags=tags,
        )
    except Exception as exc:  # noqa: BLE001
        return _render_assets_page(request, user, error=f'Unable to save active list item: {exc!s}')
    return _render_assets_page(
        request,
        user,
        status=f"Active list item saved: {item['list_name']} / {item['item_value']}",
    )


@router.post('/assets/cmdb', response_class=HTMLResponse)
async def create_cmdb_asset(
    request: Request,
    asset_id: str = Form(...),
    asset_type: str = Form('server'),
    hostname: str = Form(''),
    ip: str = Form(''),
    owner: str = Form(''),
    criticality: str = Form('medium'),
    environment: str = Form('prod'),
    business_service: str = Form(''),
    os_family: str = Form(''),
    expected_ports: str = Form(''),
    tags: str = Form(''),
    notes: str = Form(''),
    user=Depends(require_permissions('cmdb:write')),
) -> HTMLResponse:
    try:
        item = save_cmdb_asset(
            asset_id=asset_id,
            asset_type=asset_type,
            hostname=hostname,
            ip=ip,
            owner=owner,
            criticality=criticality,
            environment=environment,
            business_service=business_service,
            os_family=os_family,
            expected_ports=expected_ports,
            tags=tags,
            notes=notes,
        )
    except Exception as exc:  # noqa: BLE001
        return _render_assets_page(request, user, error=f'Unable to save CMDB asset: {exc!s}')
    return _render_assets_page(request, user, status=f"CMDB asset saved: {item['asset_id']}")


@router.post('/assets/cmdb/import', response_class=HTMLResponse)
async def import_cmdb_asset_records(
    request: Request,
    payload: str = Form(...),
    user=Depends(require_permissions('cmdb:write')),
) -> HTMLResponse:
    try:
        result = import_cmdb_assets(payload)
    except Exception as exc:  # noqa: BLE001
        return _render_assets_page(request, user, error=f'Unable to import CMDB assets: {exc!s}')
    return _render_assets_page(request, user, status=f"CMDB import completed: {result['saved']} saved from {result['parsed']} parsed records.")


@router.post('/assets/cmdb/sync-observed', response_class=HTMLResponse)
async def sync_observed_assets(
    request: Request,
    hours: int = Form(72),
    limit: int = Form(200),
    user=Depends(require_permissions('cmdb:write')),
) -> HTMLResponse:
    try:
        result = sync_observed_assets_to_cmdb(hours=max(1, hours), limit=max(1, min(1000, limit)))
    except Exception as exc:  # noqa: BLE001
        return _render_assets_page(request, user, error=f'Unable to sync observed assets: {exc!s}')
    return _render_assets_page(request, user, status=f"Observed asset sync completed: {result['created']} provisional assets created.")


@router.post('/assets/threat-intel', response_class=HTMLResponse)
async def create_threat_intel_item(
    request: Request,
    indicator_type: str = Form(...),
    indicator: str = Form(...),
    provider: str = Form(''),
    severity: str = Form('medium'),
    confidence: int = Form(50),
    description: str = Form(''),
    tags: str = Form(''),
    user=Depends(require_permissions('threat_intel:write')),
) -> HTMLResponse:
    try:
        item = save_threat_intel_indicator(
            indicator_type=indicator_type,
            indicator=indicator,
            provider=provider,
            severity=severity,
            confidence=confidence,
            description=description,
            tags=tags,
        )
    except Exception as exc:  # noqa: BLE001
        return _render_assets_page(request, user, error=f'Unable to save threat intel indicator: {exc!s}')
    return _render_assets_page(request, user, status=f"Threat intel indicator saved: {item['indicator_type']} / {item['indicator']}")


@router.post('/assets/threat-intel/import', response_class=HTMLResponse)
async def import_threat_intel_records(
    request: Request,
    payload: str = Form(...),
    user=Depends(require_permissions('threat_intel:write')),
) -> HTMLResponse:
    try:
        result = import_threat_intel_entries(payload)
    except Exception as exc:  # noqa: BLE001
        return _render_assets_page(request, user, error=f'Unable to import threat intel: {exc!s}')
    return _render_assets_page(request, user, status=f"Threat intel import completed: {result['saved']} saved from {result['parsed']} parsed records.")


@router.post('/api/rules/{rule_id}/test', response_class=JSONResponse)
async def test_rule_api(rule_id: int, user=Depends(require_permissions('rules:test'))) -> JSONResponse:
    try:
        return JSONResponse(test_detection_rule(rule_id))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({'error': str(exc)}, status_code=400)


@router.post('/api/resources/archive-hot', response_class=JSONResponse)
async def archive_hot_events_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions('storage:archive')),
) -> JSONResponse:
    hours = int(payload.get('older_than_hours', CONFIG.hot_retention_hours) or CONFIG.hot_retention_hours)
    try:
        return JSONResponse(archive_events_to_cold(max(1, hours)))
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
        ui_context(
            request,
            user,
            'resources',
            overview=overview,
            sources=sources,
            error=error,
        ),
    )


@router.get('/sources', response_class=HTMLResponse)
async def sources_page(request: Request, user=Depends(get_current_user)) -> HTMLResponse:
    error = None
    sources = []
    try:
        sources = fetch_source_inventory(limit=300, hours=24)
    except Exception as exc:  # noqa: BLE001
        error = f'Unable to load source inventory: {exc!s}'
    return templates.TemplateResponse(
        'sources.html',
        ui_context(
            request,
            user,
            'sources',
            sources=sources,
            error=error,
        ),
    )


@router.get('/collectors', response_class=HTMLResponse)
async def collectors_page(request: Request, user=Depends(get_current_user)) -> HTMLResponse:
    error = None
    collectors = []
    try:
        collectors = fetch_collector_inventory(hours=24)
    except Exception as exc:  # noqa: BLE001
        error = f'Unable to load collector inventory: {exc!s}'
    return templates.TemplateResponse(
        'collectors.html',
        ui_context(
            request,
            user,
            'collectors',
            collectors=collectors,
            error=error,
        ),
    )


@router.get('/documentation', response_class=HTMLResponse)
async def documentation_page(request: Request, user=Depends(get_current_user)) -> HTMLResponse:
    context = ui_context(request, user, 'documentation')
    context['playbooks'] = investigation_playbooks(context['ui_lang'])
    return templates.TemplateResponse('documentation.html', context)
