from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Body, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .auth import get_current_user
from ..config import CONFIG
from ..deps import (
    archive_events_to_cold,
    fetch_active_list_items,
    fetch_asset_categories,
    fetch_assets,
    fetch_cmdb_assets,
    fetch_collector_inventory,
    fetch_dashboard_snapshot,
    fetch_detection_rules,
    fetch_normalizer_rules,
    fetch_platform_status,
    fetch_resource_overview,
    fetch_source_inventory,
    fetch_threat_intel_entries,
    fetch_top_sources,
    import_cmdb_assets,
    import_threat_intel_entries,
    save_active_list_item,
    save_cmdb_asset,
    save_sigma_rule,
    save_threat_intel_indicator,
    sync_observed_assets_to_cmdb,
    test_detection_rule,
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
    "log_source",
    "source.ip",
    "user.name",
    "user.target.name",
]

ASSET_TAB_TO_PAGE = {
    "overview": "assets.tab.overview",
    "devices": "assets.tab.devices",
    "collectors": "assets.tab.collectors",
    "rules": "assets.tab.rules",
    "normalizers": "assets.tab.normalizers",
    "active-lists": "assets.tab.active_lists",
    "cmdb": "assets.tab.cmdb",
    "threat-intel": "assets.tab.threat_intel",
}


def _safe_asset_tab(value: str | None) -> str:
    candidate = str(value or "overview").strip().lower()
    return candidate if candidate in ASSET_TAB_TO_PAGE else "overview"


def _assets_tabs(request: Request, tab: str) -> list[dict[str, str | bool]]:
    lang = str(request.cookies.get("ui_lang", "en") or "en").strip().lower()
    labels = ui_context(request, None, "assets")["t"] if lang in {"en", "ru"} else ui_context(request, None, "assets")["t"]
    tabs = []
    for tab_id, label_key in ASSET_TAB_TO_PAGE.items():
        tabs.append(
            {
                "id": tab_id,
                "label": labels[label_key],
                "href": f"/assets?tab={quote(tab_id)}",
                "active": tab_id == tab,
            }
        )
    return tabs


def _dashboard_context(request: Request, user: dict) -> dict:
    context = ui_context(
        request,
        user,
        "dashboards",
        metrics={},
        timeline=[],
        alert_timeline=[],
        severity_breakdown=[],
        alert_severity_breakdown=[],
        alert_status_breakdown=[],
        top_sources=[],
        top_target_ports=[],
        top_categories=[],
        recent_alerts=[],
        platform_status={},
        error=None,
    )
    context.update(fetch_dashboard_snapshot())
    return context


def _render_assets_page(
    request: Request,
    user: dict,
    *,
    error: str | None = None,
    status: str | None = None,
    rule_form: dict | None = None,
    asset_tab: str = "overview",
    focus_kind: str = "",
    focus_id: str = "",
) -> HTMLResponse:
    assets = []
    asset_categories = []
    detection_rules = []
    normalizer_rules = []
    active_list_items = []
    cmdb_assets = []
    threat_intel_entries = []
    collectors = []
    load_error = error
    try:
        assets = fetch_assets(limit=80, hours=24)
        asset_categories = fetch_asset_categories()
        detection_rules = fetch_detection_rules(limit=250)
        normalizer_rules = fetch_normalizer_rules(limit=160)
        active_list_items = fetch_active_list_items(limit=250)
        cmdb_assets = fetch_cmdb_assets(limit=250)
        threat_intel_entries = fetch_threat_intel_entries(limit=250)
        collectors = fetch_collector_inventory(hours=24)
    except Exception as exc:  # noqa: BLE001
        load_error = load_error or f"Unable to load assets and detection catalog: {exc!s}"
    draft = {
        "sigma_yaml": DEFAULT_SIGMA_RULE_YAML,
        "threshold": 1,
        "window_s": 300,
        "entity_field": "log_source",
    }
    if rule_form:
        draft.update(rule_form)
    return templates.TemplateResponse(
        "assets.html",
        ui_context(
            request,
            user,
            "assets",
            assets=assets,
            asset_categories=asset_categories,
            detection_rules=detection_rules,
            normalizer_rules=normalizer_rules,
            active_list_items=active_list_items,
            cmdb_assets=cmdb_assets,
            threat_intel_entries=threat_intel_entries,
            collectors=collectors,
            entity_fields=RULE_ENTITY_FIELDS,
            rule_form=draft,
            error=load_error,
            status=status,
            asset_tab=asset_tab,
            asset_tabs=_assets_tabs(request, asset_tab),
            focus_kind=focus_kind,
            focus_id=focus_id,
        ),
    )


@router.get("/", include_in_schema=False)
async def index(request: Request, user=Depends(get_current_user)):
    return RedirectResponse(url="/dashboards", status_code=307)


@router.get("/dashboards", response_class=HTMLResponse)
async def dashboard_page(request: Request, user=Depends(get_current_user)) -> HTMLResponse:
    context = _dashboard_context(request, user)
    try:
        return templates.TemplateResponse("dashboard.html", context)
    except Exception as exc:  # noqa: BLE001
        context["error"] = f"Unable to load dashboard data from ClickHouse: {exc!s}"
        return templates.TemplateResponse("dashboard.html", context)


@router.get("/api/platform/status", response_class=JSONResponse)
async def platform_status_api(user=Depends(get_current_user)) -> JSONResponse:
    try:
        return JSONResponse(fetch_platform_status())
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc), "clickhouse_ok": False}, status_code=500)


@router.get("/api/dashboard/summary", response_class=JSONResponse)
async def dashboard_summary_api(user=Depends(get_current_user)) -> JSONResponse:
    try:
        return JSONResponse(fetch_dashboard_snapshot())
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/assets", response_class=HTMLResponse)
async def assets_page(
    request: Request,
    tab: str = Query("overview"),
    focus_kind: str = Query(""),
    focus_id: str = Query(""),
    created_rule_id: int | None = None,
    user=Depends(get_current_user),
) -> HTMLResponse:
    status = None
    safe_tab = _safe_asset_tab(tab)
    safe_focus_id = focus_id
    if created_rule_id is not None:
        safe_tab = "rules"
        focus_kind = "rule"
        safe_focus_id = str(created_rule_id)
        status = f"Detection rule #{created_rule_id} was saved and synchronized to stream correlation."
    return _render_assets_page(
        request,
        user,
        status=status,
        asset_tab=safe_tab,
        focus_kind=focus_kind,
        focus_id=safe_focus_id,
    )


@router.get("/assets/devices/{asset_name:path}", include_in_schema=False)
async def assets_device_view(asset_name: str, user=Depends(get_current_user)) -> RedirectResponse:
    return RedirectResponse(url=f"/assets?tab=devices&focus_kind=device&focus_id={quote(asset_name)}", status_code=307)


@router.get("/assets/collectors/{collector_id:path}", include_in_schema=False)
async def assets_collector_view(collector_id: str, user=Depends(get_current_user)) -> RedirectResponse:
    return RedirectResponse(url=f"/assets?tab=collectors&focus_kind=collector&focus_id={quote(collector_id)}", status_code=307)


@router.get("/assets/rules/{rule_id}", include_in_schema=False)
async def assets_rule_view(rule_id: int, user=Depends(get_current_user)) -> RedirectResponse:
    return RedirectResponse(url=f"/assets?tab=rules&focus_kind=rule&focus_id={rule_id}", status_code=307)


@router.get("/assets/normalizers/{rule_id}", include_in_schema=False)
async def assets_normalizer_view(rule_id: int, user=Depends(get_current_user)) -> RedirectResponse:
    return RedirectResponse(url=f"/assets?tab=normalizers&focus_kind=normalizer&focus_id={rule_id}", status_code=307)


@router.get("/assets/active-lists/{list_name}/{item_type}/{item_value:path}", include_in_schema=False)
async def assets_active_list_view(
    list_name: str,
    item_type: str,
    item_value: str,
    user=Depends(get_current_user),
) -> RedirectResponse:
    focus = f"{list_name}|{item_type}|{item_value}"
    return RedirectResponse(url=f"/assets?tab=active-lists&focus_kind=active-list&focus_id={quote(focus)}", status_code=307)


@router.get("/assets/cmdb/{asset_id:path}", include_in_schema=False)
async def assets_cmdb_view(asset_id: str, user=Depends(get_current_user)) -> RedirectResponse:
    return RedirectResponse(url=f"/assets?tab=cmdb&focus_kind=cmdb&focus_id={quote(asset_id)}", status_code=307)


@router.get("/assets/threat-intel/{indicator_type}/{indicator:path}", include_in_schema=False)
async def assets_ti_view(indicator_type: str, indicator: str, user=Depends(get_current_user)) -> RedirectResponse:
    focus = f"{indicator_type}|{indicator}"
    return RedirectResponse(url=f"/assets?tab=threat-intel&focus_kind=threat-intel&focus_id={quote(focus)}", status_code=307)


@router.post("/assets/rules", response_class=HTMLResponse)
async def create_sigma_rule(
    request: Request,
    sigma_yaml: str = Form(...),
    threshold: int = Form(1),
    window_s: int = Form(300),
    entity_field: str = Form("log_source"),
    user=Depends(require_permissions("rules:write")),
) -> HTMLResponse:
    try:
        rule = save_sigma_rule(
            sigma_yaml=sigma_yaml,
            threshold=max(1, threshold),
            window_s=max(60, window_s),
            entity_field=entity_field,
            author=str(getattr(user, "username", "web") or "web"),
        )
    except Exception as exc:  # noqa: BLE001
        return _render_assets_page(
            request,
            user,
            error=f"Unable to save Sigma rule: {exc!s}",
            rule_form={
                "sigma_yaml": sigma_yaml,
                "threshold": threshold,
                "window_s": window_s,
                "entity_field": entity_field,
            },
            asset_tab="rules",
        )
    return RedirectResponse(url=f"/assets?tab=rules&created_rule_id={int(rule['id'])}", status_code=303)


@router.post("/assets/active-lists", response_class=HTMLResponse)
async def create_active_list_item(
    request: Request,
    list_name: str = Form(...),
    list_kind: str = Form("watch"),
    item_type: str = Form(...),
    item_value: str = Form(...),
    item_label: str = Form(""),
    tags: str = Form(""),
    user=Depends(require_permissions("active_lists:write")),
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
        return _render_assets_page(request, user, error=f"Unable to save active list item: {exc!s}", asset_tab="active-lists")
    return _render_assets_page(
        request,
        user,
        status=f"Active list item saved: {item['list_name']} / {item['item_value']}",
        asset_tab="active-lists",
        focus_kind="active-list",
        focus_id=f"{item['list_name']}|{item['item_type']}|{item['item_value']}",
    )


@router.post("/assets/cmdb", response_class=HTMLResponse)
async def create_cmdb_asset(
    request: Request,
    asset_id: str = Form(...),
    asset_type: str = Form("server"),
    hostname: str = Form(""),
    ip: str = Form(""),
    owner: str = Form(""),
    criticality: str = Form("medium"),
    environment: str = Form("prod"),
    business_service: str = Form(""),
    os_family: str = Form(""),
    expected_ports: str = Form(""),
    tags: str = Form(""),
    notes: str = Form(""),
    user=Depends(require_permissions("cmdb:write")),
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
        return _render_assets_page(request, user, error=f"Unable to save CMDB asset: {exc!s}", asset_tab="cmdb")
    return _render_assets_page(
        request,
        user,
        status=f"CMDB asset saved: {item['asset_id']}",
        asset_tab="cmdb",
        focus_kind="cmdb",
        focus_id=item["asset_id"],
    )


@router.post("/assets/cmdb/import", response_class=HTMLResponse)
async def import_cmdb_asset_records(
    request: Request,
    payload: str = Form(...),
    user=Depends(require_permissions("cmdb:write")),
) -> HTMLResponse:
    try:
        result = import_cmdb_assets(payload)
    except Exception as exc:  # noqa: BLE001
        return _render_assets_page(request, user, error=f"Unable to import CMDB assets: {exc!s}", asset_tab="cmdb")
    return _render_assets_page(
        request,
        user,
        status=f"CMDB import completed: {result['saved']} saved from {result['parsed']} parsed records.",
        asset_tab="cmdb",
    )


@router.post("/assets/cmdb/sync-observed", response_class=HTMLResponse)
async def sync_observed_assets(
    request: Request,
    hours: int = Form(72),
    limit: int = Form(200),
    user=Depends(require_permissions("cmdb:write")),
) -> HTMLResponse:
    try:
        result = sync_observed_assets_to_cmdb(hours=max(1, hours), limit=max(1, min(1000, limit)))
    except Exception as exc:  # noqa: BLE001
        return _render_assets_page(request, user, error=f"Unable to sync observed assets: {exc!s}", asset_tab="cmdb")
    return _render_assets_page(
        request,
        user,
        status=f"Observed asset sync completed: {result['created']} provisional assets created.",
        asset_tab="cmdb",
    )


@router.post("/assets/threat-intel", response_class=HTMLResponse)
async def create_threat_intel_item(
    request: Request,
    indicator_type: str = Form(...),
    indicator: str = Form(...),
    provider: str = Form(""),
    severity: str = Form("medium"),
    confidence: int = Form(50),
    description: str = Form(""),
    tags: str = Form(""),
    user=Depends(require_permissions("threat_intel:write")),
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
        return _render_assets_page(request, user, error=f"Unable to save threat intel indicator: {exc!s}", asset_tab="threat-intel")
    return _render_assets_page(
        request,
        user,
        status=f"Threat intel indicator saved: {item['indicator_type']} / {item['indicator']}",
        asset_tab="threat-intel",
        focus_kind="threat-intel",
        focus_id=f"{item['indicator_type']}|{item['indicator']}",
    )


@router.post("/assets/threat-intel/import", response_class=HTMLResponse)
async def import_threat_intel_records(
    request: Request,
    payload: str = Form(...),
    user=Depends(require_permissions("threat_intel:write")),
) -> HTMLResponse:
    try:
        result = import_threat_intel_entries(payload)
    except Exception as exc:  # noqa: BLE001
        return _render_assets_page(request, user, error=f"Unable to import threat intel: {exc!s}", asset_tab="threat-intel")
    return _render_assets_page(
        request,
        user,
        status=f"Threat intel import completed: {result['saved']} saved from {result['parsed']} parsed records.",
        asset_tab="threat-intel",
    )


@router.post("/api/rules/{rule_id}/test", response_class=JSONResponse)
async def test_rule_api(rule_id: int, user=Depends(require_permissions("rules:test"))) -> JSONResponse:
    try:
        return JSONResponse(test_detection_rule(rule_id))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/resources/archive-hot", response_class=JSONResponse)
async def archive_hot_events_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("storage:archive")),
) -> JSONResponse:
    hours = int(payload.get("older_than_hours", CONFIG.hot_retention_hours) or CONFIG.hot_retention_hours)
    try:
        return JSONResponse(archive_events_to_cold(max(1, hours)))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/resources", response_class=HTMLResponse)
async def resources_page(request: Request, user=Depends(get_current_user)) -> HTMLResponse:
    overview = {}
    sources = []
    error = None
    try:
        overview = fetch_resource_overview()
        sources = fetch_top_sources(limit=10, hours=24)
    except Exception as exc:  # noqa: BLE001
        error = f"Unable to load platform resources: {exc!s}"
    return templates.TemplateResponse(
        "resources.html",
        ui_context(
            request,
            user,
            "resources",
            overview=overview,
            sources=sources,
            error=error,
        ),
    )


@router.get("/sources", response_class=HTMLResponse)
async def sources_page(request: Request, user=Depends(get_current_user)) -> HTMLResponse:
    error = None
    sources = []
    try:
        sources = fetch_source_inventory(limit=300, hours=24)
    except Exception as exc:  # noqa: BLE001
        error = f"Unable to load source inventory: {exc!s}"
    return templates.TemplateResponse(
        "sources.html",
        ui_context(
            request,
            user,
            "sources",
            sources=sources,
            error=error,
        ),
    )


@router.get("/collectors", response_class=HTMLResponse)
async def collectors_page(request: Request, user=Depends(get_current_user)) -> HTMLResponse:
    error = None
    collectors = []
    try:
        collectors = fetch_collector_inventory(hours=24)
    except Exception as exc:  # noqa: BLE001
        error = f"Unable to load collector inventory: {exc!s}"
    return templates.TemplateResponse(
        "collectors.html",
        ui_context(
            request,
            user,
            "collectors",
            collectors=collectors,
            error=error,
        ),
    )


@router.get("/documentation", response_class=HTMLResponse)
async def documentation_page(request: Request, user=Depends(get_current_user)) -> HTMLResponse:
    context = ui_context(request, user, "documentation")
    context["playbooks"] = investigation_playbooks(context["ui_lang"])
    return templates.TemplateResponse("documentation.html", context)
