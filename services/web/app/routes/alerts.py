from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

# Импорт из того же namespace, который использует main.py
from app.routes.auth import get_current_user  # type: ignore[import]

from ..deps import fetch_alerts_agg, fetch_alerts_raw
from ..templates import templates

router = APIRouter()


@router.get("/alerts_raw", response_class=HTMLResponse)
async def alerts_raw_page(
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
) -> HTMLResponse:
    """
    Страница сырых алертов.
    При ошибке ClickHouse показываем сообщение и пустой список (без 500).
    """
    error: Optional[str] = None
    alerts: List[Dict[str, Any]] = []

    try:
        alerts = fetch_alerts_raw(limit=200)
    except Exception as exc:  # noqa: BLE001
        error = f"Ошибка обращения к ClickHouse при чтении сырых алертов: {exc!s}"

    return templates.TemplateResponse(
        "alerts_raw.html",
        {
            "request": request,
            "user": user,
            "alerts": alerts,
            "error": error,
        },
    )


@router.get("/alerts_agg", response_class=HTMLResponse)
async def alerts_agg_page(
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
) -> HTMLResponse:
    """
    Страница агрегированных алертов.
    Также ловим ошибки ClickHouse и не роняем 500.
    """
    error: Optional[str] = None
    alerts_agg: List[Dict[str, Any]] = []

    try:
        alerts_agg = fetch_alerts_agg(limit=200)
    except Exception as exc:  # noqa: BLE001
        error = f"Ошибка обращения к ClickHouse при чтении агрегированных алертов: {exc!s}"

    return templates.TemplateResponse(
        "alerts_agg.html",
        {
            "request": request,
            "user": user,
            "alerts_agg": alerts_agg,
            "error": error,
        },
    )
