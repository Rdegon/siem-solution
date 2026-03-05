from typing import List, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from .auth import get_current_user
from ..deps import fetch_alerts_agg, fetch_alerts_raw
from ..templates import templates

router = APIRouter()


@router.get("/alerts_raw", response_class=HTMLResponse)
async def alerts_raw_page(
    request: Request,
    user = Depends(get_current_user),
) -> HTMLResponse:
    error: Optional[str] = None
    alerts: List[dict] = []

    try:
        alerts = fetch_alerts_raw(limit=200)
    except Exception as exc:  # noqa: BLE001
        error = f"?????? ????????? ? ClickHouse ??? ?????? ????? ???????: {exc!s}"

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
    user = Depends(get_current_user),
) -> HTMLResponse:
    error: Optional[str] = None
    alerts_agg: List[dict] = []

    try:
        alerts_agg = fetch_alerts_agg(limit=200)
    except Exception as exc:  # noqa: BLE001
        error = f"?????? ????????? ? ClickHouse ??? ?????? ?????????????? ???????: {exc!s}"

    return templates.TemplateResponse(
        "alerts_agg.html",
        {
            "request": request,
            "user": user,
            "alerts_agg": alerts_agg,
            "error": error,
        },
    )
