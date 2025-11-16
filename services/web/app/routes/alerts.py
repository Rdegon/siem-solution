from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates

from ..config import CONFIG
from ..deps import fetch_alerts_agg, fetch_alerts_raw
from ..security import CurrentUser

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/alerts_agg", include_in_schema=False)
async def alerts_agg_page(
    request: Request,
    user: CurrentUser = Depends(),
):
    alerts = fetch_alerts_agg(limit=200)
    return templates.TemplateResponse(
        "alerts_agg.html",
        {
            "request": request,
            "user": user,
            "alerts": alerts,
            "base_url": CONFIG.base_url,
        },
    )


@router.get("/alerts_raw", include_in_schema=False)
async def alerts_raw_page(
    request: Request,
    user: CurrentUser = Depends(),
):
    alerts = fetch_alerts_raw(limit=200)
    return templates.TemplateResponse(
        "alerts_raw.html",
        {
            "request": request,
            "user": user,
            "alerts": alerts,
            "base_url": CONFIG.base_url,
        },
    )
