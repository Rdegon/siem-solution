from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from .auth import get_current_user

router = APIRouter()


@router.get("/", include_in_schema=False)
async def index(
    request: Request,
    user = Depends(get_current_user),
):
    return RedirectResponse(url="/alerts_agg", status_code=307)
