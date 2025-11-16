from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import RedirectResponse

from ..security import CurrentUser

router = APIRouter()


@router.get("/", include_in_schema=False)
async def index(_: CurrentUser = Depends()):
    # редирект на основную страницу алертов
    return RedirectResponse(url="/alerts_agg")
