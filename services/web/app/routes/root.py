from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from ..config import CONFIG
from ..security import CurrentUser

router = APIRouter()


@router.get("/", include_in_schema=False)
async def index(
    request: Request,
    user: CurrentUser,
):
    """
    Главная страница Web UI.

    Требует аутентифицированного пользователя (CurrentUser)
    и просто редиректит на страницу агрегированных алертов.
    """
    return RedirectResponse(url="/alerts_agg", status_code=307)
