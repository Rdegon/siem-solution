from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates

from ..config import CONFIG
from ..security import login_via_form

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/auth/login", include_in_schema=False)
async def login_page(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "base_url": CONFIG.base_url},
    )


@router.post("/auth/login", include_in_schema=False)
async def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    token = await login_via_form(form_data)
    redirect = RedirectResponse(url="/alerts_agg", status_code=status.HTTP_302_FOUND)
    # HttpOnly cookie, Secure ставить в бою при HTTPS
    redirect.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=CONFIG.env == "prod",
        samesite="lax",
        max_age=CONFIG.jwt_expires_minutes * 60,
    )
    return redirect


@router.get("/auth/logout", include_in_schema=False)
async def logout():
    redirect = RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)
    redirect.delete_cookie("access_token")
    return redirect
