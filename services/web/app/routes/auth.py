from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..config import CONFIG
from ..security import CurrentUser, authenticate_user, create_access_token, decode_access_token, get_token_from_request

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def get_current_user(request: Request) -> CurrentUser:
    token = get_token_from_request(request)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": "/auth/login"},
        )
    try:
        return decode_access_token(token)
    except HTTPException as exc:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": "/auth/login"},
        ) from exc


@router.get("/auth/login", include_in_schema=False)
async def login_page(request: Request):
    token = get_token_from_request(request)
    if token:
        try:
            decode_access_token(token)
            return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
        except HTTPException:
            pass
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "base_url": CONFIG.base_url,
            "error": None,
        },
    )


@router.post("/auth/login", include_in_schema=False)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    user = authenticate_user(username, password)
    if user is None:
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "base_url": CONFIG.base_url,
                "error": "Invalid username or password",
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    token = create_access_token(subject=user.username, role=user.role)
    secure_cookie = CONFIG.base_url.startswith("https://")
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
        max_age=CONFIG.jwt_expires_minutes * 60,
    )
    return response


@router.get("/auth/logout", include_in_schema=False)
async def logout(request: Request, user=Depends(get_current_user)):
    response = RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("access_token")
    return response
