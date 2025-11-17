from __future__ import annotations

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..config import CONFIG
from ..security import authenticate_admin_user, create_access_token, CurrentUser

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/auth/login", include_in_schema=False)
async def login_page(request: Request):
    """
    Страница логина. Просто отдаёт форму.
    """
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
    """
    Обработка формы логина.

    При успешной аутентификации:
      - создаём JWT,
      - кладём его в HttpOnly cookie access_token,
      - редиректим на главную (/ -> /alerts_agg).

    При ошибке логина — снова показываем страницу с сообщением.
    """
    user = authenticate_admin_user(username, password)
    if user is None:
        # Неверный логин/пароль
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "base_url": CONFIG.base_url,
                "error": "Неверный логин или пароль",
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    token = create_access_token(subject=user.username, role=user.role)

    secure_cookie = CONFIG.env == "prod"

    response = RedirectResponse(
        url="/",
        status_code=status.HTTP_302_FOUND,
    )
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
async def logout(request: Request, user: CurrentUser):
    """
    Логаут: стираем cookie и редиректим на /auth/login.
    """
    response = RedirectResponse(
        url="/auth/login",
        status_code=status.HTTP_302_FOUND,
    )
    response.delete_cookie("access_token")
    return response

# ───────── Temporary stub for get_current_user (to unblock web UI) ─────────

async def get_current_user(request):
    """
    ВРЕМЕННАЯ заглушка для зависимостей Depends(get_current_user).

    Всегда возвращает фиктивного пользователя "admin".
    TODO: позже заменить на реальную аутентификацию (JWT/куки/сессии).
    """
    return {
        "username": "admin",
        "display_name": "Admin (stub)",
        "roles": ["admin"],
    }


# ───────── Override stub for get_current_user to avoid 422 on "request" ─────────

async def get_current_user():
    """
    Временная заглушка для Depends(get_current_user).

    Никаких параметров не принимает, чтобы FastAPI не требовал query-параметр
    "request". Всегда возвращает фиктивного администратора.
    """
    return {
        "username": "admin",
        "display_name": "Admin (stub)",
        "roles": ["admin"],
    }

