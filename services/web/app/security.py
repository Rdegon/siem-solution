"""
app.security
------------
JWT-аутентификация и базовый RBAC.

Использует:
- SIEM_JWT_SECRET (через CONFIG.jwt_secret)
- SIEM_ADMIN_DEFAULT_USER / SIEM_ADMIN_DEFAULT_PASSWORD

Роли:
- "admin": полный доступ (в том числе к admin-разделам).
В дальнейшем можно добавить хранение пользователей/ролей в ClickHouse.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

from .config import CONFIG

ROLE = Literal["admin"]  # на будущее можно расширить: "viewer", "analyst", ...


class User:
    def __init__(self, username: str, role: ROLE) -> None:
        self.username = username
        self.role: ROLE = role


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def authenticate_admin_user(username: str, password: str) -> Optional[User]:
    """
    Единственный пользователь сейчас задаётся через env:
    SIEM_ADMIN_DEFAULT_USER / SIEM_ADMIN_DEFAULT_PASSWORD.

    В проде вместо этого должен быть стор в ClickHouse.
    """
    if username != CONFIG.admin_default_user:
        return None
    if password != CONFIG.admin_default_password:
        return None
    return User(username=username, role="admin")


def create_access_token(*, subject: str, role: ROLE) -> str:
    expire = datetime.now(tz=timezone.utc) + timedelta(minutes=CONFIG.jwt_expires_minutes)
    to_encode = {
        "sub": subject,
        "role": role,
        "exp": expire,
    }
    encoded_jwt = jwt.encode(
        to_encode,
        CONFIG.jwt_secret,
        algorithm=CONFIG.jwt_algorithm,
    )
    return encoded_jwt


def decode_access_token(token: str) -> User:
    try:
        payload = jwt.decode(
            token,
            CONFIG.jwt_secret,
            algorithms=[CONFIG.jwt_algorithm],
        )
        username: str = payload.get("sub")  # type: ignore[assignment]
        role: str = payload.get("role", "admin")  # type: ignore[assignment]
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )
        return User(username=username, role=role)  # type: ignore[arg-type]
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        ) from exc


def get_token_from_request(request: Request) -> Optional[str]:
    """
    Достаём токен из cookie 'access_token'.
    При необходимости можно расширить до Authorization: Bearer.
    """
    token = request.cookies.get("access_token")
    if not token:
        return None
    return token


def get_current_user(request: Request) -> User:
    token = get_token_from_request(request)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return decode_access_token(token)


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_role(required: ROLE):
    def dependency(user: CurrentUser) -> User:
        if user.role != required:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient role: required {required}, got {user.role}",
            )
        return user

    return dependency


AdminUser = Annotated[User, Depends(require_role("admin"))]


async def login_via_form(form_data: OAuth2PasswordRequestForm = Depends()) -> str:
    user = authenticate_admin_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    token = create_access_token(subject=user.username, role=user.role)
    return token
