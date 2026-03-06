from __future__ import annotations

import json
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Annotated, Literal, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt

from .config import CONFIG

ROLE = Literal["admin", "analyst", "viewer"]
ALLOWED_ROLES = {"admin", "analyst", "viewer"}


class User:
    def __init__(self, username: str, role: ROLE) -> None:
        self.username = username
        self.role: ROLE = role


@lru_cache(maxsize=1)
def _configured_users() -> dict[str, tuple[str, ROLE]]:
    users: dict[str, tuple[str, ROLE]] = {}
    raw = CONFIG.web_users_json
    if raw:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("SIEM_WEB_USERS_JSON must be valid JSON") from exc
        if not isinstance(payload, list):
            raise RuntimeError("SIEM_WEB_USERS_JSON must be a JSON array")
        for item in payload:
            if not isinstance(item, dict):
                continue
            username = str(item.get("username", "") or "").strip()
            password = str(item.get("password", "") or "")
            role = str(item.get("role", "viewer") or "viewer").strip().lower()
            if not username or not password or role not in ALLOWED_ROLES:
                continue
            users[username] = (password, role)  # type: ignore[assignment]
    if not users:
        users[CONFIG.admin_default_user] = (CONFIG.admin_default_password, "admin")
    return users


def authenticate_user(username: str, password: str) -> Optional[User]:
    record = _configured_users().get(username)
    if not record:
        return None
    stored_password, role = record
    if not pysecrets.compare_digest(password, stored_password):
        return None
    return User(username=username, role=role)


def create_access_token(*, subject: str, role: ROLE) -> str:
    expire = datetime.now(tz=timezone.utc) + timedelta(minutes=CONFIG.jwt_expires_minutes)
    return jwt.encode(
        {
            "sub": subject,
            "role": role,
            "exp": expire,
        },
        CONFIG.jwt_secret,
        algorithm=CONFIG.jwt_algorithm,
    )


def decode_access_token(token: str) -> User:
    try:
        payload = jwt.decode(token, CONFIG.jwt_secret, algorithms=[CONFIG.jwt_algorithm])
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials") from exc
    username = str(payload.get("sub") or "").strip()
    role = str(payload.get("role", "viewer") or "viewer").strip().lower()
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    if role not in ALLOWED_ROLES:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid role in authentication token")
    return User(username=username, role=role)  # type: ignore[arg-type]


def get_token_from_request(request: Request) -> Optional[str]:
    token = request.cookies.get("access_token")
    return token or None


def get_current_user(request: Request) -> User:
    token = get_token_from_request(request)
    if token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return decode_access_token(token)


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*required_roles: ROLE):
    accepted = set(required_roles)

    def dependency(user: CurrentUser) -> User:
        if user.role not in accepted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient role: required one of {sorted(accepted)}, got {user.role}",
            )
        return user

    return dependency


AdminUser = Annotated[User, Depends(require_roles("admin"))]
AnalystUser = Annotated[User, Depends(require_roles("admin", "analyst"))]


async def login_via_form(form_data: OAuth2PasswordRequestForm = Depends()) -> str:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    return create_access_token(subject=user.username, role=user.role)
