"""
app.config
----------
Загрузка и валидация конфигурации Web UI из переменных окружения SIEM_*.

Используемые переменные:
- SIEM_ENV
- SIEM_INSTANCE_NAME
- SIEM_LOG_LEVEL

- SIEM_CH_HOST
- SIEM_CH_PORT
- SIEM_CH_DB
- SIEM_CH_USER
- SIEM_CH_PASSWORD

- SIEM_WEB_BIND_HOST
- SIEM_WEB_BIND_PORT
- SIEM_WEB_BASE_URL

- SIEM_JWT_SECRET
- SIEM_JWT_EXPIRES_MINUTES
- SIEM_ADMIN_DEFAULT_USER
- SIEM_ADMIN_DEFAULT_PASSWORD
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal


class ConfigError(RuntimeError):
    """Ошибка загрузки конфигурации из окружения."""


def _get_env(name: str, default: str | None = None) -> str:
    """
    Получить переменную окружения или упасть с понятной ошибкой.
    """
    value = os.getenv(name, default)
    if value is None:
        raise ConfigError(f"Required environment variable {name} is not set")
    if value == "":
        raise ConfigError(f"Environment variable {name} is empty")
    return value


@dataclass(frozen=True)
class ClickHouseConfig:
    host: str
    port: int
    db: str
    user: str
    password: str


@dataclass(frozen=True)
class WebConfig:
    env: Literal["dev", "prod", "stage"]
    instance_name: str
    log_level: str

    ch: ClickHouseConfig

    bind_host: str
    bind_port: int
    base_url: str

    jwt_secret: str
    jwt_algorithm: str
    jwt_expires_minutes: int

    admin_default_user: str
    admin_default_password: str


def load_config() -> WebConfig:
    env = _get_env("SIEM_ENV", "dev")
    if env not in {"dev", "prod", "stage"}:
        raise ConfigError(f"SIEM_ENV must be one of dev/prod/stage, got: {env!r}")

    instance_name = _get_env("SIEM_INSTANCE_NAME", "siem-web")
    log_level = _get_env("SIEM_LOG_LEVEL", "INFO").upper()

    ch_host = _get_env("SIEM_CH_HOST")
    ch_port_str = _get_env("SIEM_CH_PORT", "9000")
    ch_db = _get_env("SIEM_CH_DB", "siem")
    ch_user = _get_env("SIEM_CH_USER")
    ch_password = _get_env("SIEM_CH_PASSWORD")

    try:
        ch_port = int(ch_port_str)
    except ValueError as exc:
        raise ConfigError(f"SIEM_CH_PORT must be integer, got: {ch_port_str!r}") from exc

    bind_host = _get_env("SIEM_WEB_BIND_HOST", "127.0.0.1")
    bind_port_str = _get_env("SIEM_WEB_BIND_PORT", "8000")
    try:
        bind_port = int(bind_port_str)
    except ValueError as exc:
        raise ConfigError(
            f"SIEM_WEB_BIND_PORT must be integer, got: {bind_port_str!r}"
        ) from exc

    base_url = _get_env("SIEM_WEB_BASE_URL", f"http://{bind_host}:{bind_port}")

    jwt_secret = _get_env("SIEM_JWT_SECRET")
    jwt_algorithm = "HS256"
    jwt_expires_minutes_str = _get_env("SIEM_JWT_EXPIRES_MINUTES", "480")
    try:
        jwt_expires_minutes = int(jwt_expires_minutes_str)
    except ValueError as exc:
        raise ConfigError(
            f"SIEM_JWT_EXPIRES_MINUTES must be integer, got: {jwt_expires_minutes_str!r}"
        ) from exc

    admin_default_user = _get_env("SIEM_ADMIN_DEFAULT_USER", "admin")
    admin_default_password = _get_env("SIEM_ADMIN_DEFAULT_PASSWORD")

    ch_cfg = ClickHouseConfig(
        host=ch_host,
        port=ch_port,
        db=ch_db,
        user=ch_user,
        password=ch_password,
    )

    return WebConfig(
        env=env,  # type: ignore[arg-type]
        instance_name=instance_name,
        log_level=log_level,
        ch=ch_cfg,
        bind_host=bind_host,
        bind_port=bind_port,
        base_url=base_url,
        jwt_secret=jwt_secret,
        jwt_algorithm=jwt_algorithm,
        jwt_expires_minutes=jwt_expires_minutes,
        admin_default_user=admin_default_user,
        admin_default_password=admin_default_password,
    )


# Глобальный singleton, инициализируется при импорте модуля
CONFIG = load_config()
