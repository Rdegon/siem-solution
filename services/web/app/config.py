from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal


class ConfigError(RuntimeError):
    """Configuration loading error."""


def _get_env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise ConfigError(f"Required environment variable {name} is not set")
    if value == "":
        raise ConfigError(f"Environment variable {name} is empty")
    return value


def _get_int(name: str, default: str) -> int:
    raw = _get_env(name, default)
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be integer, got: {raw!r}") from exc


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
    web_users_json: str
    hot_retention_hours: int
    cold_retention_days: int


def load_config() -> WebConfig:
    env = _get_env("SIEM_ENV", "dev")
    if env not in {"dev", "prod", "stage"}:
        raise ConfigError(f"SIEM_ENV must be one of dev/prod/stage, got: {env!r}")

    bind_host = _get_env("SIEM_WEB_BIND_HOST", "127.0.0.1")
    bind_port = _get_int("SIEM_WEB_BIND_PORT", "8000")

    ch_cfg = ClickHouseConfig(
        host=_get_env("SIEM_CH_HOST"),
        port=_get_int("SIEM_CH_PORT", "9000"),
        db=_get_env("SIEM_CH_DB", "siem"),
        user=_get_env("SIEM_CH_USER"),
        password=_get_env("SIEM_CH_PASSWORD"),
    )

    return WebConfig(
        env=env,  # type: ignore[arg-type]
        instance_name=_get_env("SIEM_INSTANCE_NAME", "siem-web"),
        log_level=_get_env("SIEM_LOG_LEVEL", "INFO").upper(),
        ch=ch_cfg,
        bind_host=bind_host,
        bind_port=bind_port,
        base_url=_get_env("SIEM_WEB_BASE_URL", f"http://{bind_host}:{bind_port}"),
        jwt_secret=_get_env("SIEM_JWT_SECRET"),
        jwt_algorithm="HS256",
        jwt_expires_minutes=_get_int("SIEM_JWT_EXPIRES_MINUTES", "480"),
        admin_default_user=_get_env("SIEM_ADMIN_DEFAULT_USER", "admin"),
        admin_default_password=_get_env("SIEM_ADMIN_DEFAULT_PASSWORD"),
        web_users_json=os.getenv("SIEM_WEB_USERS_JSON", "").strip(),
        hot_retention_hours=_get_int("SIEM_HOT_RETENTION_HOURS", "168"),
        cold_retention_days=_get_int("SIEM_COLD_RETENTION_DAYS", "365"),
    )


CONFIG = load_config()
