from __future__ import annotations

from fastapi import APIRouter

from ..config import CONFIG
from ..deps import get_ch_client

router = APIRouter()


@router.get("/health", tags=["health"])
async def healthcheck():
    # простой ping ClickHouse
    try:
        client = get_ch_client()
        client.command("SELECT 1")
        ch_ok = True
    except Exception:  # noqa: BLE001
        ch_ok = False

    return {
        "status": "ok" if ch_ok else "degraded",
        "env": CONFIG.env,
        "instance": CONFIG.instance_name,
        "clickhouse": ch_ok,
    }
