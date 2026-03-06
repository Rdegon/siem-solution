from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from clickhouse_driver import Client
from redis.asyncio import Redis
from redis.exceptions import ResponseError

logger = logging.getLogger("siem.writer")


@dataclass
class WriterSettings:
    redis_host: str = os.getenv("SIEM_REDIS_HOST", "127.0.0.1")
    redis_port: int = int(os.getenv("SIEM_REDIS_PORT", "6379"))
    redis_db: int = int(os.getenv("SIEM_REDIS_DB", "0"))
    redis_password: str | None = os.getenv("SIEM_REDIS_PASSWORD") or None

    filtered_stream_key: str = os.getenv("SIEM_FILTERED_STREAM_KEY", "siem:filtered")
    group_name: str = os.getenv("SIEM_WRITER_GROUP", "writer")
    consumer_name: str = os.getenv("SIEM_WRITER_CONSUMER", "writer-1")
    batch_size: int = int(os.getenv("SIEM_WRITER_BATCH_SIZE", "100"))
    block_ms: int = int(os.getenv("SIEM_WRITER_BLOCK_MS", "1000"))

    ch_host: str = os.getenv("SIEM_CH_HOST", "127.0.0.1")
    ch_port: int = int(os.getenv("SIEM_CH_PORT", "8123"))
    ch_user: str = os.getenv("SIEM_CH_USER", "siem_app")
    ch_password: str = os.getenv("SIEM_CH_PASSWORD", "")
    ch_db: str = os.getenv("SIEM_CH_DB", "siem")
    ch_timeout_secs: int = int(os.getenv("SIEM_CH_TIMEOUT_SECS", "10"))
    events_table: str = os.getenv("SIEM_EVENTS_TABLE", "siem.events")
    active_list_table: str = os.getenv("SIEM_ACTIVE_LIST_TABLE", "siem.active_list_items")
    active_list_refresh_secs: int = int(os.getenv("SIEM_ACTIVE_LIST_REFRESH_SECS", "60"))


def ipv4_to_int(ip: str | None) -> int:
    if not ip:
        return 0
    try:
        return int(ipaddress.IPv4Address(ip))
    except Exception:
        return 0


class WriterWorker:
    def __init__(self, settings: WriterSettings) -> None:
        self._settings = settings
        self._redis: Redis | None = None
        self._ch: Client | None = None
        self._active_lists: Dict[str, Dict[str, Dict[str, str]]] = {}
        self._active_lists_loaded_at: datetime | None = None

    async def init(self) -> None:
        self._redis = Redis(
            host=self._settings.redis_host,
            port=self._settings.redis_port,
            db=self._settings.redis_db,
            password=self._settings.redis_password,
            decode_responses=True,
        )

        self._ch = Client(
            host=self._settings.ch_host,
            port=self._settings.ch_port,
            user=self._settings.ch_user,
            password=self._settings.ch_password,
            database=self._settings.ch_db,
            send_receive_timeout=self._settings.ch_timeout_secs,
        )

        try:
            await self._redis.xgroup_create(
                name=self._settings.filtered_stream_key,
                groupname=self._settings.group_name,
                id="0-0",
                mkstream=True,
            )
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

        self._refresh_active_lists(force=True)
        logger.info(
            "WriterWorker initialized",
            extra={
                "extra": {
                    "stream": self._settings.filtered_stream_key,
                    "group": self._settings.group_name,
                    "consumer": self._settings.consumer_name,
                    "batch_size": self._settings.batch_size,
                }
            },
        )

    def _parse_event_ts(self, fields: Dict[str, str]) -> datetime:
        candidates = [
            fields.get("ts"),
            fields.get("@timestamp"),
            fields.get("event.created"),
            fields.get("event.ingested"),
        ]
        for candidate in candidates:
            text = str(candidate or "").strip()
            if not text:
                continue
            normalized = text.replace(" ", "T")
            if normalized.endswith("Z"):
                normalized = normalized[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(normalized)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc).replace(tzinfo=None)
            except ValueError:
                continue
        return datetime.now(timezone.utc).replace(tzinfo=None)

    def _normalize_tags(self, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, list):
            items = value
        else:
            text = str(value).strip()
            if not text:
                return []
            if text.startswith("[") and text.endswith("]"):
                try:
                    parsed = json.loads(text)
                    items = parsed if isinstance(parsed, list) else [parsed]
                except Exception:
                    items = [part.strip() for part in text.split(",")]
            else:
                items = [part.strip() for part in text.split(",")]
        tags: List[str] = []
        seen: set[str] = set()
        for item in items:
            tag = str(item or "").strip()
            if not tag or tag in seen:
                continue
            seen.add(tag)
            tags.append(tag)
        return tags

    def _build_normalized_json(self, fields: Dict[str, str]) -> str:
        payload = {
            "provider": fields.get("event.provider", ""),
            "category": fields.get("event.category", ""),
            "type": fields.get("event.type", ""),
            "action": fields.get("event.action", ""),
            "outcome": fields.get("event.outcome", ""),
            "host": fields.get("host.name", ""),
            "source": {
                "ip": fields.get("source.ip", ""),
                "port": fields.get("source.port", ""),
            },
            "destination": {
                "ip": fields.get("destination.ip", ""),
                "port": fields.get("destination.port", ""),
            },
            "user": {
                "name": fields.get("user.name", ""),
                "target": fields.get("user.target.name", ""),
            },
            "process": {
                "name": fields.get("process.name", ""),
                "executable": fields.get("process.executable", ""),
                "command_line": fields.get("process.command_line", "") or fields.get("process.command", ""),
            },
            "message": fields.get("event.original") or fields.get("message") or "",
        }
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))

    def _refresh_active_lists(self, *, force: bool = False) -> None:
        assert self._ch is not None
        now = datetime.now(timezone.utc)
        if not force and self._active_lists_loaded_at is not None:
            age = (now - self._active_lists_loaded_at).total_seconds()
            if age < self._settings.active_list_refresh_secs:
                return
        try:
            exists = self._ch.execute(f"EXISTS TABLE {self._settings.active_list_table}")
            if not exists or not exists[0][0]:
                self._active_lists = {}
                self._active_lists_loaded_at = now
                return
            rows = self._ch.execute(
                f"""
                SELECT list_name, list_kind, value_type, value, label, tags
                FROM {self._settings.active_list_table}
                WHERE enabled = 1
                """
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to refresh active lists", extra={"extra": {"error": str(exc)}})
            return
        active_lists: Dict[str, Dict[str, Dict[str, str]]] = {}
        for list_name, list_kind, value_type, value, label, tags in rows:
            bucket = active_lists.setdefault(str(value_type or "").lower(), {})
            bucket[str(value or "").strip()] = {
                "list_name": str(list_name or "").strip(),
                "list_kind": str(list_kind or "watch").strip().lower() or "watch",
                "label": str(label or "").strip(),
                "tags": str(tags or "").strip(),
            }
        self._active_lists = active_lists
        self._active_lists_loaded_at = now

    def _match_active_lists(self, fields: Dict[str, str]) -> List[str]:
        self._refresh_active_lists()
        candidates = {
            "ip": [fields.get("source.ip", ""), fields.get("destination.ip", ""), fields.get("log_source", "")],
            "user": [fields.get("user.name", ""), fields.get("user.target.name", "")],
            "host": [fields.get("host.name", ""), fields.get("log_source", "")],
            "process": [fields.get("process.name", ""), fields.get("process.executable", "")],
            "raw": [fields.get("event.original", "") or fields.get("message", "")],
        }
        tags: List[str] = []
        seen: set[str] = set()
        for value_type, values in candidates.items():
            bucket = self._active_lists.get(value_type, {})
            if not bucket:
                continue
            for value in values:
                normalized = str(value or "").strip()
                if not normalized:
                    continue
                if value_type == "raw":
                    for raw_value, meta in bucket.items():
                        if raw_value and raw_value in normalized:
                            prefix = {"watch": "watchlist", "allow": "allowlist", "deny": "denylist"}.get(meta.get("list_kind", "watch"), "watchlist")
                            for tag in [f"{prefix}:{meta['list_name']}", *self._normalize_tags(meta.get("tags", ""))]:
                                if tag and tag not in seen:
                                    seen.add(tag)
                                    tags.append(tag)
                    continue
                meta = bucket.get(normalized)
                if not meta:
                    continue
                prefix = {"watch": "watchlist", "allow": "allowlist", "deny": "denylist"}.get(meta.get("list_kind", "watch"), "watchlist")
                for tag in [f"{prefix}:{meta['list_name']}", *self._normalize_tags(meta.get("tags", ""))]:
                    if tag and tag not in seen:
                        seen.add(tag)
                        tags.append(tag)
        return tags

    def _build_row(self, msg_id: str, fields: Dict[str, str]) -> Tuple[Any, ...]:
        ts = self._parse_event_ts(fields)
        event_id = fields.get("event_id") or msg_id
        provider = fields.get("event.provider", "")
        category = fields.get("event.category") or provider or "generic"
        subcategory = fields.get("event.type") or ""
        event_action = fields.get("event.action") or ""
        event_outcome = fields.get("event.outcome") or ""

        src_ip_int = ipv4_to_int(fields.get("source.ip"))
        dst_ip_int = ipv4_to_int(fields.get("destination.ip"))
        src_port = int(fields.get("source.port", "0") or 0)
        dst_port = int(fields.get("destination.port", "0") or 0)

        device_vendor = fields.get("device.vendor") or provider
        device_product = fields.get("device.product") or provider
        log_source = fields.get("log_source") or fields.get("host.name") or fields.get("source.ip") or ""
        host_name = fields.get("host.name") or log_source
        user_name = fields.get("user.name") or ""
        target_user = fields.get("user.target.name") or ""
        process_name = fields.get("process.name") or ""
        process_executable = fields.get("process.executable") or ""
        process_command = fields.get("process.command_line") or fields.get("process.command") or ""
        severity = fields.get("event.severity") or fields.get("severity") or fields.get("log.level") or "info"
        message = fields.get("event.original") or fields.get("message") or ""

        tags = self._normalize_tags(fields.get("tags"))
        tags.extend(self._match_active_lists(fields))
        if subcategory:
            tags.append(f"event_type:{subcategory}")
        tags_text = ",".join(dict.fromkeys(tag for tag in tags if tag))
        normalized_json = self._build_normalized_json(fields)

        return (
            ts,
            event_id,
            category,
            subcategory,
            event_action,
            event_outcome,
            src_ip_int,
            dst_ip_int,
            src_port,
            dst_port,
            device_vendor,
            device_product,
            log_source,
            host_name,
            user_name,
            target_user,
            process_name,
            process_executable,
            process_command,
            severity,
            message,
            normalized_json,
            tags_text,
        )

    async def run(self) -> None:
        assert self._redis is not None
        assert self._ch is not None

        redis = self._redis
        ch = self._ch
        s = self._settings

        insert_sql = (
            f"INSERT INTO {s.events_table} "
            "(ts, event_id, category, subcategory, event_action, event_outcome, "
            " src_ip, dst_ip, src_port, dst_port, device_vendor, device_product, "
            " log_source, host_name, user_name, target_user, process_name, process_executable, "
            " process_command, severity, message, normalized_json, tags) VALUES"
        )

        while True:
            resp = await redis.xreadgroup(
                groupname=s.group_name,
                consumername=s.consumer_name,
                streams={s.filtered_stream_key: ">"},
                count=s.batch_size,
                block=s.block_ms,
            )

            if not resp:
                continue

            rows: List[Tuple[Any, ...]] = []
            ids: List[str] = []

            for _stream_name, messages in resp:
                for msg_id, fields in messages:
                    try:
                        row = self._build_row(msg_id, fields)
                    except Exception as exc:  # noqa: BLE001
                        logger.error(
                            "Failed to build row from record",
                            extra={"extra": {"error": str(exc), "id": msg_id, "fields": fields}},
                        )
                        await redis.xack(s.filtered_stream_key, s.group_name, msg_id)
                        continue
                    rows.append(row)
                    ids.append(msg_id)

            if not rows:
                continue

            try:
                ch.execute(insert_sql, rows)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Failed to insert rows into ClickHouse",
                    extra={"extra": {"error": str(exc), "rows": len(rows)}},
                )
                continue

            if ids:
                await redis.xack(s.filtered_stream_key, s.group_name, *ids)

            logger.info("Batch written to ClickHouse", extra={"extra": {"rows": len(rows)}})


async def _main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    settings = WriterSettings()
    worker = WriterWorker(settings)
    await worker.init()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(_main())
