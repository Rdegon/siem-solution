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
    cmdb_table: str = os.getenv("SIEM_CMDB_TABLE", "siem.cmdb_assets")
    threat_intel_table: str = os.getenv("SIEM_THREAT_INTEL_TABLE", "siem.threat_intel_iocs")
    enrichment_refresh_secs: int = int(os.getenv("SIEM_ENRICHMENT_REFRESH_SECS", "60"))


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
        self._cmdb_by_host: Dict[str, Dict[str, str]] = {}
        self._cmdb_by_ip: Dict[str, Dict[str, str]] = {}
        self._threat_intel: Dict[str, Dict[str, List[Dict[str, str]]]] = {}
        self._threat_intel_raw: List[tuple[str, Dict[str, str]]] = []
        self._enrichment_loaded_at: datetime | None = None

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
        self._refresh_enrichment_cache(force=True)
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

    def _build_normalized_json(
        self,
        fields: Dict[str, str],
        active_list_matches: List[Dict[str, str]] | None = None,
        cmdb_asset: Dict[str, str] | None = None,
        threat_intel_matches: List[Dict[str, str]] | None = None,
    ) -> str:
        payload = {
            "provider": fields.get("event.provider", ""),
            "category": fields.get("event.category", ""),
            "type": fields.get("event.type", ""),
            "code": fields.get("event.code", ""),
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
            "enrichment": {
                "active_lists": active_list_matches or [],
                "cmdb": cmdb_asset or {},
                "threat_intel": threat_intel_matches or [],
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

    def _refresh_enrichment_cache(self, *, force: bool = False) -> None:
        assert self._ch is not None
        now = datetime.now(timezone.utc)
        if not force and self._enrichment_loaded_at is not None:
            age = (now - self._enrichment_loaded_at).total_seconds()
            if age < self._settings.enrichment_refresh_secs:
                return

        cmdb_by_host: Dict[str, Dict[str, str]] = {}
        cmdb_by_ip: Dict[str, Dict[str, str]] = {}
        threat_intel: Dict[str, Dict[str, List[Dict[str, str]]]] = {}
        threat_intel_raw: List[tuple[str, Dict[str, str]]] = []

        try:
            exists = self._ch.execute(f"EXISTS TABLE {self._settings.cmdb_table}")
            if exists and exists[0][0]:
                rows = self._ch.execute(
                    f"""
                    SELECT asset_id, asset_type, hostname, ip, owner, criticality, environment, business_service, os_family, expected_ports, tags
                    FROM {self._settings.cmdb_table}
                    WHERE enabled = 1
                    """
                )
                for asset_id, asset_type, hostname, ip_value, owner, criticality, environment, business_service, os_family, expected_ports, tags in rows:
                    item = {
                        "asset_id": str(asset_id or "").strip(),
                        "asset_type": str(asset_type or "").strip(),
                        "hostname": str(hostname or "").strip().lower(),
                        "ip": str(ip_value or "").strip(),
                        "owner": str(owner or "").strip(),
                        "criticality": str(criticality or "").strip().lower(),
                        "environment": str(environment or "").strip().lower(),
                        "business_service": str(business_service or "").strip(),
                        "os_family": str(os_family or "").strip().lower(),
                        "expected_ports": str(expected_ports or "").strip(),
                        "tags": str(tags or "").strip(),
                    }
                    if item["hostname"]:
                        cmdb_by_host[item["hostname"]] = item
                    if item["ip"]:
                        cmdb_by_ip[item["ip"]] = item
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to refresh CMDB cache", extra={"extra": {"error": str(exc)}})

        try:
            exists = self._ch.execute(f"EXISTS TABLE {self._settings.threat_intel_table}")
            if exists and exists[0][0]:
                rows = self._ch.execute(
                    f"""
                    SELECT indicator_type, indicator, provider, severity, confidence, description, tags
                    FROM {self._settings.threat_intel_table}
                    WHERE enabled = 1
                      AND (expires_ts IS NULL OR expires_ts >= now())
                    """
                )
                for indicator_type, indicator, provider, severity, confidence, description, tags in rows:
                    item = {
                        "indicator_type": str(indicator_type or "").strip().lower(),
                        "indicator": str(indicator or "").strip().lower(),
                        "provider": str(provider or "").strip(),
                        "severity": str(severity or "").strip().lower(),
                        "confidence": str(confidence or "").strip(),
                        "description": str(description or "").strip(),
                        "tags": str(tags or "").strip(),
                    }
                    if item["indicator_type"] == "raw":
                        threat_intel_raw.append((item["indicator"], item))
                        continue
                    threat_intel.setdefault(item["indicator_type"], {}).setdefault(item["indicator"], []).append(item)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to refresh threat intel cache", extra={"extra": {"error": str(exc)}})

        self._cmdb_by_host = cmdb_by_host
        self._cmdb_by_ip = cmdb_by_ip
        self._threat_intel = threat_intel
        self._threat_intel_raw = threat_intel_raw
        self._enrichment_loaded_at = now

    def _match_cmdb_asset(self, fields: Dict[str, str]) -> Dict[str, str] | None:
        self._refresh_enrichment_cache()
        host_candidates = [
            str(fields.get("host.name", "") or "").strip().lower(),
            str(fields.get("log_source", "") or "").strip().lower(),
        ]
        for candidate in host_candidates:
            if candidate and candidate in self._cmdb_by_host:
                return dict(self._cmdb_by_host[candidate])
        ip_candidates = [
            str(fields.get("source.ip", "") or "").strip(),
            str(fields.get("destination.ip", "") or "").strip(),
            str(fields.get("log_source", "") or "").strip(),
        ]
        for candidate in ip_candidates:
            if candidate and candidate in self._cmdb_by_ip:
                return dict(self._cmdb_by_ip[candidate])
        return None

    def _match_threat_intel(self, fields: Dict[str, str]) -> Tuple[List[str], List[Dict[str, str]]]:
        self._refresh_enrichment_cache()
        candidates = {
            "ip": [fields.get("source.ip", ""), fields.get("destination.ip", "")],
            "host": [fields.get("host.name", ""), fields.get("log_source", "")],
            "user": [fields.get("user.name", ""), fields.get("user.target.name", "")],
            "process": [fields.get("process.name", ""), fields.get("process.executable", "")],
        }
        tags: List[str] = []
        seen: set[str] = set()
        matches: List[Dict[str, str]] = []
        match_seen: set[tuple[str, str, str]] = set()
        for indicator_type, values in candidates.items():
            bucket = self._threat_intel.get(indicator_type, {})
            if not bucket:
                continue
            for value in values:
                normalized = str(value or "").strip().lower()
                if not normalized:
                    continue
                for match in bucket.get(normalized, []):
                    key = (match["indicator_type"], match["indicator"], match["provider"])
                    if key not in match_seen:
                        match_seen.add(key)
                        matches.append(dict(match))
                    for tag in [f"ti:{match['provider'] or 'feed'}", f"ti_severity:{match['severity']}", *self._normalize_tags(match.get("tags", ""))]:
                        if tag and tag not in seen:
                            seen.add(tag)
                            tags.append(tag)
        raw_haystack = str(fields.get("event.original", "") or fields.get("message", "")).lower()
        for indicator, match in self._threat_intel_raw:
            if indicator and indicator in raw_haystack:
                key = (match["indicator_type"], match["indicator"], match["provider"])
                if key not in match_seen:
                    match_seen.add(key)
                    matches.append(dict(match))
                for tag in [f"ti:{match['provider'] or 'feed'}", f"ti_severity:{match['severity']}", *self._normalize_tags(match.get("tags", ""))]:
                    if tag and tag not in seen:
                        seen.add(tag)
                        tags.append(tag)
        return tags, matches

    def _match_active_lists(self, fields: Dict[str, str]) -> Tuple[List[str], List[Dict[str, str]]]:
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
        match_seen: set[tuple[str, str, str]] = set()
        matches: List[Dict[str, str]] = []
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
                            match_key = (meta["list_name"], meta.get("list_kind", "watch"), raw_value)
                            if match_key not in match_seen:
                                match_seen.add(match_key)
                                matches.append({
                                    "list_name": meta["list_name"],
                                    "list_kind": meta.get("list_kind", "watch"),
                                    "value_type": value_type,
                                    "value": raw_value,
                                    "label": meta.get("label", ""),
                                    "tags": meta.get("tags", ""),
                                })
                            for tag in [f"{prefix}:{meta['list_name']}", *self._normalize_tags(meta.get("tags", ""))]:
                                if tag and tag not in seen:
                                    seen.add(tag)
                                    tags.append(tag)
                    continue
                meta = bucket.get(normalized)
                if not meta:
                    continue
                prefix = {"watch": "watchlist", "allow": "allowlist", "deny": "denylist"}.get(meta.get("list_kind", "watch"), "watchlist")
                match_key = (meta["list_name"], meta.get("list_kind", "watch"), normalized)
                if match_key not in match_seen:
                    match_seen.add(match_key)
                    matches.append({
                        "list_name": meta["list_name"],
                        "list_kind": meta.get("list_kind", "watch"),
                        "value_type": value_type,
                        "value": normalized,
                        "label": meta.get("label", ""),
                        "tags": meta.get("tags", ""),
                    })
                for tag in [f"{prefix}:{meta['list_name']}", *self._normalize_tags(meta.get("tags", ""))]:
                    if tag and tag not in seen:
                        seen.add(tag)
                        tags.append(tag)
        return tags, matches

    def _build_row(self, msg_id: str, fields: Dict[str, str]) -> Tuple[Any, ...]:
        ts = self._parse_event_ts(fields)
        event_id = fields.get("event_id") or msg_id
        event_code = fields.get("event.code") or fields.get("winlog.event_id") or fields.get("audit.type") or ""
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
        cmdb_asset = self._match_cmdb_asset(fields) or {}
        threat_intel_tags, threat_intel_matches = self._match_threat_intel(fields)
        top_ti = sorted(
            threat_intel_matches,
            key=lambda item: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(item.get("severity") or "").lower(), 0),
            reverse=True,
        )[0] if threat_intel_matches else {}

        tags = self._normalize_tags(fields.get("tags"))
        active_list_tags, active_list_matches = self._match_active_lists(fields)
        tags.extend(active_list_tags)
        tags.extend(threat_intel_tags)
        if subcategory:
            tags.append(f"event_type:{subcategory}")
        if cmdb_asset.get("asset_id"):
            tags.append(f"asset:{cmdb_asset['asset_id']}")
        if cmdb_asset.get("criticality"):
            tags.append(f"asset_criticality:{cmdb_asset['criticality']}")
        if cmdb_asset.get("environment"):
            tags.append(f"asset_environment:{cmdb_asset['environment']}")
        tags.extend(self._normalize_tags(cmdb_asset.get("tags", "")))
        tags_text = ",".join(dict.fromkeys(tag for tag in tags if tag))
        normalized_json = self._build_normalized_json(fields, active_list_matches, cmdb_asset, threat_intel_matches)

        return (
            ts,
            event_id,
            event_code,
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
            cmdb_asset.get("asset_id", ""),
            cmdb_asset.get("owner", ""),
            cmdb_asset.get("criticality", ""),
            cmdb_asset.get("environment", ""),
            cmdb_asset.get("business_service", ""),
            user_name,
            target_user,
            process_name,
            process_executable,
            process_command,
            top_ti.get("indicator", ""),
            top_ti.get("indicator_type", ""),
            top_ti.get("provider", ""),
            top_ti.get("severity", ""),
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
            "(ts, event_id, event_code, category, subcategory, event_action, event_outcome, "
            " src_ip, dst_ip, src_port, dst_port, device_vendor, device_product, "
            " log_source, host_name, asset_id, asset_owner, asset_criticality, asset_environment, asset_service, "
            " user_name, target_user, process_name, process_executable, process_command, "
            " ti_indicator, ti_indicator_type, ti_provider, ti_severity, severity, message, normalized_json, tags) VALUES"
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
