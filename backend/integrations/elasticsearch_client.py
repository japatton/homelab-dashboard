from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from .base import BaseIntegration, ConnectionResult

log = logging.getLogger(__name__)

# Index names
IDX_DEVICES  = "homelab-devices"
IDX_SCANS    = "homelab-scans"
IDX_VULNS    = "homelab-vulns"

INDEX_TEMPLATES = {
    IDX_DEVICES: {
        "mappings": {
            "properties": {
                "mac": {"type": "keyword"},
                "ip": {"type": "ip"},
                "hostname": {"type": "keyword"},
                "device_type": {"type": "keyword"},
                "is_online": {"type": "boolean"},
                "@timestamp": {"type": "date"},
            }
        }
    },
    IDX_SCANS: {
        "mappings": {
            "properties": {
                "scan_type": {"type": "keyword"},
                "device_id": {"type": "keyword"},
                "@timestamp": {"type": "date"},
            }
        }
    },
    IDX_VULNS: {
        "mappings": {
            "properties": {
                "device_id": {"type": "keyword"},
                "cve_id": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "score": {"type": "float"},
                "@timestamp": {"type": "date"},
            }
        }
    },
}


class ElasticsearchClient(BaseIntegration):
    name = "elasticsearch"

    def __init__(self, host: str, port: int = 9200, user: str = "", password: str = ""):
        self._host = host
        self._port = port
        self._user = user
        self._password = password
        self._es = None

    def _get_client(self):
        if self._es is not None:
            return self._es
        try:
            from elasticsearch import AsyncElasticsearch
            kwargs: dict = {"hosts": [f"http://{self._host}:{self._port}"]}
            if self._user:
                kwargs["basic_auth"] = (self._user, self._password)
            self._es = AsyncElasticsearch(**kwargs)
        except ImportError:
            log.warning("elasticsearch package not installed")
            self._es = None
        return self._es

    async def test_connection(self) -> ConnectionResult:
        es = self._get_client()
        if es is None:
            return ConnectionResult.offline("elasticsearch package not available")
        try:
            info = await es.info()
            version = info.get("version", {}).get("number", "unknown")
            return ConnectionResult.success(f"Elasticsearch {version}")
        except Exception as e:
            return ConnectionResult.offline(self._safe_error(e))

    async def ensure_indices(self) -> None:
        es = self._get_client()
        if es is None:
            return
        try:
            for index, body in INDEX_TEMPLATES.items():
                exists = await es.indices.exists(index=index)
                if not exists:
                    await es.indices.create(index=index, body=body)
        except Exception as e:
            log.warning("ES index setup failed: %s", self._safe_error(e))

    async def store_device_snapshot(self, device: dict) -> None:
        es = self._get_client()
        if es is None:
            return
        try:
            doc = {**device, "@timestamp": datetime.now(timezone.utc).isoformat()}
            await es.index(index=IDX_DEVICES, id=device.get("id"), document=doc)
        except Exception as e:
            log.warning("ES device store failed: %s", self._safe_error(e))

    async def store_scan_result(self, scan_id: str, scan_type: str, device_id: str, summary: dict) -> None:
        es = self._get_client()
        if es is None:
            return
        try:
            doc = {
                "scan_id": scan_id,
                "scan_type": scan_type,
                "device_id": device_id,
                "summary": summary,
                "@timestamp": datetime.now(timezone.utc).isoformat(),
            }
            await es.index(index=IDX_SCANS, document=doc)
        except Exception as e:
            log.warning("ES scan store failed: %s", self._safe_error(e))

    async def store_vuln_result(self, vuln: dict) -> None:
        es = self._get_client()
        if es is None:
            return
        try:
            doc = {**vuln, "@timestamp": datetime.now(timezone.utc).isoformat()}
            await es.index(index=IDX_VULNS, document=doc)
        except Exception as e:
            log.warning("ES vuln store failed: %s", self._safe_error(e))

    async def query_device_stats(self, device_id: str, days: int = 7) -> list[dict]:
        es = self._get_client()
        if es is None:
            return []
        try:
            result = await es.search(
                index=IDX_DEVICES,
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"id": device_id}},
                                {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
                            ]
                        }
                    },
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "size": 100,
                },
            )
            return [hit["_source"] for hit in result.get("hits", {}).get("hits", [])]
        except Exception as e:
            log.warning("ES query failed: %s", self._safe_error(e))
            return []

    async def close(self) -> None:
        if self._es is not None:
            await self._es.close()
            self._es = None


# ── Module-level singleton ───────────────────────────────────────────────────
# The previous pattern was to instantiate ElasticsearchClient on every call
# site, which closed the connection between uses. Callers should use
# get_es_client() to share one long-lived client across the process. Returns
# None when ES isn't configured so callers can no-op cleanly.

_client: Optional[ElasticsearchClient] = None


def get_es_client() -> Optional[ElasticsearchClient]:
    global _client
    if _client is not None:
        return _client

    from config import get_config_manager

    cfg = get_config_manager().get()
    if not cfg.elasticsearch.host:
        return None

    _client = ElasticsearchClient(
        host=cfg.elasticsearch.host,
        port=cfg.elasticsearch.port,
        user=cfg.elasticsearch.user,
        password=cfg.elasticsearch.password.get_secret_value(),
    )
    return _client


async def close_es_client() -> None:
    global _client
    if _client is not None:
        await _client.close()
        _client = None
