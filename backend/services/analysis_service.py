"""Daily AI analysis of the past 24h of homelab telemetry.

Pipeline:
  1. Pull aggregated stats from Elasticsearch (vuln counts by severity,
     scan runs, devices seen, top CVEs) for a configurable window.
  2. Render a compact prompt — we keep the payload small so small local
     models (Gemma 4B, Llama 3 8B, etc.) don't truncate or hallucinate.
  3. Call Ollama via the OpenAI-compatible endpoint.
  4. Persist the report (markdown body + the raw input + response) to SQLite
     for later rendering in /analysis.

This is deliberately prompt-first and cheap to iterate on — tuning the
prompt and stat aggregation is the main lever for output quality.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from database import get_db

log = logging.getLogger(__name__)


# ── Prompt ───────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a security and network operations analyst for a home
lab. You receive a JSON summary of the past 24 hours of network telemetry
(devices, vulnerability scans, scheduler runs). Produce a concise, actionable
daily brief in Markdown with these sections:

## Executive Summary
2–3 sentences on overall health.

## Notable Changes
New devices, newly-offline devices, major vuln count changes vs. prior periods.

## Top Risks
Up to 5 highest-severity or highest-scoring findings, each with:
- **CVE or name** (severity)
- One-line impact
- Recommended action (patch / mitigation / accept)

## Recommendations
3–5 specific follow-ups for the operator this week.

Be terse. Avoid boilerplate caveats. If data is thin, say so plainly rather
than padding. Do not invent CVEs or findings — only reference what the data
shows."""


# ── Aggregation ──────────────────────────────────────────────────────────────


async def _aggregate_es_stats(period_hours: int = 24) -> dict:
    """Pull per-window stats from Elasticsearch. Always returns a dict —
    fields default to empty/zero when ES is absent or a query fails so the
    downstream prompt still renders."""
    from integrations.elasticsearch_client import (
        get_es_client,
        IDX_DEVICES,
        IDX_SCANS,
        IDX_VULNS,
    )

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=period_hours)
    start_iso, end_iso = start.isoformat(), end.isoformat()

    stats: dict = {
        "period": {"start": start_iso, "end": end_iso, "hours": period_hours},
        "devices": {"online": 0, "offline": 0, "total": 0, "by_type": {}},
        "scans": {"nmap_runs": 0, "openvas_runs": 0, "total_findings": 0},
        "vulns": {
            "new_in_period": 0,
            "by_severity": {},
            "top_findings": [],  # [{name, cve, severity, score, device_ip}]
        },
        "elasticsearch_available": False,
    }

    es = get_es_client()
    if es is None:
        return stats

    client = es._get_client()  # internal AsyncElasticsearch
    if client is None:
        return stats

    stats["elasticsearch_available"] = True

    # 1. Device snapshot (most recent doc per device)
    try:
        r = await client.search(
            index=IDX_DEVICES,
            body={"size": 1000, "sort": [{"@timestamp": "desc"}]},
        )
        seen_ids = set()
        by_type: dict = {}
        online = offline = 0
        for hit in r.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            did = src.get("id") or hit.get("_id")
            if did in seen_ids:
                continue
            seen_ids.add(did)
            t = src.get("device_type") or "unknown"
            by_type[t] = by_type.get(t, 0) + 1
            if src.get("is_online"):
                online += 1
            else:
                offline += 1
        stats["devices"] = {
            "online": online,
            "offline": offline,
            "total": online + offline,
            "by_type": by_type,
        }
    except Exception as e:
        log.debug("ES device aggregate failed: %s", e)

    # 2. Scan runs in window
    try:
        r = await client.search(
            index=IDX_SCANS,
            body={
                "size": 0,
                "query": {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}},
                "aggs": {"by_type": {"terms": {"field": "scan_type"}}},
            },
        )
        buckets = r.get("aggregations", {}).get("by_type", {}).get("buckets", [])
        for b in buckets:
            key = b.get("key")
            if key == "nmap":
                stats["scans"]["nmap_runs"] = b.get("doc_count", 0)
            elif key == "openvas":
                stats["scans"]["openvas_runs"] = b.get("doc_count", 0)
    except Exception as e:
        log.debug("ES scan aggregate failed: %s", e)

    # 3. Vulns in window + severity breakdown + top findings
    try:
        r = await client.search(
            index=IDX_VULNS,
            body={
                "size": 20,
                "query": {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}},
                "sort": [{"score": "desc"}],
                "aggs": {"by_severity": {"terms": {"field": "severity"}}},
            },
        )
        total = r.get("hits", {}).get("total", {})
        if isinstance(total, dict):
            stats["vulns"]["new_in_period"] = total.get("value", 0)
        by_sev: dict = {}
        for b in r.get("aggregations", {}).get("by_severity", {}).get("buckets", []):
            by_sev[b.get("key")] = b.get("doc_count", 0)
        stats["vulns"]["by_severity"] = by_sev

        tops = []
        for hit in r.get("hits", {}).get("hits", [])[:10]:
            s = hit.get("_source", {})
            tops.append(
                {
                    "name": (s.get("name") or "")[:120],
                    "cve": s.get("cve_id") or "",
                    "severity": s.get("severity"),
                    "score": s.get("score"),
                    "device_ip": s.get("device_ip"),
                    "port": s.get("port"),
                }
            )
        stats["vulns"]["top_findings"] = tops
        stats["scans"]["total_findings"] = stats["vulns"]["new_in_period"]
    except Exception as e:
        log.debug("ES vuln aggregate failed: %s", e)

    return stats


def _build_prompt(stats: dict) -> str:
    """Render the stats as a stable, compact JSON block wrapped in a short
    instruction. Keeping this separate from SYSTEM_PROMPT makes tuning easier."""
    return (
        "Here is the homelab telemetry summary for the past "
        f"{stats['period']['hours']} hours "
        f"({stats['period']['start']} → {stats['period']['end']}). "
        "Produce the daily brief as described in the system prompt.\n\n"
        "```json\n" + json.dumps(stats, indent=2, default=str) + "\n```"
    )


# ── Orchestration ────────────────────────────────────────────────────────────


async def run_daily_analysis(period_hours: int = 24) -> Optional[str]:
    """Collect → prompt → call model → persist. Returns report id or None
    when Ollama isn't configured/enabled (caller logs the skip)."""
    from config import get_config_manager
    from integrations.ollama import OllamaIntegration

    cfg = get_config_manager().get()
    if not (cfg.ollama.enabled and cfg.ollama.host):
        log.info("daily_analysis: Ollama not configured/enabled — skipping")
        return None

    report_id = str(uuid.uuid4())
    t0 = time.time()
    stats = await _aggregate_es_stats(period_hours)
    prompt = _build_prompt(stats)

    client_ = OllamaIntegration(
        host=cfg.ollama.host,
        port=cfg.ollama.port,
        model=cfg.ollama.model,
        api_key=cfg.ollama.api_key.get_secret_value(),
    )

    now = datetime.now(timezone.utc).isoformat()
    period_start = stats["period"]["start"]
    period_end = stats["period"]["end"]

    try:
        summary = await client_.generate(
            prompt=prompt,
            system=SYSTEM_PROMPT,
            temperature=0.3,
        )
        duration_ms = int((time.time() - t0) * 1000)
        await _persist_report(
            report_id=report_id,
            generated_at=now,
            period_start=period_start,
            period_end=period_end,
            model=cfg.ollama.model,
            status="completed",
            summary_md=summary,
            input_json=stats,
            raw_prompt=prompt,
            raw_response=summary,
            error=None,
            duration_ms=duration_ms,
        )
        log.info(
            "daily_analysis: report %s stored (%d ms, %d chars)",
            report_id,
            duration_ms,
            len(summary),
        )
        return report_id

    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        log.error("daily_analysis: generation failed: %s", e)
        await _persist_report(
            report_id=report_id,
            generated_at=now,
            period_start=period_start,
            period_end=period_end,
            model=cfg.ollama.model,
            status="failed",
            summary_md=None,
            input_json=stats,
            raw_prompt=prompt,
            raw_response=None,
            error=str(e),
            duration_ms=duration_ms,
        )
        return report_id


async def _persist_report(
    report_id: str,
    generated_at: str,
    period_start: str,
    period_end: str,
    model: str,
    status: str,
    summary_md: Optional[str],
    input_json: dict,
    raw_prompt: Optional[str],
    raw_response: Optional[str],
    error: Optional[str],
    duration_ms: int,
) -> None:
    async with get_db() as db:
        await db.execute(
            """INSERT INTO analysis_reports
               (id, generated_at, period_start, period_end, model, status,
                summary_md, input_json, raw_prompt, raw_response, error, duration_ms)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                report_id,
                generated_at,
                period_start,
                period_end,
                model,
                status,
                summary_md,
                json.dumps(input_json, default=str),
                raw_prompt,
                raw_response,
                error,
                duration_ms,
            ),
        )
        await db.commit()


# ── Read helpers used by the API ─────────────────────────────────────────────


async def list_reports(limit: int = 50) -> list[dict]:
    async with get_db() as db:
        rows = await (
            await db.execute(
                """SELECT id, generated_at, period_start, period_end, model,
                      status, duration_ms,
                      substr(coalesce(summary_md, error, ''), 1, 300) AS preview
               FROM analysis_reports
               ORDER BY generated_at DESC
               LIMIT ?""",
                (limit,),
            )
        ).fetchall()
    return [dict(r) for r in rows]


async def get_report(report_id: str) -> Optional[dict]:
    async with get_db() as db:
        row = await (
            await db.execute(
                "SELECT * FROM analysis_reports WHERE id = ?", (report_id,)
            )
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    # Parse input_json for the frontend so we don't send a nested JSON string.
    try:
        d["input_json"] = json.loads(d.get("input_json") or "{}")
    except Exception:
        d["input_json"] = {}
    return d


async def delete_report(report_id: str) -> bool:
    async with get_db() as db:
        cur = await db.execute(
            "DELETE FROM analysis_reports WHERE id = ?", (report_id,)
        )
        await db.commit()
        return (cur.rowcount or 0) > 0
