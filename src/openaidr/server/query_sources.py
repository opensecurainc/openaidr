"""Bounded application query observations; no SQL text or parameter retention."""

from collections import deque
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from threading import Lock
from time import monotonic

import psycopg
from psycopg.sql import Composable

from .database_diagnostics import query_label

WINDOW_SECONDS = 300
LEASE_SECONDS = 60
MAX_OBSERVATIONS = 20_000

# Only product labels and route templates may leave the collector. Client
# headers are hints, never authentication or authorization inputs.
PAGES = {
    "/activity": "Live Activity",
    "/": "Overview", "/user-risk": "Risky Sessions/Users", "/user-risk/findings": "User findings",
    "/security-posture": "Security Posture", "/ai-inventory": "AI Inventory",
    "/ai-inventory/preview": "AI Inventory preview",
    "/ai-supply-chain": "AI Supply Chain Inventory", "/ai-skills": "AI Skills Inventory",
    "/ai-supply-chain/preview": "AI Supply Chain Inventory preview",
    "/ai-skills/preview": "AI Skills Inventory preview",
    "/gateways/overview": "Gateway Overview", "/gateways/instances": "Gateway Instances",
    "/gateways/requests": "Gateway Requests", "/gateways/instances/:id": "Gateway Instance",
    "/gateways/requests/:id": "Gateway Request",
    "/detections": "Detection Queue", "/evidence": "Evidence Search",
    "/detections/preview": "Detection Queue preview",
    "/detection-rules": "Detection Rules", "/guardrail/live": "Live Guardrail",
    "/guardrail/configuration": "Guardrail Configuration",
    "/guardrail/history": "Guardrail History", "/company-knowledge": "Company Policy and Knowledge",
    "/company-knowledge/preview/policy": "Company Policy preview",
    "/company-knowledge/preview/guardrails": "Guardrail Configuration preview",
    "/costs/agents": "AI Agent Costs", "/costs/openaidr": "Credits & Usage",
    "/costs/detections": "Credits & Usage",
    "/audit-logs": "Audit Logs", "/administration/users": "Users and Roles",
    "/administration/app": "App Health",
    "/administration/sensors": "App Health", "/administration/server": "Server Health",
    "/administration/enrollment": "Enrollment", "/administration/integrations": "Integrations",
    "/administration/settings": "Settings", "/sessions/:id": "Session",
    "/detections/reports/:id": "Investigation report",
}
CARDS = {
    "server-status": "API health and detection pipeline",
    "database-health": "Database health", "database-diagnostics": "PostgreSQL diagnostics",
    "host-metrics": "Host resource usage", "risk-summary": "Risk summary",
    "riskiest-users": "Riskiest users", "agent-costs": "AI agent cost summary",
    "guardrail-costs": "Guardrail costs", "detection-costs": "Detection costs",
    "asset-management-costs": "AI Asset Management costs", "assistant-costs": "Assistant costs",
}
ROUTE_PARTS = frozenset("""api ingest admin otlp v1 auth me login logout config status callback
    overview user-risk users invites sensors enrollment-tokens enrollment-links enroll enrollment preview
    events live findings detections eligibility rules response actions policy company-policy hook-settings
    system database diagnostics metrics settings model-keys telemetry-retention slack audit telemetry
    exports logs traces costs credits agents summary detections projects guardrail active stats hook-decisions
    inventory applications sources roots components relationships skills plugins mcp packages
    knowledge library passages uploads connections documents sync test servers tools resources
    sessions detection detection-owner guardrail-actions session-snapshots session-investigations session-investigation-reads
    approvals decision revoke hook-checks delivery guardrail-checks consume guardrail-releases outcome
    session-registrations close delivery-status heartbeat commands result acknowledge tenants admins
    deployments memberships tokens bootstrap limits reports healthz readyz""".split())


@dataclass(frozen=True)
class Source:
    page: str = ""
    card: str = ""
    endpoint: str = ""
    job: str = ""


current_source = ContextVar("query_source", default=Source())


@contextmanager
def query_source(source):
    token = current_source.set(source)
    try:
        yield
    finally:
        current_source.reset(token)


async def source_job(name, work):
    with query_source(Source(job=name)):
        return await work


def request_source(method, path, headers):
    parts = path.split("?", 1)[0].split("/")[1:]
    route = "/" + "/".join(part if part in ROUTE_PARTS else ":id" for part in parts[:10])
    method = method if method in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} else "OTHER"
    page = PAGES.get(headers.get("x-openaidr-page", ""), "") if path.startswith("/api/v1/") else ""
    card = CARDS.get(headers.get("x-openaidr-card", ""), "") if page else ""
    return Source(page=page, card=card, endpoint=f"{method} {route}")


class QuerySources:
    def __init__(self):
        self.lock = Lock()
        self.events = deque()
        self.until = 0
        self.started = 0
        self.started_at = None
        self.dropped = 0

    def active(self):
        return monotonic() < self.until

    def clear(self):
        with self.lock:
            self.until = 0
            self.events.clear()
            self.dropped = 0

    def record(self, query_id, label, source, elapsed_ms, failed, started):
        # Observability must never make a database caller wait for the panel.
        if not self.lock.acquire(blocking=False):
            self.dropped += 1
            return
        try:
            now = monotonic()
            if now >= self.until or started < self.started:
                return
            while self.events and self.events[0][0] < now - WINDOW_SECONDS:
                self.events.popleft()
            if len(self.events) >= MAX_OBSERVATIONS:
                self.events.popleft()
                self.dropped += 1
            self.events.append((now, query_id, label, source, elapsed_ms, failed))
        finally:
            self.lock.release()

    def read(self):
        now = monotonic()
        with self.lock:
            if now >= self.until:
                self.events.clear()
                self.dropped = 0
                self.started = now
                self.started_at = datetime.now(timezone.utc).isoformat()
            self.until = now + LEASE_SECONDS
            while self.events and self.events[0][0] < now - WINDOW_SECONDS:
                self.events.popleft()
            events = list(self.events)
            dropped = self.dropped
        rows = {}
        for _, ident, label, source, elapsed_ms, failed in events:
            key = (ident, source)
            if key not in rows:
                rows[key] = dict(query_id=ident, label=label, source=asdict(source),
                                 calls=0, failures=0, total_time_ms=0)
            row = rows[key]
            row["calls"] += 1
            row["failures"] += int(failed)
            row["total_time_ms"] += elapsed_ms
        ranked = sorted(rows.values(), key=lambda row: row["total_time_ms"], reverse=True)
        return dict(
            status="limited" if dropped else "ok", items=ranked[:20],
            omitted_groups=max(0, len(ranked) - 20), dropped_observations=dropped,
            window_seconds=round(min(WINDOW_SECONDS, now - self.started), 1),
            collection_started_at=self.started_at,
        )


class SourceCursor(psycopg.Cursor):
    def __init__(self, *args, collector, **kwargs):
        super().__init__(*args, **kwargs)
        self.collector = collector

    def execute(self, query, params=None, **kwargs):
        if not self.collector.active():
            return super().execute(query, params, **kwargs)
        started = monotonic()
        failed = True
        try:
            result = super().execute(query, params, **kwargs)
            failed = False
            return result
        finally:
            elapsed_ms = (monotonic() - started) * 1000
            try:
                text = query.as_string(self.connection) if isinstance(query, Composable) else query
                if isinstance(text, bytes):
                    text = text.decode(self.connection.info.encoding)
                if isinstance(text, str) and len(text) <= 65_536:
                    ident = "app:" + sha256(text.encode()).hexdigest()[:16]
                    self.collector.record(ident, query_label(text), current_source.get(), elapsed_ms, failed, started)
                else:
                    self.collector.dropped += 1
            except Exception:
                # Diagnostic failures must not alter query results or errors.
                self.collector.dropped += 1
