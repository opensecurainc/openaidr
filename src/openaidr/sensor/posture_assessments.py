"""Opt-in, account-bound package assessments with durable dispatch identities."""

import asyncio
from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import time

from openaidr_api_client.client import IntelligenceClient, Unavailable
from openaidr_api_client.clients.threat_intel import ThreatIntelClient
from openaidr_api_client.contracts.capabilities import Capabilities
from openaidr_api_client.contracts.credits import microcredits
from openaidr_api_client.validation.osv import package_query

from openaidr.core.files import atomic_write
from .config import Config, configuration_lock
from .inventory_service import InventoryService
from .posture_store import Store
from .usage import identity

MODES = ("free", "api_key")


def enabled(config):
    options = config.get("posture", {})
    return (config.get("connection_mode") in MODES and isinstance(options, dict)
            and options.get("automatic") is True and options.get("scope") == identity(config))


def configure(config, automatic, scope):
    if type(automatic) is not bool:
        raise ValueError("Choose whether automatic assessments are enabled.")
    with configuration_lock(config.path):
        current = Config.load(config.path)
        if not current.enrolled() or current.get("connection_mode") not in MODES or scope != identity(current):
            raise ValueError("The Posture connection changed. Refresh before changing assessments.")
        current["posture"] = {"automatic": automatic, "scope": scope}
        current.save()
    return {"enabled": automatic, "scope": scope}


def connection(config):
    if config.get("connection_mode") == "free":
        from .free_enrollment import prepare
        return prepare(config).connection
    from .api_key import connection as key_connection
    return key_connection(config)


def package_key(query):
    return "package:" + hashlib.sha256(json.dumps(query, sort_keys=True).encode()).hexdigest()


def packages(config):
    snapshot = InventoryService(config, None, components=True).state.get("snapshot", {})
    result = {}
    for root in snapshot.get("roots", []):
        for row in root.get("components", []):
            if row.get("kind") == "package":
                query, _ = package_query(row)
                if query is not None:
                    result[package_key(query)] = query
    return result


def eligible(record, stamp):
    if not record:
        return True
    if record["state"] in ("pending", "unknown"):
        return False
    if record["state"] == "retry":
        return record["retry_at"] is not None and record["retry_at"] <= stamp
    if record.get("billing_state") not in ("settled", "released", "disabled"):
        return False
    value = (record.get("report") or {}).get("expires_at")
    return value is not None and datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() <= stamp


class Client(ThreatIntelClient):
    # Keep typed pre-admission status codes; the general threat client erases them.
    request = IntelligenceClient.request


async def balance(client, config, transport=None):
    if config.get("connection_mode") == "free":
        from .desktop_free_usage import fetch, project
        value = await fetch(client.connection, transport)
        if value.get("tenant_id") != client.tenant_id or value.get("plan") != "free":
            raise ValueError("Credit identity differs")
        usage = project(value.get("usage"))
        return {key: usage[key] for key in ("status", "available", "reserved", "used", "resets_at", "checked_at")}
    value = await client.credits()
    return dict(status=value.status, available=value.balance.available, reserved=value.balance.reserved,
                used=value.summary.credits_charged, resets_at=None, checked_at=value.until)


def save_status(config, state, billing=None):
    value = dict(scope=identity(config), checked_at=time.time(), state=state, billing=billing)
    atomic_write(Path(config["data_dir"]) / "posture-status.json", json.dumps(value))


def status(config):
    value = dict(enabled=enabled(config), state="disabled" if not enabled(config) else "waiting", billing=None)
    try:
        with (Path(config["data_dir"]) / "posture-status.json").open() as stream:
            saved = json.loads(stream.read(8193))
        if saved["scope"] == identity(config) and 0 <= time.time() - saved["checked_at"] <= 180:
            value.update(state=saved["state"] if value["enabled"] else "disabled", billing=saved["billing"])
    except (OSError, ValueError, TypeError, KeyError):
        pass
    path = Path(config["data_dir"]) / "posture-assessments.sqlite3"
    value["usage"] = Store(config).summary() if path.exists() else None
    return value


def enrich(config, groups):
    """Project retained evidence only; never collect or make a network request."""
    from .local_posture import record_id
    state = status(config)
    path = Path(config["data_dir"]) / "posture-assessments.sqlite3"
    store = Store(config) if path.exists() else None
    installations = {}
    snapshot = InventoryService(config, None, components=True).state.get("snapshot", {})
    for root in snapshot.get("roots", []):
        for row in root.get("components", []):
            if row.get("kind") == "package":
                query, _ = package_query(row)
                installations[record_id(root["source"], root["root"], row)] = package_key(query) if query else None
    records = store.records(list(set(installations.values()) - {None})) if store else {}
    for item in groups["components"]["items"]:
        if item["kind"] != "package":
            continue
        key = installations.get(item["id"])
        record = records.get(key, {})
        report = record.get("report") or {}
        item["assessment_status"] = ("unsupported" if not key else "failed" if record.get("state") in ("retry", "unknown")
            else "pending" if record.get("state") == "pending" else "stale" if report and record["expires_at"] <= time.time()
            else "complete" if report else "pending" if state["enabled"] else "disabled")
        findings = report.get("findings", [])
        item.update(findings=findings[:10], findings_truncated=len(findings) > 10,
                    attention=item["attention"] or bool(findings) or item["assessment_status"] in ("failed", "stale"))
    from .posture_skill_state import enrich as skills_enrich

    skills_enrich(config, groups["skills"]["items"], store, state["enabled"])
    return state


class Worker:
    def __init__(self, config, paused=lambda: False, *, transport=None):
        self.path, self.paused, self.transport = config.path, paused, transport

    def active(self, config, stop=None):
        latest = Config.load(self.path)
        return (not self.paused() and not (stop and stop.is_set()) and enabled(latest)
                and identity(latest) == identity(config) and latest.get("sensor_token") == config.get("sensor_token"))

    async def once(self, stop=None):
        config = Config.load(self.path)
        if not self.active(config, stop):
            return False
        try:
            with (Path(config["data_dir"]) / "posture-status.json").open() as stream:
                previous = json.loads(stream.read(8193))
            if (previous["scope"] == identity(config) and previous["state"] == "exhausted"
                    and 0 <= time.time() - previous["checked_at"] < 900):
                return False
        except (OSError, ValueError, KeyError, TypeError):
            pass
        remote = connection(config)
        transport = self.transport
        if transport is None:
            from . import network_proxy

            # One proxied transport for this pass, shared with the balance reads.
            transport = network_proxy.async_transport(config, remote.origin, remote.verify())
        client = Client.from_connection(remote, transport=transport)
        billing = None
        try:
            billing = await balance(client, config, transport)
            if billing["status"] != "active":
                save_status(config, billing["status"], billing)
                return False
            if microcredits(billing["available"]) == 0:
                save_status(config, "exhausted", billing)
                return False
            store, candidates, stamp = Store(config), packages(config), time.time()
            records = store.records(list(candidates))
            package_keys = [key for key in sorted(candidates) if eligible(records.get(key), stamp)][:25]
            service, skill, prepared = "package_vulnerabilities", None, False
            for attempt in range(4):
                if not self.active(config, stop):
                    return False
                readiness = Capabilities.model_validate(await client.request("/v1/capabilities", None, 16 << 10, 10, method="GET"))
                if readiness.tenant_id != client.tenant_id:
                    raise ValueError("Capability identity differs")
                if not self.active(config, stop):
                    return False
                capabilities = [readiness.capabilities[name] for name in ("package_vulnerabilities", "skill_assessment")]
                keys = package_keys if capabilities[0] == "configured" else []
                if not keys and capabilities[1] == "configured" and not prepared:
                    from .posture_skill_state import prepare

                    skill = prepare(config, store, lambda: not self.active(config, stop))
                    prepared = True
                    if skill:
                        service, keys = "skill_assessment", [skill["key"]]
                if keys or attempt == 3 or "runtime_unavailable" not in capabilities:
                    break
                # A cold scanner probe can outlive one capability response.
                await asyncio.sleep(2)
            with configuration_lock(config.path):
                if not keys or not self.active(config, stop):
                    unavailable = not keys and any(value != "configured" for value in capabilities)
                    save_status(config, "unavailable" if unavailable else "idle", billing)
                    return False
                request_id = store.claim(service, keys, now=time.time())
            if request_id is None:
                return False
            save_status(config, "running", billing)
            received = None

            async def receipt(value):
                nonlocal received
                store.receipt(request_id, value)
                received = value

            try:
                if skill:
                    from openaidr_api_client.clients.threat_intel import billing as receive_billing
                    from .posture_skills import report

                    value = await client.request("/v1/services/skills/assess-bundle", skill["task"], 4 << 20, 130, request_id=request_id)
                    await receive_billing(value, service, request_id, receipt)
                    reports = {skill["key"]: report(skill["task"], value)}
                else:
                    results = await client.packages([candidates[key] for key in keys], request_id=request_id, receipt=receipt)
                    reports = {}
                    for key, result in zip(keys, results, strict=True):
                        if result["status"] != "complete":
                            raise ValueError("Incomplete package result")
                        reports[key] = dict(status="complete", checked_at=result["checked_at"].isoformat(),
                            expires_at=result["expires_at"].isoformat(), findings=[
                                {"title": item["id"], "detail": item["summary"]} for item in result["findings"]])
                store.complete(request_id, reports)
            except Unavailable as error:
                # These responses confirm rejection before paid dispatch. A lost
                # response or a duplicate ID cannot establish that no charge occurred.
                rejected = error.status_code in (400, 401, 402, 403, 404, 429)
                store.fail(request_id, retry_at=time.time() + 900 if rejected else None)
                save_status(config, "exhausted" if error.status_code == 402 else "unavailable", None)
                return False
            except Exception:
                released = received and received["state"] in ("released", "disabled")
                store.fail(request_id, retry_at=time.time() + 900 if released else None)
                save_status(config, "unavailable", None)
                return False
            billing = await balance(client, config, transport)
            save_status(config, "idle", billing)
            return True
        except Exception:
            save_status(config, "unavailable", None)
            return False
        finally:
            await client.aclose()

    def run(self, stop):
        while not stop.is_set():
            try:
                worked = asyncio.run(self.once(stop))
            except Exception:
                logging.warning("Local Posture assessment unavailable")
                worked = False
            stop.wait(1 if worked else 60)
