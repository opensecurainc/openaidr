"""Tenant-bound Intelligence service status and guardrail adapters."""

import asyncio
import json
import time
from dataclasses import replace

import httpx

from .httpx import APIError, require
from openaidr_api_client.client import Connection, SyncIntelligenceClient, Unavailable
from openaidr_api_client.contracts.capabilities import Capabilities
from .store import now, new_id
from . import free_tier
from .intelligence import ORIGINS, cipher, connection_for_origin, selected_connection, selection, switchable
from psycopg.types.json import Jsonb


KINDS = ("guardrail", "detection")


def check_capabilities(tenant, data, cfg, st=None):
    require(isinstance(data, dict) and not data, "Capability checks do not accept connection settings")
    return verify_capabilities(tenant, selected_connection(cfg, st))


def verify_capabilities(tenant, connection, *, previous=None):
    client = None
    environment = {"https://api.opensecura.ai": "Production"}.get(
        connection.origin if connection else "", "The Intelligence service")
    try:
        require(connection is not None and connection.tenant_id == tenant,
                "The selected Intelligence service is unavailable for this workspace.", 409)
        client = SyncIntelligenceClient.from_connection(connection)
        try:
            result = Capabilities.model_validate(client.request("/v1/capabilities", None, 16 << 10, 10, method="GET"))
        except Unavailable as error:
            if error.status_code not in (401, 403):
                raise
            from openaidr.core.service_keys import claim
            result = asyncio.run(claim(connection, previous))
        if result.tenant_id != tenant:
            raise APIError(400, "This key belongs to a different workspace. Use an unassigned key, "
                           "or ask an administrator to restore access.")
    except Unavailable as error:
        if error.status_code in (401, 403):
            raise APIError(400, f"{environment} rejected this key. It may be revoked or from another environment. "
                           f"If the current key is lost or revoked, ask an administrator to restore access.") from None
        raise APIError(503, f"Unable to verify {environment}. Check the service connection and try again.") from None
    except (httpx.HTTPError, TimeoutError, OSError, ValueError):
        raise APIError(503, "Unable to verify the selected Intelligence service. Check its connection and tenant credential.") from None
    finally:
        if client is not None:
            client.close()
    return {**result.model_dump(), "origin": connection.origin, "checked_at": now()}


def guardrail_credential(st, tenant, cfg, *, conn=None):
    connection = selected_connection(cfg, st, conn=conn)
    return connection if connection is not None and connection.tenant_id == str(tenant) else None


def key_management_available(st, cfg, connection):
    return bool(switchable(cfg, connection) and (connection.origin in ORIGINS
                or selection(st, connection.tenant_id)["origin"] in ORIGINS))


def read(st, tenant, cfg):
    connection = Connection.from_config(cfg) if cfg is not None else None
    bound = connection is not None and connection.tenant_id == str(tenant)
    routing = {"mode": "intelligence", "origin": connection.origin if bound else "",
               "credential_configured": bound,
               "trust": "private_ca" if bound and connection.ca_file else "system",
               "capability_status": "unverified" if bound else "unavailable"}
    if bound and switchable(cfg, connection):
        current = selection(st, tenant)
        saved = {row["origin"] for row in st.many("SELECT origin FROM tenant_intelligence_keys WHERE tenant_id=$1", tenant)}
        origin = current["origin"] or connection.origin
        manageable = key_management_available(st, cfg, connection)
        routing.update(origin=current["origin"] or connection.origin, version=current["version"],
                       tenant_id=str(tenant), credential_management=manageable and bool(cfg.intelligence_keys_key),
                       credential_configured=origin == connection.origin or (origin in ORIGINS and origin in saved))
        if manageable:
            routing["environments"] = [{"origin": value, "label": "Production", "saved_key": value in saved,
                                        "credential_configured": value in saved or value == connection.origin}
                                       for value in ORIGINS]
    return {**{kind: {"configured": bound} for kind in KINDS}, "routing": routing}


def save(st, tenant, data, actor, cfg):
    raise APIError(409, "Provider API keys are managed by the Intelligence service. Configure its tenant connection in the deployment.")


def save_connection(st, tenant, data, actor, cfg):
    require(isinstance(data, dict) and set(data) == {"origin", "version"}, "origin and version are required")
    require(data["origin"] in ORIGINS and type(data["version"]) is int and data["version"] >= 0,
            "Select the Production service and a valid version")
    configured = Connection.from_config(cfg)
    require(key_management_available(st, cfg, configured) and configured.tenant_id == str(tenant),
            "Service switching is unavailable for this workspace", 409)
    require(selection(st, tenant)["version"] == data["version"], "Service selection changed. Reload Settings and try again.", 409)
    candidate = connection_for_origin(cfg, st, data["origin"])
    require(candidate is not None, "Save a key for this environment before switching.", 409)
    verified = verify_capabilities(tenant, candidate)
    with st.transaction() as conn:
        st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "intelligence-selection:" + tenant, conn=conn)
        current = selection(st, tenant, conn=conn)
        require(current["version"] == data["version"], "Service selection changed. Reload Settings and try again.", 409)
        st.execute("INSERT INTO tenant_intelligence_selection(tenant_id,origin) VALUES($1,$2) "
                   "ON CONFLICT(tenant_id) DO UPDATE SET origin=EXCLUDED.origin, "
                   "version=tenant_intelligence_selection.version+1,updated_at=now()", tenant, data["origin"], conn=conn)
        st.execute("""INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
            VALUES($1,$2,$3,$4,$5,'intelligence.service.select','intelligence',$2,$6)""",
            new_id(), tenant, actor.get("type", "user"), actor.get("id", ""), actor.get("name", ""),
            Jsonb({"before": current["origin"] or configured.origin, "origin": data["origin"],
                   "version": current["version"] + 1}), conn=conn)
    return {**read(st, tenant, cfg), "verification": verified}


def save_environment_key(st, tenant, data, actor, cfg):
    require(isinstance(data, dict) and set(data) in ({"origin", "api_key", "version"},
            {"origin", "api_key", "version", "activate"}),
            "origin, api_key and version are required")
    activate = data.get("activate", False)
    require(type(activate) is bool, "activate must be a boolean")
    require(data["origin"] in ORIGINS and type(data["version"]) is int and data["version"] >= 0
            and isinstance(data["api_key"], str) and 0 < len(data["api_key"]) <= 256,
            "Provide an environment, service key and current version")
    configured = Connection.from_config(cfg)
    require(key_management_available(st, cfg, configured) and configured.tenant_id == str(tenant),
            "Service key management is unavailable for this workspace", 409)
    encryption = cipher(cfg)
    require(selection(st, tenant)["version"] == data["version"], "Service selection changed. Reload Settings and try again.", 409)
    try:
        candidate = replace(configured, origin=data["origin"], api_key=data["api_key"].strip())
    except ValueError:
        if data["api_key"].strip().startswith("oati_"):
            raise APIError(400, "This is a legacy key. Create a new key for current OpenAIDR in the selected environment's API administration.") from None
        raise APIError(400, "Paste the complete connection key copied from API administration, without quotes or a Bearer prefix.") from None
    verified = verify_capabilities(tenant, candidate, previous=connection_for_origin(cfg, st, candidate.origin))
    encrypted = encryption.encrypt(json.dumps([tenant, candidate.origin, candidate.api_key]).encode()).decode()
    with st.transaction() as conn:
        st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "intelligence-selection:" + tenant, conn=conn)
        current = selection(st, tenant, conn=conn)
        require(current["version"] == data["version"], "Service selection changed. Reload Settings and try again.", 409)
        previous_origin = current["origin"] or configured.origin
        st.execute("""INSERT INTO tenant_intelligence_keys(tenant_id,origin,encrypted_api_key) VALUES($1,$2,$3)
            ON CONFLICT(tenant_id,origin) DO UPDATE SET encrypted_api_key=EXCLUDED.encrypted_api_key,updated_at=now()""",
            tenant, candidate.origin, encrypted, conn=conn)
        st.execute("""INSERT INTO tenant_intelligence_selection(tenant_id,origin) VALUES($1,$2)
            ON CONFLICT(tenant_id) DO UPDATE SET origin=EXCLUDED.origin,
            version=tenant_intelligence_selection.version+1,updated_at=now()""",
            tenant, candidate.origin if activate else previous_origin, conn=conn)
        st.execute("""INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
            VALUES($1,$2,$3,$4,$5,'intelligence.key.save','intelligence',$2,$6)""",
            new_id(), tenant, actor.get("type", "user"), actor.get("id", ""), actor.get("name", ""),
            Jsonb({"origin": candidate.origin, "version": current["version"] + 1}), conn=conn)
        if activate and candidate.origin != previous_origin:
            st.execute("""INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
                VALUES($1,$2,$3,$4,$5,'intelligence.service.select','intelligence',$2,$6)""",
                new_id(), tenant, actor.get("type", "user"), actor.get("id", ""), actor.get("name", ""),
                Jsonb({"before": previous_origin, "origin": candidate.origin,
                       "version": current["version"] + 1}), conn=conn)
    return {**read(st, tenant, cfg), "verification": verified}


class TenantAsyncGuardrailClient:
    def __init__(self, st, tenant, cfg, *, clients=None):
        self.st, self.tenant, self.cfg = st, tenant, cfg
        self.clients = clients

    def available(self):
        return bool(guardrail_credential(self.st, self.tenant, self.cfg))

    def key_digest(self):
        from .guardrail.clients import credential_digest
        return credential_digest(guardrail_credential(self.st, self.tenant, self.cfg))

    async def assess(self, state, *, company_policy="", timeout=None, run_sync=None):
        from openaidr_api_client.contracts.guardrail import JevError
        from openaidr_api_client.clients.guardrail import AsyncGuardrailClient

        run_sync = run_sync or asyncio.to_thread
        try:
            deadline = time.monotonic() + timeout if timeout is not None else None
            key = await run_sync(guardrail_credential, self.st, self.tenant, self.cfg)
            if not key:
                if self.clients is not None:
                    self.clients.invalidate(self.tenant)
                raise JevError("provider_unavailable")
            remaining = max(0, deadline - time.monotonic()) if deadline is not None else None
            if self.clients is not None:
                value = await self.clients.assess(self.tenant, key, state, company_policy=company_policy, timeout=remaining)
                free_tier.succeeded(self.cfg)
                return value
            client = AsyncGuardrailClient(key)
            try:
                remaining = max(0, deadline - time.monotonic()) if deadline is not None else None
                value = await client.assess(state, company_policy=company_policy, timeout=remaining)
                free_tier.succeeded(self.cfg)
                return value
            finally:
                await client.aclose()
        except JevError as error:
            free_tier.failed(self.cfg, error)
            raise
        except Exception as error:
            free_tier.failed(self.cfg, error)
            raise JevError("provider_unavailable") from None


class TenantGuardrailClient:
    def __init__(self, st, tenant, cfg, *, clients=None):
        self.st, self.tenant, self.cfg = st, tenant, cfg
        self.clients = clients
        self.used_key_digest = ""

    def available(self):
        return bool(guardrail_credential(self.st, self.tenant, self.cfg))

    def key_digest(self):
        from .guardrail.clients import credential_digest
        return credential_digest(guardrail_credential(self.st, self.tenant, self.cfg))

    def assess(self, state, *, company_policy=""):
        from openaidr_api_client.contracts.guardrail import JevError
        from openaidr_api_client.clients.guardrail import GuardrailClient
        from .guardrail.clients import credential_digest

        try:
            key = guardrail_credential(self.st, self.tenant, self.cfg)
            if not key:
                if self.clients is not None:
                    self.clients.invalidate(self.tenant)
                raise JevError("provider_unavailable")
            self.used_key_digest = credential_digest(key)
            if self.clients is not None:
                value = self.clients.assess(self.tenant, key, state, company_policy=company_policy)
                free_tier.succeeded(self.cfg)
                return value
            client = GuardrailClient(key)
            try:
                value = client.assess(state, company_policy=company_policy)
                free_tier.succeeded(self.cfg)
                return value
            finally:
                client.close()
        except JevError as error:
            free_tier.failed(self.cfg, error)
            raise
        except Exception as error:
            free_tier.failed(self.cfg, error)
            raise JevError("provider_unavailable") from None
