"""Advisory event risk assessment using Jev, independent of ingestion and policy."""

from openaidr_api_client.contracts.guardrail import (
    MODEL as MODEL,
    KINDS as KINDS,
    MAX_RESPONSE_BYTES as MAX_RESPONSE_BYTES,
    REQUEST_TIMEOUT as REQUEST_TIMEOUT,
    RUBRIC_VERSION as RUBRIC_VERSION,
    JevError as JevError,
)

import logging
import time

from openaidr.core.redact import redact_value as redact_value

from .storage import risk_store as risk_store, DB_STATEMENT_TIMEOUT_MS as DB_STATEMENT_TIMEOUT_MS, DB_LOCK_TIMEOUT_MS as DB_LOCK_TIMEOUT_MS

from .evidence import (
    MAX_EVENT_BYTES as MAX_EVENT_BYTES, MAX_STATE_BYTES as MAX_STATE_BYTES,
    event_evidence as event_evidence, assessment_state as assessment_state,
)
from .findings import (
    DETECTION_RULE_ID as DETECTION_RULE_ID, ACTIVITY_LABELS as ACTIVITY_LABELS,
    DETECTION_LEVELS as DETECTION_LEVELS, CATEGORY_LABELS as CATEGORY_LABELS,
    detection_finding as detection_finding,
)

log = logging.getLogger("openaidr.server.risk")


class RiskWorker:
    def __init__(self, store, client, tenant_id="", client_for_tenant=None, require_tenant_key=False):
        self.store, self.client, self.tenant_id = store, client, tenant_id
        self.client_for_tenant = client_for_tenant
        self.require_tenant_key = require_tenant_key
        self.blocked_keys = {}
        self.retry_at = 0
        self.suspended = False

    def tick(self):
        if (self.suspended and self.client_for_tenant is None) or time.monotonic() < self.retry_at:
            return False
        if self.client_for_tenant:
            for tenant, digest in list(self.blocked_keys.items()):
                if self.client_for_tenant(tenant).key_digest() != digest:
                    del self.blocked_keys[tenant]
            if self.tenant_id:
                client = self.client_for_tenant(self.tenant_id)
                digest = client.key_digest()
                if not digest or self.blocked_keys.get(self.tenant_id) == digest:
                    return False
            row = self.store.claim_risk_event(
                self.tenant_id or None,
                require_tenant_key=self.require_tenant_key,
                excluded_tenants=self.blocked_keys,
            )
        else:
            row = self.store.claim_risk_event(self.tenant_id or None)
        if row is None:
            return False
        provider_delay = 0
        call_id, usage = None, None
        client = None
        knowledge = None
        policy = None
        try:
            context, prompt = self.store.risk_context(row)
            knowledge = self.store.risk_knowledge(row)
            from ..knowledge_retrieval import augment_state
            from ..company_policy import read as read_policy

            state = assessment_state(row, context, prompt)
            state, knowledge = augment_state(state, knowledge)
            policy = read_policy(self.store, row["tenant_id"])
            call_id = self.store.start_model_call(row, MODEL)
            if call_id is None:
                return True
            client = (self.client_for_tenant(row["tenant_id"])
                      if self.client_for_tenant else self.client)
            result = client.assess(state, company_policy=policy["prompt"])
            usage = result.pop("usage", None)
            retry = False
        except JevError as exc:
            usage = exc.usage
            result, retry = {"status": "error", "reason": exc.code}, exc.retryable
            if exc.code == "authentication_failed":
                if self.client_for_tenant and client is not None:
                    self.blocked_keys[row["tenant_id"]] = client.used_key_digest
                else:
                    self.suspended = True
                retry = exc.retry_after
            elif retry:
                # The database shares the provider pause with restarted and replica
                # workers; this local deadline avoids polling it during the pause.
                provider_delay = exc.retry_after
                self.retry_at = time.monotonic() + provider_delay
                retry = max(provider_delay, 30 * row["risk_retry_attempts"])
        except Exception:
            # Never log exception text or provider bodies: they may contain evidence.
            log.warning("Risk assessment failed for event %s", row["id"])
            result, retry = {"status": "error", "reason": "assessment_failed"}, True
        if call_id is not None:
            self.store.finish_model_call(
                row["tenant_id"], call_id, usage, failed=result["status"] == "error",
            )
        if knowledge is not None:
            result["knowledge"] = knowledge
        if policy is not None and policy["revision"]:
            result["company_policy"] = {key: policy[key] for key in ("revision", "prompt")}
        self.store.finish_risk_event(row, result, retry, provider_delay=provider_delay)
        return True
