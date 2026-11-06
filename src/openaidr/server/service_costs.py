"""Billing metadata for service calls without a sensor event or investigation."""

from openaidr_api_client.contracts.usage import (
    chat_usage as chat_usage,
    _search_calls as _search_calls,
    response_usage as response_usage,
    validate_response_usage as validate_response_usage,
)

import logging
from decimal import Decimal

from psycopg.types.json import Jsonb

from .model_costs import PRICE_DATE, RATES, parse_usage
from openaidr_api_client.contracts.investigation_runtime import SUPPORTED_MODELS
from .session_investigator import _quote, _rates
from .store import new_id

log = logging.getLogger(__name__)


class Call:
    def __init__(self, st, tenant, purpose, provider, model, *, web_search=False, conn=None):
        self.st, self.tenant, self.provider = st, tenant, provider
        self.web_search = web_search
        self.id, self.payload = None, None
        self.quote = _quote(model, 0) if provider == "openai" and model in SUPPORTED_MODELS | {"gpt-6-luna"} else None
        if web_search and self.quote:
            # https://developers.openai.com/api/docs/pricing, verified 2026-10-21.
            self.quote = {**self.quote, "web_search_per_call": "0.01", "web_search_price_date": "2026-10-21"}
        if st is None:
            return
        try:
            ident = new_id()
            rates = RATES.get((provider, model), (None, None))
            st.execute(
                """INSERT INTO model_usage(id,tenant_id,attempt,purpose,provider,model,
                       price_quote,input_rate_usd,output_rate_usd,price_date)
                   VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9)""",
                ident, tenant, purpose, provider, model,
                Jsonb(self.quote) if self.quote else None, *rates,
                self.quote["date"] if self.quote else PRICE_DATE, conn=conn,
            )
            self.id = ident
        except Exception:
            log.warning("API cost recording unavailable")

    @classmethod
    def from_record(cls, st, row):
        """Complete an existing attempt using its original immutable price quote."""
        call = cls.__new__(cls)
        call.st, call.tenant, call.id = st, row["tenant_id"], row["id"]
        call.provider, call.quote = row["provider"], row["price_quote"]
        call.web_search = bool(call.quote and "web_search_per_call" in call.quote)
        call.payload = None
        return call

    def finish(self, failed=False):
        if self.id is None:
            return
        try:
            if self.provider == "typesafe":
                self.st.finish_model_call(self.tenant, self.id, self.payload, failed=failed)
                return
            payload = self.payload if isinstance(self.payload, dict) else {}
            counts = parse_usage(payload)
            usage = payload.get("usage")
            details = usage.get("input_tokens_details") if isinstance(usage, dict) else None
            details = details if isinstance(details, dict) else {}
            cached, write = details.get("cached_tokens"), details.get("cache_write_tokens")
            valid = (counts["input_tokens"] is not None
                     and all(type(n) is int and 0 <= n <= counts["input_tokens"] for n in (cached, write))
                     and cached + write <= counts["input_tokens"])
            cost = None
            searches = _search_calls(payload) if self.web_search else None
            if (valid and self.quote and counts["model"] == self.quote["model"] and payload.get("service_tier") == "default"
                    and (not self.web_search or searches is not None)):
                ordinary_rate, cached_rate, write_rate, output_rate = _rates(self.quote, counts["input_tokens"])
                cost = ((counts["input_tokens"] - cached - write) * ordinary_rate
                        + cached * cached_rate + write * write_rate + counts["output_tokens"] * output_rate)
                if self.web_search:
                    cost += searches * Decimal(self.quote["web_search_per_call"])
            self.st.execute(
                """UPDATE model_usage SET completed_at=clock_timestamp(),status=$3,
                       input_tokens=$4,output_tokens=$5,cached_input_tokens=$6,
                       cache_write_input_tokens=$7,cost_usd=$8,web_search_calls=$9
                   WHERE id=$1 AND tenant_id=$2 AND completed_at IS NULL""",
                self.id, self.tenant, "error" if failed else "completed",
                counts["input_tokens"], counts["output_tokens"],
                cached if valid else None, write if valid else None, cost, searches,
            )
        except Exception:
            log.warning("API cost recording unavailable")
