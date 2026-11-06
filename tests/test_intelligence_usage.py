"""Content-free usage receipts preserve real tenant accounting."""

import json

import pytest

from openaidr_api.config import Config
from openaidr_api_client.contracts.usage import ResponseUsage
from openaidr.server.service_costs import Call, response_usage, validate_response_usage
from test_store import db as db


def provider_usage():
    return {"model": "gpt-6-luna", "service_tier": "default", "usage": {
        "input_tokens": 1000, "output_tokens": 200,
        "input_tokens_details": {"cached_tokens": 600, "cache_write_tokens": 100},
    }, "output": [
        {"type": "web_search_call", "status": "completed", "action": {
            "type": "search", "sources": [{"url": "https://private.example/evidence"}]}},
        {"type": "message", "content": [{"type": "output_text", "text": "private answer evidence"}]},
    ]}


@pytest.mark.parametrize("variant", ["complete", "unknown", "partial_tokens", "bad_cache", "bad_search"])
def test_receipts_remove_content_and_preserve_known_and_unknown_costs(db, variant):
    payload = provider_usage()
    if variant == "unknown":
        payload = None
    elif variant == "partial_tokens":
        del payload["usage"]["output_tokens"]
    elif variant == "bad_cache":
        payload["usage"]["input_tokens_details"]["cached_tokens"] = True
    elif variant == "bad_search":
        payload["output"][0]["status"] = "failed"
    receipt = response_usage(payload)
    assert validate_response_usage(receipt) == receipt
    ResponseUsage.model_validate(receipt)
    assert "private" not in json.dumps(receipt)
    tenant = db.create_tenant("Receipt test", "receipts")["id"]
    records = []
    for value in (payload, receipt):
        call = Call(db, tenant, "asset_management", "openai", "gpt-6-luna", web_search=True)
        call.payload = value
        call.finish(failed=variant != "complete")
        records.append(db.one(
            "SELECT status,input_tokens,output_tokens,cached_input_tokens,cache_write_input_tokens,"
            "web_search_calls,cost_usd FROM model_usage WHERE id=$1", call.id))
    assert records[0] == records[1]
    assert (records[0]["cost_usd"] is not None) == (variant == "complete")


@pytest.mark.parametrize("mutation", ["answer", "source", "boolean", "negative", "extra", "cache_sum"])
def test_receipt_validation_rejects_content_and_invalid_counts(mutation):
    receipt = response_usage(provider_usage())
    if mutation == "answer":
        receipt["output"].append({"type": "message", "text": "private answer"})
    elif mutation == "source":
        receipt["output"][0]["action"]["sources"] = ["https://private.example/"]
    elif mutation == "boolean":
        receipt["usage"]["input_tokens"] = True
    elif mutation == "negative":
        receipt["usage"]["output_tokens"] = -1
    elif mutation == "extra":
        receipt["provider_key"] = "must-not-be-retained"
    else:
        receipt["usage"]["input_tokens_details"]["cached_tokens"] = 1000
    with pytest.raises(ValueError, match="Invalid intelligence usage"):
        validate_response_usage(receipt)


def test_openai_credential_is_explicit_private_and_uses_one_source(monkeypatch, tmp_path):
    name = "OPENAIDR_INTELLIGENCE_OPENAI_API_KEY"
    monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv(name + "_FILE", raising=False)
    assert Config.from_env().openai_key == ""
    key = tmp_path / "openai.key"
    key.write_text("private-service-openai-key\n")
    monkeypatch.setenv(name + "_FILE", str(key))
    cfg = Config.from_env()
    assert cfg.openai_key == "private-service-openai-key"
    assert cfg.openai_key not in repr(cfg)
    monkeypatch.setenv(name, "second-private-key")
    with pytest.raises(ValueError, match="only one credential source"):
        Config.from_env()
    monkeypatch.delenv(name)
    key.unlink()
    with pytest.raises(OSError):
        Config.from_env()
