"""Real API and PostgreSQL fixture for cost browser tests. Drops its own schema."""

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import runpy
import signal
import sys
from uuid import uuid4

verify_runtime = runpy.run_path(str(Path(__file__).with_name("browser-runtime.py")))["prepare"]()

import psycopg
from psycopg.conninfo import make_conninfo
import uvicorn

from openaidr.server.app import create_app
from openaidr.server.agent_cost_usage import process_pending
from openaidr.server.agent_cost_summaries import rebuild_pending
from openaidr.server.auth import hash_password
from openaidr.server.config import Config
from openaidr.server.store import Store, new_id
from openaidr.core.hook_estimates import estimate, payload as hook_payload


def main():
    # Uvicorn re-raises its shutdown signal. Turn it into a Python exit so the
    # outer finally block can drop this fixture's schema after shutdown.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    url = os.environ["OPENAIDR_TEST_DATABASE_URL"]
    schema = "cost_browser_" + uuid4().hex
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
    st = Store(make_conninfo(url, options=f"-c search_path={schema}"))
    try:
        st.migrate()
        tenant = st.bootstrap_tenant("Cost test tenant", "cost-test")
        sensor, _, _ = st.enroll_sensor(
            {
                "enrollment_token": tenant["enrollment_token"],
                "hostname": "cost-test-device",
            }
        )
        st.create_tenant_owner(
            sensor["tenant_id"],
            "costs@example.invalid",
            "Test operator",
            hash_password("cost-test-password"),
        )
        now = datetime.now(timezone.utc)
        hook_items = []
        for product, model, kind in (("github-copilot", "", "prompt"), ("cursor", "auto", "response"),
                                     ("cursor", "jev-test", "response")):
            hook_items.append(estimate(dict(id=new_id(), time=now.isoformat(), kind=kind,
                agent=dict(product=product, model=model), source={"collector": "hook"}, text="x" * 400),
                {"github-copilot": "claude-sonnet-4-6"}))
        st.ingest_telemetry(sensor, "logs", new_id(), hook_payload(hook_items), len(hook_items))
        for index in range(52):
            when = now - timedelta(
                hours=index / 2 + 0.25 if index < 48 else [120, 240, 1440, 2400][index - 48]
            )
            model = ["gpt-6-astra", "claude-sonnet-5", "gpt-6-luna", "custom-model"][
                index % 4
            ]
            codex = model != "claude-sonnet-5"
            service = "codex-cli" if codex else "claude-code"
            attrs = {
                "model": model,
                "session.id": f"session-{index}",
                "prompt.id": f"prompt-{index}",
                "os.user": ["Alice", "Bob", "Charlie", "Dana"][index % 4],
                "project.name": "Archive" if index == 50 else ["Console", "Sensor", "Gateway"][index % 3],
                "activity": [
                    "coding",
                    "delegation",
                    "testing",
                    "exploration",
                    "git",
                    "build/deploy",
                ][index % 6],
            }
            effort = ["low", "high", "xhigh", None, "auto", "none", "minimal", "medium", "max", "ultra"][index % 10]
            if effort is not None:
                attrs["reasoning_effort"] = effort
            if codex:
                attrs.update(
                    {
                        "event.kind": "response.completed",
                        "input_token_count": 120000,
                        "cached_token_count": 40000,
                        "output_token_count": 12000 + index * 1000,
                    }
                )
            else:
                attrs.update(
                    {
                        "cost_usd": str((index + 1) / 10),
                        "input_tokens": 120000,
                        "output_tokens": 12000,
                    }
                )
            item = {
                "timeUnixNano": str(int(when.timestamp() * 1e9)),
                "eventName": "codex.sse_event" if codex else "claude_code.api_request",
                "attributes": [
                    {"key": k, "value": {"stringValue": str(v)}}
                    for k, v in attrs.items()
                ],
            }
            payload = {
                "resourceLogs": [
                    {
                        "resource": {
                            "attributes": [
                                {
                                    "key": "service.name",
                                    "value": {"stringValue": service},
                                }
                            ]
                        },
                        "scopeLogs": [{"logRecords": [item]}],
                    }
                ]
            }
            st.ingest_telemetry(sensor, "logs", new_id(), payload, 1)
        providers = st.bootstrap_tenant("Provider cost team", "cost-providers")
        device, _, _ = st.enroll_sensor({"enrollment_token": providers["enrollment_token"], "hostname": "cost-providers"})
        st.create_tenant_owner(device["tenant_id"], "providers@example.invalid", "Provider operator", hash_password("cost-test-password"))
        records = [{
            "eventName": "claude_code.api_request",
            "timeUnixNano": str(int((now - timedelta(hours=2)).timestamp() * 1e9)),
            "attributes": [{"key": key, "value": {"stringValue": value}} for key, value in {
                "model": model, "cost_usd": str(100 / (index + 1)),
                "os.user": "Alice", "project.name": ["Console", "Sensor", "Gateway"][index % 3],
                "activity": ["coding", "testing", "exploration", "delegation", "git", "build/deploy"][index],
                "reasoning_effort": ["xhigh", "max", "low", "medium", "high", "auto"][index],
            }.items()],
        } for index, model in enumerate([
            "gpt-6-astra", "claude-opus-5-5", "gemini-3-pro", "openai/o3", "custom-model", "JeV-1.13.0",
        ])]
        st.ingest_telemetry(device, "logs", new_id(), {
            "resourceLogs": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "claude-code"}}]},
                              "scopeLogs": [{"logRecords": records}]}],
        }, len(records))
        scale = st.bootstrap_tenant("Large cost team", "cost-scale")
        device, _, _ = st.enroll_sensor({"enrollment_token":scale["enrollment_token"],"hostname":"cost-scale"})
        st.create_tenant_owner(device["tenant_id"], "scale@example.invalid", "Scale operator", hash_password("cost-test-password"))
        records = [{
            "eventName":"claude_code.api_request",
            "timeUnixNano":str(int((now-timedelta(hours=2)).timestamp()*1e9)),
            "attributes":[{"key":key,"value":{"stringValue":value}} for key,value in {
                "cost_usd":str(index+1),"os.user":"jev-operator" if index == 129 else f"Person {index:03}",
                "model": {129: "JeV-1.13.0", 128: "Guardrail-1.13.0"}.get(index, f"model-{index:03}"),
                "project.name":"/workspace/jev" if index == 129 else f"Project {index:03}","activity":"coding",
            }.items()],
        } for index in range(130)]
        st.ingest_telemetry(device, "logs", new_id(), {
            "resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"claude-code"}}]},
                             "scopeLogs":[{"logRecords":records}]}],
        }, len(records))
        while process_pending(st)["exports"]:
            pass
        while rebuild_pending(st):
            pass
        cfg = Config(
            database_url=st.url,
            public_url=os.environ.get("OPENAIDR_DEMO_URL", "https://127.0.0.1:8443"),
        )
        cfg.set_services("ingest,api")
        uvicorn.run(
            create_app(cfg, st, customer=True),
            host="127.0.0.1",
            port=int(os.environ.get("OPENAIDR_COST_TEST_API_PORT", "8769")),
            log_level="warning",
        )
    finally:
        st.close()
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute(f"DROP SCHEMA {schema} CASCADE")


if __name__ == "__main__":
    try:
        main()
    finally:
        verify_runtime()
