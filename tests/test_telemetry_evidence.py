"""Exceptional canonical OTLP exports stay durable and cannot block later exports."""

from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient
import pytest

from openaidr.core.event import new_id
from openaidr.core.telemetry import decode_export, encode_export
from openaidr.sensor.telemetry import partial_rejection
from openaidr.server import ingest_evidence
from openaidr.server.app import create_app
from test_telemetry_server import backend as backend, export


def send(client, token, batch, signal, value, media="application/json"):
    return client.post(
        "/otlp/v1/" + signal, content=encode_export(signal, value, media),
        headers={"Authorization": "Bearer " + token, "Content-Type": media,
                 "X-OpenAIDR-Batch-Id": batch},
    )


@pytest.mark.parametrize("signal", ["logs", "metrics", "traces"])
@pytest.mark.parametrize("media", ["application/json", "application/x-protobuf"])
def test_unsupported_exports_are_retained_before_success_and_deduplicated(backend, signal, media):
    st, cfg, sensor, token, *_ = backend
    value = export(signal, service="claude\x00code 😀")
    resource = next(iter(value.values()))[0]["resource"]
    resource["attributes"].append({"key": "nested\x00key", "value": {"arrayValue": {
        "values": [{"stringValue": "value\x00with nul"}, {"bytesValue": "AP8="}],
    }}})
    original = decode_export(signal, encode_export(signal, value, media), media)
    batch = new_id()
    with TestClient(create_app(cfg, st)) as client:
        result = send(client, token, batch, signal, value, media)
        assert result.status_code == 200, result.text
        assert result.headers["x-openaidr-duplicate"] == "false"
        # The sensor may remove its queued export only after this durable success.
        assert not partial_rejection(signal, result)
        retained = st.one("SELECT * FROM retained_ingest_evidence")
        assert retained["tenant_id"] == sensor["tenant_id"] and retained["sensor_id"] == sensor["id"]
        assert retained["source"] == "otlp-" + signal and retained["record_key"] == batch
        assert retained["status"] == "unavailable"
        assert retained["payload"] == ingest_evidence.encode(original)
        assert st.scalar("SELECT count(*) FROM telemetry_exports") == 0
        assert st.scalar("SELECT count(*) FROM telemetry_export_keys") == 0
        alternate = "application/x-protobuf" if media == "application/json" else "application/json"
        retry = send(client, token, batch, signal, value, alternate)
        assert retry.status_code == 200 and retry.headers["x-openaidr-duplicate"] == "true"
        assert st.scalar("SELECT count(*) FROM retained_ingest_evidence") == 1
        good = export(signal)
        assert send(client, token, batch, signal, good).status_code == 409
        normal_batch = new_id()
        assert send(client, token, normal_batch, signal, good).status_code == 200
        assert send(client, token, normal_batch, signal, value).status_code == 409
        assert st.scalar("SELECT count(*) FROM telemetry_exports") == 1
        assert st.scalar("SELECT count(*) FROM retained_ingest_evidence") == 1
        # No fallback write may bypass authentication or disabled state.
        assert send(client, "invalid", new_id(), signal, value).status_code == 401
        st.execute("UPDATE sensors SET disabled=true WHERE id=$1", sensor["id"])
        assert send(client, token, new_id(), signal, value).status_code == 403
        assert st.scalar("SELECT count(*) FROM retained_ingest_evidence") == 1


def test_concurrent_retained_export_retries_share_the_authenticated_batch_identity(backend):
    st, _, sensor, _, other, *_ = backend
    value = export("logs", service="claude\x00code")
    batch = new_id()
    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(lambda _: st.ingest_telemetry(sensor, "logs", batch, value, 1), range(8)))
    assert sum(results) == 1
    assert st.ingest_telemetry(other, "logs", batch, value, 1)
    assert st.scalar("SELECT count(*) FROM retained_ingest_evidence") == 2


@pytest.mark.parametrize("target,sqlstate", [("telemetry_exports", "22003"),
                                            ("telemetry_exports", "54000"),
                                            ("telemetry_exports", "55P03"),
                                            ("retained_ingest_evidence", "55P03")])
def test_database_failures_preserve_the_telemetry_acknowledgment_contract(backend, target, sqlstate):
    st, cfg, sensor, token, *_ = backend
    st.execute("""CREATE FUNCTION reject_test_export() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        RAISE EXCEPTION 'test export storage failure' USING ERRCODE='""" + sqlstate + """'; END $$;
        CREATE TRIGGER reject_test_export BEFORE INSERT ON """ + target + """
        FOR EACH ROW EXECUTE FUNCTION reject_test_export()""")
    value = export("logs", service="claude 😀" + ("\x00" if target == "retained_ingest_evidence" else ""))
    batch = new_id()
    with TestClient(create_app(cfg, st)) as client:
        result = send(client, token, batch, "logs", value)
        assert st.scalar("SELECT count(*) FROM telemetry_exports") == 0
        assert st.scalar("SELECT count(*) FROM telemetry_export_keys") == 0
        assert st.scalar("SELECT count(*) FROM events") == 0
        if sqlstate == "55P03":
            assert result.status_code == 503, result.text
            assert st.scalar("SELECT count(*) FROM retained_ingest_evidence") == 0
        else:
            assert result.status_code == 200, result.text
            retained = st.one("SELECT * FROM retained_ingest_evidence")
            original = decode_export("logs", encode_export("logs", value), "application/json")
            assert retained["payload"] == ingest_evidence.encode(original)
        st.execute("DROP TRIGGER reject_test_export ON " + target)
        retry = send(client, token, batch, "logs", value)
        assert retry.status_code == 200, retry.text
        assert retry.headers["x-openaidr-duplicate"] == ("false" if sqlstate == "55P03" else "true")
        assert st.scalar("SELECT count(*) FROM telemetry_exports") == int(sqlstate == "55P03" and target == "telemetry_exports")
