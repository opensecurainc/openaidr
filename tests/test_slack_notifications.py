"""Slack authorization and delivery against PostgreSQL; only Slack transport is mocked."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from threading import Event

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
import pytest

from openaidr.server import slack_notifications as slack
from openaidr.server.app import create_app
from openaidr.server.config import Config, from_env
from openaidr.server.httpx import APIError
from openaidr.server.store import new_id
from test_hook_policy import system as system, browser
from test_store import db as db, tenant
from test_host_metrics import sample, capacity
from test_session_investigator import (
    system as investigation_system, attempt, prepared, finish_steps, investigator, finding_result,
)

WEBHOOK = "https://hooks.slack.com/services/TTEST/BTEST/SYNTHETIC_SECRET"


def config(tenant_id=""):
    return Config(slack_webhook_key=Fernet.generate_key().decode(), tenant_id=tenant_id,
                  public_url="https://console.example.test")


def connect(st, tid, cfg, **changes):
    current = slack.read(st, tid, cfg)
    return slack.save(st, tid, {"enabled": True, "version": current["version"],
                              "webhook_url": WEBHOOK, **changes}, {}, cfg)


def finding(st, tid, severity="high", conn=None):
    ident = new_id()
    st.execute("""INSERT INTO findings(id,tenant_id,rule_id,category,severity,title,summary,
        sensor_id,primary_event_id,first_event_at)
        VALUES($1,$2,'test','secret_exfiltration',$3,'PRIVATE_PROMPT','PRIVATE_COMMAND',$4,$5,clock_timestamp())""",
        ident, tid, severity, new_id(), new_id(), conn=conn)
    return ident


def due(st):
    st.execute("UPDATE tenant_slack_settings SET next_delivery_at=clock_timestamp()")
    st.execute("UPDATE slack_outbox SET next_attempt_at=clock_timestamp()")


def test_settings_authorization_csrf_secrets_versions_and_disconnect(system):
    cfg = system.client.app.state.service.cfg
    cfg.slack_webhook_key = Fernet.generate_key().decode()
    path = "settings/slack"
    data = {"enabled": True, "version": 0, "webhook_url": WEBHOOK}
    current = browser(system, "GET", path)
    assert current.status_code == 200 and current.headers["cache-control"] == "no-store"
    assert not current.json()["configured"] and not current.json()["enabled"]
    for method, route, payload in [("GET", path, None), ("PUT", path, data), ("POST", path + "/test", {"version": 0})]:
        assert browser(system, method, route, payload, user="viewer").status_code == 403
    assert system.client.put("/api/v1/" + path, json=data, headers={"X-OpenAIDR-CSRF": "1"}).status_code == 401
    headers = {k: v for k, v in system.headers["admin"].items() if k.lower() != "x-openaidr-csrf"}
    assert system.client.put("/api/v1/" + path, json=data, headers=headers).status_code == 403
    for bad in (WEBHOOK + "?secret=x", WEBHOOK + "\n", "https://hooks.slack.com.evil.test/services/T/B/S",
                "http://hooks.slack.com/services/T/B/S", "https://127.0.0.1/services/T/B/S", [], None):
        result = browser(system, "PUT", path, {**data, "webhook_url": bad})
        assert result.status_code == 400 and "SYNTHETIC_SECRET" not in result.text
    result = browser(system, "PUT", path, data)
    assert result.status_code == 200 and result.json()["version"] == 1
    assert WEBHOOK not in result.text and "encrypted_webhook" not in result.text
    assert browser(system, "PUT", path, data).status_code == 409
    assert browser(system, "GET", path, user="foreign").json()["version"] == 0
    ciphertext = system.db.scalar("SELECT encrypted_webhook FROM tenant_slack_settings")
    assert WEBHOOK not in ciphertext and cfg.slack_webhook_key not in repr(cfg)
    assert json.loads(Fernet(cfg.slack_webhook_key.encode()).decrypt(ciphertext.encode())) == [system.tenant["id"], WEBHOOK]
    audit = system.db.one("SELECT details FROM audit_log WHERE action='slack.configure'")["details"]
    assert "SYNTHETIC_SECRET" not in json.dumps(audit)
    queued = browser(system, "POST", path + "/test", {"version": 1})
    assert queued.status_code == 202 and queued.json() == {"queued": True}
    message = system.db.scalar("SELECT message FROM slack_outbox")
    assert message["text"].endswith("/administration/integrations")
    assert browser(system, "POST", path + "/test", {"version": 1}).status_code == 429
    result = browser(system, "PUT", path, {"version": 1, "enabled": False, "webhook_url": ""})
    assert result.status_code == 200 and not result.json()["configured"]
    assert system.db.scalar("SELECT status FROM slack_outbox") == "cancelled"
    assert browser(system, "POST", path + "/test", {"version": 2}).status_code == 409


def notification(st, tid):
    with st.transaction() as conn:
        slack._enqueue(st, tid, "incident:" + new_id(), {"text": "Test"}, conn)


def test_policy_findings_never_notify(db, monkeypatch):
    tid, other = tenant(db)["id"], tenant(db)["id"]
    cfg = config(tid)
    connect(db, tid, cfg)
    connect(db, other, cfg)
    for severity in ("critical", "high", "medium", "low"):
        finding(db, tid, severity)
        finding(db, other, severity)
    slack.collect(db, cfg)
    slack.collect(db, cfg)
    calls = []
    monkeypatch.setattr(slack, "send", lambda url, message: calls.append(message))
    assert not slack.dispatch_one(db, cfg)
    assert db.scalar("SELECT count(*) FROM slack_outbox") == 0
    assert calls == []


def test_upgrade_cancels_legacy_alerts_including_retries(db, monkeypatch):
    db.execute("ALTER TABLE tenant_slack_settings DROP COLUMN disk_alerts")
    db.execute("DELETE FROM schema_migrations WHERE version=94")
    tid = tenant(db)["id"]
    cfg = config(tid)
    db.execute("""INSERT INTO tenant_slack_settings(tenant_id,enabled,encrypted_webhook)
        VALUES($1,true,'old credential')""", tid)
    with db.transaction() as conn:
        for prefix in ("finding", "report", "digest", "batch"):
            for attempts in (0, 1):
                key = prefix + ":" + new_id()
                slack._enqueue(db, tid, key, {"text": "Legacy alert"}, conn)
                db.execute("UPDATE slack_outbox SET attempts=$2 WHERE event_key=$1", key, attempts, conn=conn)
    assert db.migrate() == ["0094_slack_incident_alerts.sql"]
    assert db.scalar("SELECT count(*) FROM slack_outbox WHERE status='cancelled'") == 8
    # A legacy worker can enqueue after migration. Dispatch must still stay silent.
    with db.transaction() as conn:
        slack._enqueue(db, tid, "finding:" + new_id(), {"text": "Late legacy alert"}, conn)
    calls = []
    monkeypatch.setattr(slack, "send", lambda url, message: calls.append(message))
    assert not slack.dispatch_one(db, cfg)
    slack.collect(db, cfg)
    assert db.scalar("SELECT count(*) FROM slack_outbox WHERE status='pending'") == 0
    assert calls == []


def disk_metrics(path, percent=60, root=60, same=False, age=0, available=None):
    row = {**sample(datetime.now(timezone.utc) - timedelta(seconds=age)), **capacity(),
           "disk_percent": percent, "disk_used_bytes": percent * 10,
           "disk_available_bytes": (100 - percent) * 10 if available is None else available,
           "disk_is_root": same, "root_disk_percent": root, "root_disk_used_bytes": root * 10,
           "root_disk_total_bytes": 1000, "root_disk_available_bytes": (100 - root) * 10}
    path.write_text(json.dumps({"version": 1, "interval_seconds": 60, "hostname": "PRIVATE_HOST",
                               "disk_path": "/srv/private", "samples": [row]}))


def test_disk_alert_episodes_persist_recover_and_deduplicate(db, monkeypatch, tmp_path):
    tid = tenant(db)["id"]
    cfg = config(tid)
    path = tmp_path / "metrics.json"
    cfg.host_metrics_path = str(path)
    connect(db, tid, cfg)
    calls = []
    monkeypatch.setattr(slack, "send", lambda url, message: calls.append(message))
    disk_metrics(path, 94)
    slack.collect(db, cfg)
    assert not slack.dispatch_one(db, cfg)
    disk_metrics(path, 95)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: slack.collect(db, cfg), range(2)))
    assert slack.dispatch_one(db, cfg)
    assert "Data disk: 95% full" in calls[0]["text"]
    assert calls[0]["text"].endswith("/administration/server")
    # A new worker/configuration object uses the persisted episode state.
    restarted = config(tid)
    restarted.slack_webhook_key, restarted.host_metrics_path = cfg.slack_webhook_key, str(path)
    for percent in (100, 91, 95):
        disk_metrics(path, percent)
        slack.collect(db, restarted)
        due(db)
        assert not slack.dispatch_one(db, restarted)
    disk_metrics(path, 89)
    slack.collect(db, cfg)
    assert db.scalar("SELECT disk_alerts FROM tenant_slack_settings") == {}
    disk_metrics(path, 95, root=96)
    slack.collect(db, cfg)
    assert slack.read(db, tid, cfg)["delivery"]["pending"] == 2
    # Recovery cancels an unsent warning and does not send a recovery message.
    disk_metrics(path, 89, root=96)
    slack.collect(db, cfg)
    due(db)
    assert slack.dispatch_one(db, cfg)
    assert "Boot disk: 96% full" in calls[1]["text"]
    assert len(calls) == 2
    assert "PRIVATE_HOST" not in json.dumps(calls) and "/srv/private" not in json.dumps(calls)
    assert slack.read(db, tid, cfg)["delivery"]["pending"] == 0


def test_disk_metrics_require_fresh_tenant_bound_data_and_do_not_repeat_root(db, monkeypatch, tmp_path):
    tid = tenant(db)["id"]
    cfg = config(tid)
    path = tmp_path / "metrics.json"
    cfg.host_metrics_path = str(path)
    connect(db, tid, cfg)
    for raw in (None, "invalid", "stale", "future"):
        if raw == "invalid":
            path.write_text("invalid")
        elif raw in ("stale", "future"):
            disk_metrics(path, 100, age=300 if raw == "stale" else -120)
        slack.collect(db, cfg)
        assert db.scalar("SELECT count(*) FROM slack_outbox") == 0
    disk_metrics(path, 90, root=90, same=True, available=10)
    cfg.tenant_id = ""
    slack.collect(db, cfg)
    assert db.scalar("SELECT count(*) FROM slack_outbox") == 0
    cfg.tenant_id = tid
    slack.collect(db, cfg)
    row = db.one("SELECT message FROM slack_outbox")
    assert "Server disk: 99% full" in row["message"]["text"]
    # Missing or stale samples must not rearm an active warning.
    disk_metrics(path, 60, age=300)
    slack.collect(db, cfg)
    disk_metrics(path, 100, same=True)
    slack.collect(db, cfg)
    assert db.scalar("SELECT count(*) FROM slack_outbox") == 1
    # Replacing a destination warns it once about an ongoing disk shortage.
    connect(db, tid, cfg, webhook_url=WEBHOOK + "REPLACED")
    slack.collect(db, cfg)
    calls = []
    monkeypatch.setattr(slack, "send", lambda url, message: calls.append(url))
    assert slack.dispatch_one(db, cfg)
    assert calls == [WEBHOOK + "REPLACED"]
    assert {r["status"] for r in db.many("SELECT status FROM slack_outbox")} == {"sent", "cancelled"}
    other = tenant(db)["id"]
    connect(db, other, cfg)
    connect(db, tid, cfg)
    slack.collect(db, cfg)
    assert db.scalar("SELECT count(*) FROM slack_outbox") == 2
    assert db.scalar("SELECT disk_alerts FROM tenant_slack_settings WHERE tenant_id=$1", tid) == {}


@pytest.mark.parametrize("outcome", ["complete", "inconclusive"])
def test_reports_from_real_investigation_publication(investigation_system, outcome):
    system = investigation_system
    cfg = config(system.tenant["id"])
    connect(system.db, system.tenant["id"], cfg)
    value = attempt(system)
    slack.collect(system.db, cfg)
    assert system.db.scalar("SELECT count(*) FROM slack_outbox WHERE event_key LIKE 'report:%'") == 0
    if outcome == "complete":
        prepared(system, value)
        finish_steps(system, value)
        investigator.publish_report(system.db, value.claim)
    else:
        investigator.stop_attempt(system.db, value.claim, "runtime_unavailable", retryable=False)
    slack.collect(system.db, cfg)
    slack.collect(system.db, cfg)
    assert system.db.scalar("SELECT count(*) FROM slack_outbox") == 0
    assert not slack.dispatch_one(system.db, cfg)


def publish_incident(system, severity="high"):
    value = attempt(system)
    prepared(system, value)
    anchor = system.db.one("""SELECT ordinal,kind,source_id,body FROM session_snapshot_items
        WHERE snapshot_id=$1 AND kind='observation' AND source_id=$2""",
        value.claim["snapshot_id"], value.value["target"]["id"])
    output = finding_result(value, anchor)
    output["findings"] = [deepcopy(output["findings"][0]) for _ in range(3)]
    for entry in output["findings"]:
        entry["severity"] = severity
    finish_steps(system, value, lambda step: output)
    investigator.publish_report(system.db, value.claim)
    return value


@pytest.mark.parametrize("severity", ["low", "medium", "high", "critical"])
def test_investigation_findings_and_report_share_one_delivery(investigation_system, monkeypatch, severity):
    system = investigation_system
    cfg = config(system.tenant["id"])
    connect(system.db, system.tenant["id"], cfg)
    value = publish_incident(system, severity)
    slack.collect(system.db, cfg)
    slack.collect(system.db, cfg)
    assert slack.read(system.db, system.tenant["id"], cfg)["delivery"]["pending"] == 1
    assert system.db.scalar("SELECT count(*) FROM slack_outbox") == 1
    calls = []
    monkeypatch.setattr(slack, "send", lambda url, message: calls.append(message))
    assert slack.dispatch_one(system.db, cfg)
    assert len(calls) == 1
    assert "Incident detected\n3 findings." in calls[0]["text"]
    assert "/detections/reports/" + value.claim["job_id"] in calls[0]["text"]
    assert "review-secret" not in json.dumps(calls)
    slack.collect(system.db, cfg)
    due(system.db)
    assert not slack.dispatch_one(system.db, cfg)


@pytest.mark.parametrize("batched,attempts", [(False, 0), (False, 1), (True, 0), (True, 1)])
def test_upgrade_converts_only_unattempted_incident_reports(investigation_system, monkeypatch, batched, attempts):
    system = investigation_system
    db, tid = system.db, system.tenant["id"]
    cfg = config(tid)
    connect(db, tid, cfg)
    value = publish_incident(system)
    with db.transaction() as conn:
        key = "report:" + value.claim["job_id"]
        slack._enqueue(db, tid, key, {"text": "Legacy report"}, conn)
        if batched:
            parent_key = "digest:" + new_id()
            slack._enqueue(db, tid, parent_key, {"text": "Legacy digest"}, conn)
            db.execute("""UPDATE slack_outbox SET status='grouped',
                batch_id=(SELECT id FROM slack_outbox WHERE event_key=$2) WHERE event_key=$1""",
                key, parent_key, conn=conn)
            key = parent_key
        db.execute("UPDATE slack_outbox SET attempts=$2 WHERE event_key=$1", key, attempts, conn=conn)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: slack.collect(db, cfg), range(2)))
    calls = []
    monkeypatch.setattr(slack, "send", lambda url, message: calls.append(message))
    assert slack.dispatch_one(db, cfg) is (attempts == 0)
    assert len(calls) == (1 if attempts == 0 else 0)
    if calls:
        assert "Incident detected" in calls[0]["text"]
    slack.collect(db, cfg)
    due(db)
    assert not slack.dispatch_one(db, cfg)


def test_incident_collection_respects_tenant_and_new_activity(investigation_system):
    system = investigation_system
    db, tid = system.db, system.tenant["id"]
    publish_incident(system)
    cfg = config(tid)
    connect(db, tid, cfg)
    slack.collect(db, cfg)
    assert db.scalar("SELECT count(*) FROM slack_outbox") == 0
    publish_incident(system)
    other = tenant(db)["id"]
    connect(db, other, cfg)
    cfg.tenant_id = other
    slack.collect(db, cfg)
    assert db.scalar("SELECT count(*) FROM slack_outbox") == 0
    cfg.tenant_id = tid
    slack.collect(db, cfg)
    assert db.scalar("SELECT count(*) FROM slack_outbox WHERE tenant_id=$1", tid) == 1
    connect(db, tid, cfg, enabled=False)
    publish_incident(system)
    connect(db, tid, cfg)
    slack.collect(db, cfg)
    assert db.scalar("SELECT count(*) FROM slack_outbox") == 1
    assert db.scalar("SELECT status FROM slack_outbox") == "cancelled"


def test_retry_backoff_exhaustion_and_secret_binding(db, monkeypatch):
    tid, other = tenant(db)["id"], tenant(db)["id"]
    cfg = config()
    connect(db, tid, cfg)
    connect(db, other, cfg)
    notification(db, tid)
    slack.collect(db, cfg)
    calls = []

    def throttled(url, message):
        calls.append(url)
        raise slack.DeliveryError("rate_limited", retry_after=7200)

    monkeypatch.setattr(slack, "send", throttled)
    assert slack.dispatch_one(db, cfg)
    row = db.one("SELECT status,attempts,error_code,next_attempt_at>clock_timestamp()+interval '7190 seconds' AS delayed FROM slack_outbox")
    assert row == {"status": "pending", "attempts": 1, "error_code": "rate_limited", "delayed": True}
    assert not slack.dispatch_one(db, cfg)
    assert calls == [WEBHOOK]
    due(db)
    monkeypatch.setattr(slack, "send", lambda url, message: calls.append(url))
    assert slack.dispatch_one(db, cfg)
    assert db.scalar("SELECT status FROM slack_outbox") == "sent"
    assert slack.read(db, tid, cfg)["delivery"]["last_sent_at"] is not None
    notification(db, tid)
    slack.collect(db, cfg)
    monkeypatch.setattr(slack, "send", throttled)
    for _ in range(8):
        due(db)
        assert slack.dispatch_one(db, cfg)
    assert db.scalar("SELECT attempts FROM slack_outbox WHERE status='failed'") == 8
    assert slack.read(db, tid, cfg)["delivery"]["failed"] == 1
    notification(db, other)
    slack.collect(db, cfg)
    # Copying another tenant's encrypted URL cannot redirect this tenant's notifications.
    db.execute("UPDATE tenant_slack_settings SET encrypted_webhook=(SELECT encrypted_webhook FROM tenant_slack_settings WHERE tenant_id=$1) WHERE tenant_id=$2", tid, other)
    before = len(calls)
    due(db)
    assert slack.dispatch_one(db, cfg)
    assert len(calls) == before
    assert db.scalar("SELECT error_code FROM slack_outbox WHERE tenant_id=$1", other) == "credentials_unavailable"


def test_concurrent_workers_and_disabling_in_flight(db, monkeypatch):
    tid = tenant(db)["id"]
    cfg = config(tid)
    connect(db, tid, cfg)
    notification(db, tid)
    notification(db, tid)
    slack.collect(db, cfg)
    sending, release, disabling = Event(), Event(), Event()
    calls = []

    def send(url, message):
        calls.append(message)
        sending.set()
        assert release.wait(10)

    def disable():
        disabling.set()
        return slack.save(db, tid, {"enabled": False, "version": 1}, {}, cfg)

    monkeypatch.setattr(slack, "send", send)
    with ThreadPoolExecutor(max_workers=3) as pool:
        first = pool.submit(slack.dispatch_one, db, cfg)
        assert sending.wait(10)
        try:
            assert pool.submit(slack.dispatch_one, db, cfg).result(5) is False
            stopped = pool.submit(disable)
            assert disabling.wait(5)
        finally:
            release.set()
        assert first.result(5) is True
        assert stopped.result(5)["enabled"] is False
    assert len(calls) == 1 and not slack.dispatch_one(db, cfg)
    assert {row["status"] for row in db.many("SELECT status FROM slack_outbox")} == {"sent", "cancelled"}


@pytest.mark.parametrize("change", ["replace", "reconnect", "reenable"])
def test_destination_changes_clear_bounded_retry_delay(db, monkeypatch, change):
    tid = tenant(db)["id"]
    cfg = config(tid)
    connect(db, tid, cfg)
    notification(db, tid)
    slack.collect(db, cfg)

    def throttled(url, message):
        raise slack.DeliveryError("rate_limited", retry_after=99999999)

    monkeypatch.setattr(slack, "send", throttled)
    assert slack.dispatch_one(db, cfg)
    assert db.scalar("""SELECT next_delivery_at BETWEEN clock_timestamp()+interval '23 hours'
        AND clock_timestamp()+interval '24 hours' FROM tenant_slack_settings""")
    assert db.scalar("""SELECT next_attempt_at BETWEEN clock_timestamp()+interval '23 hours'
        AND clock_timestamp()+interval '24 hours' FROM slack_outbox""")
    assert not slack.dispatch_one(db, cfg)
    if change == "replace":
        settings = connect(db, tid, cfg, webhook_url=WEBHOOK + "REPLACED")
    else:
        disabled = {"enabled": False, "version": 1}
        if change == "reconnect":
            disabled["webhook_url"] = ""
        slack.save(db, tid, disabled, {}, cfg)
        settings = (connect(db, tid, cfg) if change == "reconnect" else
                    slack.save(db, tid, {"enabled": True, "version": 2}, {}, cfg))
    slack.queue_test(db, tid, {"version": settings["version"]}, {}, cfg)
    calls = []
    monkeypatch.setattr(slack, "send", lambda url, message: calls.append(url))
    # Recovery must not require changing database timestamps or waiting for the old delay.
    assert slack.dispatch_one(db, cfg)
    assert calls == [WEBHOOK + "REPLACED" if change == "replace" else WEBHOOK]
    assert {row["status"] for row in db.many("SELECT status FROM slack_outbox")} == {"cancelled", "sent"}


def test_api_worker_automatically_delivers_and_respects_suspension(db, monkeypatch):
    tid = tenant(db)["id"]
    cfg = config(tid)
    cfg.database_url, cfg.cost_processing = db.url, False
    cfg.set_services("api")
    connect(db, tid, cfg)
    notification(db, tid)
    slack.collect(db, cfg)
    db.execute("UPDATE tenants SET status='suspended' WHERE id=$1", tid)
    finding(db, tid, "critical")
    slack.collect(db, cfg)
    assert db.scalar("SELECT count(*) FROM slack_outbox") == 1
    assert not slack.dispatch_one(db, cfg)
    db.execute("UPDATE tenants SET status='active' WHERE id=$1", tid)
    delivered = Event()
    monkeypatch.setattr(slack, "send", lambda url, message: delivered.set())
    with TestClient(create_app(cfg, db)):
        assert delivered.wait(10)
    assert slack.read(db, tid, cfg)["delivery"]["last_sent_at"] is not None


@pytest.mark.parametrize("status,body,expected", [(200,b"ok",None), (200,b"error","webhook_rejected"),
    (302,b"redirect","webhook_rejected"), (403,b"secret provider response","webhook_rejected"),
    (429,b"rate limited","rate_limited"), (503,b"error","provider_unavailable"), (0,b"","provider_unavailable")])
def test_fixed_https_transport_and_sanitized_errors(monkeypatch, caplog, status, body, expected):
    calls = []

    class Connection:
        def __init__(self, host, timeout):
            assert host == "hooks.slack.com" and timeout == 5

        def request(self, method, path, body, headers):
            assert method == "POST" and path == "/services/TTEST/BTEST/SYNTHETIC_SECRET"
            assert json.loads(body) == {"text": "Test"}
            calls.append(method)
            if status == 0:
                raise OSError(WEBHOOK)

        def getresponse(self):
            self.status = status
            return self

        def read(self, size):
            assert size == 128
            return body

        def getheader(self, name, default):
            return "120"

        def close(self):
            calls.append("closed")

    monkeypatch.setattr(slack.http.client, "HTTPSConnection", Connection)
    if expected:
        with pytest.raises(slack.DeliveryError) as error:
            slack.send(WEBHOOK, {"text": "Test"})
        assert str(error.value) == expected
        assert error.value.retryable == (status == 429 or status >= 500 or status == 0)
        if status == 429:
            assert error.value.retry_after == 120
    else:
        slack.send(WEBHOOK, {"text": "Test"})
    assert calls == ["POST", "closed"]
    assert "SYNTHETIC_SECRET" not in caplog.text


def test_encryption_key_required_and_loaded_from_environment(db, monkeypatch, tmp_path):
    tid = tenant(db)["id"]
    with pytest.raises(APIError) as error:
        connect(db, tid, Config())
    assert error.value.status == 503
    assert db.scalar("SELECT count(*) FROM tenant_slack_settings") == 0
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("OPENAIDR_SLACK_WEBHOOK_KEY", key)
    assert from_env().slack_webhook_key == key
    monkeypatch.delenv("OPENAIDR_SLACK_WEBHOOK_KEY")
    secret = tmp_path / "slack_webhook_key"
    secret.write_text(key + "\n")
    monkeypatch.setenv("OPENAIDR_SLACK_WEBHOOK_KEY_FILE", str(secret))
    assert from_env().slack_webhook_key == key
    with pytest.raises(ValueError, match="Fernet key"):
        Config(slack_webhook_key="bad").validate()
