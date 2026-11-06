from copy import deepcopy
from uuid import UUID
import pytest
from openaidr.core.event import new_id, now, validate_event
from openaidr.core.protocol import default_sensor_config, normalize_sensor_config


def valid():
    return {
        "id": new_id(),
        "time": now(),
        "observed_at": now(),
        "kind": "prompt",
        "agent": {"product": "claude-code"},
        "session": {"id": "s"},
        "host": {},
        "source": {},
    }


def test_wire_contract():
    event = valid()
    event["future_field"] = {"new": "value"}
    event["agent"]["account"] = "dev@example.com"
    assert validate_event(event) == ""
    for account in (None, 3, [], {}):
        broken = deepcopy(event)
        broken["agent"]["account"] = account
        assert validate_event(broken) == "agent.account must be a string"
    assert UUID(event["id"]).version == 7
    for key, reason in [
        ("id", "missing id"),
        ("time", "missing time"),
        ("kind", "missing kind"),
    ]:
        broken = deepcopy(event)
        del broken[key]
        assert validate_event(broken) == reason
    event["kind"] = "unknown"
    assert validate_event(event) == "unknown kind"
    event["kind"] = "sensor"
    event["session"] = {}
    assert validate_event(event) == ""


def test_optional_evidence_contract():
    event = valid()
    assert validate_event(event) == ""
    evidence = {
        "version": 1,
        "logical_id": "logical-1",
        "observation_id": "observation-1",
        "stream_id": "stream-1",
        "sequence": 1,
        "part": 0,
        "gaps": ["skipped_history", "content_redacted"],
        "future_field": "preserved",
    }
    event["evidence"] = evidence
    assert validate_event(event) == ""
    for key, values in {
        "version": [True, 1.0, "1", 2, None],
        "logical_id": ["", "x" * 129, "contains spaces", "é", 2],
        "observation_id": [None],
        "stream_id": [""],
        "sequence": [True, -1, 1.0, "1", 1 << 63],
        "part": [False, -1],
        "gaps": [None, "skipped_history", ["unknown"], [[]], ["skipped_history"] * 33],
    }.items():
        for value in values:
            event["evidence"] = dict(evidence, **{key: value})
            assert validate_event(event).startswith("invalid evidence"), (key, value)
    event["evidence"] = None
    assert validate_event(event) == "invalid evidence version"


def test_optional_session_registration_contract():
    event = valid()
    registration_id = new_id()
    for ident in (registration_id, registration_id.upper()):
        event["session"]["registration_id"] = ident
        assert validate_event(event) == ""
    for ident in (None, 7, {}, "", "not-a-uuid", "urn:uuid:" + registration_id):
        event["session"]["registration_id"] = ident
        assert validate_event(event) == "invalid session.registration_id"
    event["session"]["registration_id"] = registration_id
    for ident in (None, {}, 7, "", "x" * 257, "native\x00id", "native\nid", "native\x7fid"):
        event["session"]["id"] = ident
        assert validate_event(event) == "invalid registered session.id"


@pytest.mark.parametrize(
    "kind,field,key,reason",
    [
        ("command", "command", "text", "command event without command.text"),
        ("file.read", "file", "path", "file event without file.path"),
        ("file.write", "file", "path", "file event without file.path"),
        ("network", "network", "url", "network event without network.url"),
    ],
)
def test_required_kind_fields(kind, field, key, reason):
    event = valid()
    event["kind"] = kind
    assert validate_event(event) == reason
    event[field] = {key: "value"}
    assert validate_event(event) == ""


def test_config_defaults_and_normalization():
    config = default_sensor_config()
    assert config["batch_max_events"] == 500 and config["capture"]["redact"]
    config["capture"]["raw"] = True
    assert not default_sensor_config()["capture"]["raw"]
    normalized = normalize_sensor_config(
        {"batch_max_events": -1, "capture": {"prompt_text": False}}
    )
    assert (
        normalized["heartbeat_interval_s"] == 30
        and normalized["batch_max_events"] == 500
    )
    assert not normalized["capture"]["prompt_text"]
    assert normalized["capture"]["max_text_bytes"] == 16384
