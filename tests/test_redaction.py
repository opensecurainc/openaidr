import json
import re
from pathlib import Path

import pytest
import yaml

from openaidr.core.redact import SecretRedactor, redact_event, redact_string
from openaidr_common import redact as shared_redact
from openaidr.sensor.config import Config
from openaidr.sensor.telemetry import Telemetry
from openaidr.core.telemetry import decode_export, encode_export


RULES_PATH = Path(shared_redact.__file__).with_name("secret-redaction.yaml")
RULES = yaml.safe_load(RULES_PATH.read_text())
# All credentials in these fixtures are synthetic and never used for authentication.
CASES = json.loads(
    (Path(__file__).parent / "fixtures/secret-redaction.json").read_text()
)


def redactor_from_rules(tmp_path, patterns):
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump({**RULES, "patterns": patterns}, sort_keys=False))
    return SecretRedactor(path)


def test_every_bundled_rule_has_a_credential_fixture():
    assert {rule["name"] for rule in RULES["patterns"]} == {
        case["name"] for case in CASES
    }
    assert len(CASES) == len({case["name"] for case in CASES})


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_each_rule_redacts_only_the_complete_credential(tmp_path, case):
    rule = next(r for r in RULES["patterns"] if r["name"] == case["name"])
    redactor = redactor_from_rules(tmp_path, [rule])
    source = case["before"] + case["secret"] + case["after"]
    expected = case["before"] + "[REDACTED:" + case["name"] + "]" + case["after"]
    assert redactor.redact(source) == (expected, [case["name"]])
    assert redactor.redact(expected) == (expected, [])


@pytest.fixture(scope="module")
def unfiltered_redactor(tmp_path_factory):
    return redactor_from_rules(
        tmp_path_factory.mktemp("unfiltered"),
        [
            {key: value for key, value in rule.items() if key != "keywords"}
            for rule in RULES["patterns"]
        ],
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_all_rules_preserve_context_and_keyword_filters_keep_matches(
    case, unfiltered_redactor
):
    source = case["before"] + case["secret"] + case["after"]
    result, names = redact_string(source)
    assert names
    assert result.startswith(case["before"] + "[REDACTED:")
    assert result.endswith("]" + case["after"])
    assert result.count("[REDACTED:") == 1
    assert case["secret"] not in result
    assert re.fullmatch(
        r"\[REDACTED:[a-z0-9-]+\]",
        result[len(case["before"]) : len(result) - len(case["after"])],
    )
    assert (result, names) == unfiltered_redactor.redact(source)
    assert redact_string(result) == (result, [])


@pytest.mark.parametrize(
    "field", ["CO_API_KEY", "CO_API-KEY", "CO-API_KEY", "CO-API-KEY"]
)
def test_cohere_field_separators_preserve_keyword_matches(field, unfiltered_redactor):
    source = field + "=" + "aB3d" * 10
    assert redact_string(source) == unfiltered_redactor.redact(source)


@pytest.mark.parametrize("scheme", ["redis", "rediss", "amqp", "amqps"])
@pytest.mark.parametrize("username", ["", "user"])
def test_connection_url_passwords_with_optional_username(scheme, username):
    source = f"{scheme}://{username}:synthetic-password@service.example:6379"
    assert redact_string(source) == (
        f"{scheme}://{username}:[REDACTED:url-password]@service.example:6379",
        ["url-password"],
    )


@pytest.mark.parametrize(
    "field",
    ["dbPassword", "databasePassword", "dbpassword", "dbApiKey", "serviceToken"],
)
def test_namespaced_secret_assignments_and_serialized_tool_inputs(field):
    source = field + "=synthetic-password"
    assert redact_string(source) == (field + "=[REDACTED:assignment]", ["assignment"])
    event = {"tool": {"input": {field: "synthetic-password"}}}
    redact_event(event, {"redact": True, "tool_input": True})
    assert event["tool"]["input"] == {field: "[REDACTED:assignment]"}


@pytest.mark.parametrize(
    "source",
    [
        "Meeting on 2026-09-30 at 15:24:30 with alice@example.com",
        "arn:aws:s3:::company-assets s3://company-assets/public/logo.svg",
        "https://api.example.com/v1/events?date=2026-09-30&count=123456",
        "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6 " + "a1b2c3d4" * 8,
        "stripe_publishable_key=pk_live_" + "aB3dE5" * 4,
        "public key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ user@example.com",
        "AWS_SECRET_ACCESS_KEY is an environment variable name",
        "token_count=123456 password_length=123456 api_version=20260930",
        'linear_commit="' + "a1b2c3d4" * 4 + '"',
        'cloudflare_checksum="' + "a1b2c3d4" * 5 + '"',
        "The basic implementation includes an authorization component.",
        "gitlab-pat-routable and github-token are rule names, not credentials.",
        "redis://service.example:6379 redis://@service.example redis://:@service.example",
    ],
)
def test_normal_text_is_preserved(source):
    assert redact_string(source) == (source, [])


@pytest.mark.parametrize(
    "secret",
    [
        "AIza" + "aB3dE5fG" * 4 + "hI-",
        "glpat-" + "aB3_dE5-" * 4,
        "github_pat_" + "aB3_dE5_" * 6,
        "rk_test_" + "aB3dE5" * 4,
        "ASIAIOSFODNN7EXAMPLE",
        "fm1a_" + "aB3dE5" * 20 + "==",
        "fm2_" + "aB3dE5" * 20 + "==",
        "sgp_" + "a1b2c3d4" * 5,
        "sgp_local_" + "a1b2c3d4" * 5,
        "A3-ABC123-ABC123ABC12-ABC12-ABC12-ABC12",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nprivate-material\n-----END PGP PRIVATE KEY BLOCK-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nprivate-material\n-----END ENCRYPTED PRIVATE KEY-----",
    ],
)
def test_token_variants_and_punctuation_are_fully_redacted(secret):
    for source, expected in (
        (secret, "[REDACTED]"),
        ('["' + secret + '"]', '["[REDACTED]"]'),
    ):
        result, names = redact_string(source)
        assert names
        assert re.sub(r"\[REDACTED:[a-z0-9-]+\]", "[REDACTED]", result) == expected


def test_truncated_private_key_is_redacted_through_end_of_text():
    result, _ = redact_string(
        "before\n-----BEGIN RSA PRIVATE KEY-----\nprivate-material"
    )
    assert result == "before\n[REDACTED:private-key]"


def test_multiple_credentials_and_json_assignments_preserve_structure():
    source = '{"password":"synthetic-password","note":"' + "npm_" + "aB3dE5" * 6 + '"}'
    result, _ = redact_string(source)
    assert json.loads(result) == {
        "password": "[REDACTED:assignment]",
        "note": "[REDACTED:npm-access-token]",
    }


def test_overlapping_rules_remove_the_union_without_scanning_markers(tmp_path):
    redactor = redactor_from_rules(
        tmp_path,
        [
            {"name": "short", "pattern": "abc", "keywords": ["ABC"]},
            {"name": "long", "pattern": "bcdef", "keywords": ["BCDEF"]},
            {"name": "marker", "pattern": "REDACTED"},
        ],
    )
    assert redactor.redact("before abcdef after") == (
        "before [REDACTED:short] after",
        ["short", "long"],
    )


def test_optional_capture_group_does_not_redact_unmatched_text(tmp_path):
    redactor = redactor_from_rules(
        tmp_path,
        [
            {"name": "optional", "pattern": "prefix(?:=(value))?", "group": 1},
        ],
    )
    assert redactor.redact("prefix prefix=value") == (
        "prefix prefix=[REDACTED:optional]",
        ["optional"],
    )


@pytest.mark.parametrize(
    "fields",
    [
        {"keywords": "token"},
        {"keywords": [""]},
        {"keywords": [None]},
        {"pattern": ""},
        {"group": True},
        {"keywrods": ["token"]},
        {"name": 'quoted"name'},
        {"name": "back\\slash"},
        {"name": "new\nline"},
        {"name": "closing]bracket"},
        {"name": "Uppercase"},
    ],
)
def test_invalid_rule_options_fail_to_load(tmp_path, fields):
    with pytest.raises(ValueError):
        redactor_from_rules(tmp_path, [{"name": "test", "pattern": "token", **fields}])


@pytest.mark.parametrize("content_type", ["application/json", "application/x-protobuf"])
def test_new_credentials_are_redacted_before_durable_queue(tmp_path, content_type):
    values = [case["before"] + case["secret"] + case["after"] for case in CASES]
    payload = {
        "resourceLogs": [
            {
                "scopeLogs": [
                    {
                        "logRecords": [
                            {
                                "body": {"stringValue": "tool_result"},
                                "attributes": [
                                    {"key": "output", "value": {"stringValue": value}}
                                ],
                            }
                            for value in values
                        ]
                    }
                ]
            }
        ],
    }
    config = Config(
        tmp_path / "sensor.yaml",
        data_dir=str(tmp_path / "data"),
        server_url="https://remote.example",
        sensor_id="sensor-id",
        sensor_token="synthetic-sensor-token",
    )
    telemetry = Telemetry(config)
    try:
        telemetry.accept(
            "logs", encode_export("logs", payload, content_type), content_type
        )
        stored = decode_export("logs", telemetry.queue.next()["body"], content_type)
    finally:
        telemetry.close()
    records = stored["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    for case, record in zip(CASES, records, strict=True):
        attribute = record["attributes"][0]
        assert (
            attribute["value"]["stringValue"]
            == redact_string(case["before"] + case["secret"] + case["after"])[0]
        )
        assert case["secret"] not in attribute["value"]["stringValue"]


@pytest.mark.parametrize(
    "name,arguments,cwd,fields",
    [
        (
            "WebFetch", {"url": "https://example.com/doc?token={secret}&page=1"},
            "/repo", [("network", "url")],
        ),
        (
            "WebFetch", {"url": "https://user:{secret}@example.com/doc"},
            "/repo", [("network", "url")],
        ),
        (
            "WebFetch", {"url": "https://{secret}.example.com/doc"},
            "/repo", [("network", "url"), ("network", "host")],
        ),
        (
            "Read", {"file_path": "/tmp/{secret}/file.txt"},
            "/repo", [("file", "path")],
        ),
        (
            "Bash", {"command": "pwd", "description": "Inspect {secret}"},
            "/repo", [("command", "description")],
        ),
        (
            "Bash", {"command": "pwd"}, "/tmp/{secret}",
            [("command", "cwd"), ("session", "cwd")],
        ),
        (
            "WebFetch", {"url": "https://example.com/doc?page=1"},
            "/repo", [("network", "url")],
        ),
        (
            "WebFetch", {"url": "https://example.com/" + "public/" * 20},
            "/repo", [("network", "url")],
        ),
    ],
    ids=["query", "userinfo", "hostname", "file", "description", "cwd", "public-url", "long-url"],
)
@pytest.mark.parametrize("redact,tool_input", [(True, True), (True, False), (False, True)])
def test_mapped_transcript_evidence_is_redacted_before_disk_queue(
    tmp_path, name, arguments, cwd, fields, redact, tool_input
):
    from openaidr.sensor.collectors import Parser
    from openaidr.sensor.runtime import Sensor

    secret = "ghp_" + "a" * 36
    record = {
        "type": "assistant",
        "sessionId": "synthetic-session",
        "uuid": "synthetic-record",
        "cwd": cwd.format(secret=secret),
        "message": {"content": [{
            "type": "tool_use", "id": "synthetic-call", "name": name,
            "input": {key: value.format(secret=secret) for key, value in arguments.items()},
        }]},
    }
    events = Parser("claude-code", "/synthetic/transcript.jsonl").parse(record)
    event = next(event for event in events if "tool" in event)
    original = json.dumps(event, sort_keys=True)
    has_secret = secret in original
    config = Config(
        tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"),
        server_url="http://localhost", sensor_id="sensor-id",
        sensor_token="synthetic-token", telemetry={"enabled": False},
    )
    sensor = Sensor(config)
    sensor.capture.update(redact=redact, tool_input=tool_input, max_text_bytes=64)
    try:
        sensor.emit(event)
        stored = sensor.spool.read()["events"][0]
        disk = b"".join(path.read_bytes() for path in sensor.spool.segments())
        if redact or not has_secret:
            assert secret.encode() not in disk
        else:
            assert secret.encode() in disk
        for section, key in fields:
            value = event[section][key]
            expected = redact_string(value)[0] if redact else value
            assert stored[section][key] == expected
        assert stored.get("redacted", False) == (redact and has_secret)
        assert ("content_redacted" in stored["evidence"]["gaps"]) == (redact and has_secret)
        assert ("input" in stored["tool"]) == tool_input
        assert stored["tool"]["call_id"] == event["tool"]["call_id"]
        assert stored["session"]["id"] == event["session"]["id"]
        for key in ("logical_id", "observation_id", "stream_id", "sequence", "part"):
            assert stored["evidence"][key] == event["evidence"][key]
        assert json.dumps(event, sort_keys=True) == original
    finally:
        sensor.spool.close()
        sensor.client.close()


def test_transcript_capture_gaps_and_replay_identity_survive_sensor_restart(tmp_path):
    from openaidr.sensor.runtime import Sensor

    evidence = {
        "version": 1,
        "logical_id": "a" * 64,
        "observation_id": "b" * 64,
        "stream_id": "c" * 64,
        "sequence": 1,
        "part": 1,
        "gaps": [],
    }
    event = {
        "kind": "prompt",
        "session": {"id": "session"},
        "agent": {"product": "codex-cli"},
        "text": "password=synthetic-password",
        "evidence": evidence,
    }
    replay_ids = []
    for sensor_id in ("sensor-a", "sensor-a", "sensor-b"):
        config = Config(
            tmp_path / sensor_id / "sensor.yaml",
            data_dir=str(tmp_path / sensor_id),
            server_url="http://localhost",
            sensor_id=sensor_id,
            sensor_token="synthetic-token",
            telemetry={"enabled": False},
        )
        sensor = Sensor(config)
        try:
            sensor.emit(event)
            batch = sensor.spool.read()
            stored = batch["events"][0]
            replay_ids.append(stored["id"])
            assert "synthetic-password" not in json.dumps(stored)
            assert "content_redacted" in stored["evidence"]["gaps"]
            assert stored["evidence"]["logical_id"] == evidence["logical_id"]
            sensor.spool.ack(batch)

            sensor.capture["prompt_text"] = False
            sensor.emit(event)
            batch = sensor.spool.read()
            stored = batch["events"][0]
            assert "text" not in stored
            assert "capture_disabled" in stored["evidence"]["gaps"]
            sensor.spool.ack(batch)

            sensor.capture["prompt_text"] = True
            sensor.capture["max_text_bytes"] = 4
            sensor.emit({**event, "text": "\u00e9" * 10})
            stored = sensor.spool.read()["events"][0]
            assert len(stored["text"].encode()) <= 4
            assert "content_truncated" in stored["evidence"]["gaps"]
            sensor.spool.ack(sensor.spool.read())
        finally:
            sensor.spool.close()
            sensor.client.close()
    assert replay_ids[0] == replay_ids[1]
    assert replay_ids[0] != replay_ids[2]
    assert event["text"] == "password=synthetic-password"
    assert evidence["gaps"] == []
