"""The real customer SDK crosses only a simulated external HTTP boundary."""

import json
import os
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import httpx
import pytest

from openaidr.sensor.config import Config
from openaidr.sensor import free_enrollment


def config(tmp_path):
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"))
    cfg.save()
    return cfg


class Service:
    def __init__(self, cfg, *, failure=None, available=True):
        self.cfg, self.failure, self.available = cfg, failure, available
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        assert str(request.url).startswith(free_enrollment.ORIGIN + "/v1/free/")
        saved = json.loads((self.cfg.path.parent / "data/free-enrollment.json").read_text())
        tenant = str(uuid5(NAMESPACE_URL, free_enrollment.ORIGIN + "/free/" + UUID(saved["installation_id"]).hex))
        if request.url.path.endswith("/enroll"):
            assert "authorization" not in request.headers
            assert json.loads(request.content) == saved
        else:
            assert request.url.path == "/v1/free/status"
            assert request.headers["authorization"] == "Bearer oasc_" + UUID(saved["installation_id"]).hex + "." + saved["secret"]
        if self.failure == "lost_reply" and len(self.requests) == 1:
            raise httpx.ReadTimeout("lost response")
        if self.failure == "status_timeout" and request.url.path.endswith("/status"):
            raise httpx.ReadTimeout("status timed out")
        if self.failure == "rate_limit":
            return httpx.Response(429)
        if self.failure == "redirect":
            return httpx.Response(307, headers={"Location":"https://other.example/collect"})
        value = dict(tenant_id=tenant, plan="free", status="available" if self.available else "exhausted",
            guardrail_available=self.available, guardrail_configured=True, credit_status="active" if self.available else "exhausted",
            credits_per_usd="100", reset_at=None)
        if self.failure == "wrong_enrollment" and request.url.path.endswith("/enroll"):
            value["tenant_id"] = str(uuid4())
        if self.failure == "wrong_status" and request.url.path.endswith("/status"):
            value["tenant_id"] = str(uuid4())
        if self.failure == "invalid_status" and request.url.path.endswith("/status"):
            value["guardrail_available"] = False
        return httpx.Response(200, json=value)


@pytest.mark.parametrize("available", [True, False])
def test_free_connection_proves_identity_without_changing_sensor_configuration(tmp_path, available):
    cfg = config(tmp_path)
    before = cfg.path.read_bytes()
    service = Service(cfg, available=available)
    enrollment, status = free_enrollment.connect(cfg, transport=httpx.MockTransport(service))
    assert status.guardrail_available is available
    assert len(service.requests) == 2
    assert cfg.path.read_bytes() == before and not Config.load(cfg.path).enrolled()
    assert enrollment.secret not in repr(enrollment)
    path = tmp_path / "data/free-enrollment.json"
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    saved = path.read_bytes()
    repeated, _ = free_enrollment.connect(Config.load(cfg.path), transport=httpx.MockTransport(service))
    assert repeated == enrollment and path.read_bytes() == saved


@pytest.mark.parametrize("failure", ["lost_reply", "status_timeout", "rate_limit", "redirect", "wrong_enrollment", "wrong_status", "invalid_status"])
def test_failed_proof_retains_identity_and_retries_without_binding(tmp_path, failure):
    cfg = config(tmp_path)
    before = cfg.path.read_bytes()
    service = Service(cfg, failure=failure)
    with pytest.raises(ValueError):
        free_enrollment.connect(cfg, transport=httpx.MockTransport(service))
    assert cfg.path.read_bytes() == before
    identity = (tmp_path / "data/free-enrollment.json").read_bytes()
    service.failure = None
    enrollment, status = free_enrollment.connect(Config.load(cfg.path), transport=httpx.MockTransport(service))
    assert status.tenant_id == enrollment.connection.tenant_id
    assert (tmp_path / "data/free-enrollment.json").read_bytes() == identity


def test_organization_and_damaged_free_identities_are_never_replaced(tmp_path):
    cfg = config(tmp_path)
    cfg.update(server_url="https://organization.example", sensor_id=str(uuid4()), sensor_token="organization-secret")
    cfg.save()
    before = cfg.path.read_bytes()
    with pytest.raises(ValueError, match="organization"):
        free_enrollment.connect(cfg)
    assert cfg.path.read_bytes() == before and not (tmp_path / "data/free-enrollment.json").exists()
    cfg.pop("sensor_token")
    cfg.save()
    path = tmp_path / "data/free-enrollment.json"
    path.parent.mkdir(exist_ok=True)
    for value in ('broken', '{}', 'x' * 2049):
        path.write_text(value)
        with pytest.raises(ValueError, match="not replaced"):
            free_enrollment.connect(cfg)
        assert path.read_text() == value


def test_enrolled_connection_must_match_its_saved_identity(tmp_path):
    cfg = config(tmp_path)
    service = Service(cfg)
    enrollment, _ = free_enrollment.connect(cfg, transport=httpx.MockTransport(service))
    connection = enrollment.connection
    cfg.update(connection_mode="free", server_url=connection.origin, tenant_id=connection.tenant_id,
        sensor_id=enrollment.device_id, sensor_token=connection.api_key)
    cfg.save()
    repeated, _ = free_enrollment.connect(cfg, transport=httpx.MockTransport(service))
    assert repeated == enrollment
    cfg["sensor_id"] = str(uuid4())
    cfg.save()
    with pytest.raises(ValueError, match="does not match"):
        free_enrollment.connect(cfg)
    path = tmp_path / "data/free-enrollment.json"
    path.unlink()
    with pytest.raises(ValueError, match="missing"):
        free_enrollment.connect(cfg)
    assert not path.exists()


def test_activation_publishes_verified_identity_once_and_rejects_organization_replacement(tmp_path):
    cfg = config(tmp_path)
    stale = Config.load(cfg.path)
    service = Service(cfg, failure="lost_reply")
    transport = httpx.MockTransport(service)
    with pytest.raises(ValueError):
        free_enrollment.activate(cfg, transport=transport)
    assert not Config.load(cfg.path).enrolled()
    identity = (tmp_path / "data/free-enrollment.json").read_bytes()
    service.failure = None
    result = free_enrollment.activate(cfg, transport=transport)
    connected = Config.load(cfg.path)
    assert connected.enrolled() and connected["connection_mode"] == "free"
    assert connected["sensor_token"] not in json.dumps(result)
    assert free_enrollment.activate(Config.load(cfg.path), transport=transport) == result
    stale["log_level"] = "debug"
    stale.save()
    assert Config.load(cfg.path)["connection_mode"] == "free"
    assert (tmp_path / "data/free-enrollment.json").read_bytes() == identity
    connected.pop("connection_mode")
    connected["sensor_token"] = "org-secret"
    connected.save()
    calls = len(service.requests)
    with pytest.raises(ValueError, match="organization"):
        free_enrollment.activate(cfg, transport=transport)
    assert len(service.requests) == calls
    assert Config.load(cfg.path)["sensor_token"] == "org-secret"


@pytest.mark.parametrize("failure", [None, "rejected", "redirect", "timeout", "malformed", "oversized", "tenant_changed"])
def test_manual_api_key_verification_is_bounded_private_and_atomic(tmp_path, failure):
    from openaidr.sensor import api_key
    from openaidr_api_client.contracts.capabilities import CAPABILITIES
    cfg = config(tmp_path)
    pending = free_enrollment.prepare(cfg)
    saved = (tmp_path / "data/free-enrollment.json").read_bytes()
    key, tenant, calls = "oasc_" + uuid4().hex + "." + "k" * 43, str(uuid4()), []
    if failure == "tenant_changed":
        cfg.update(connection_mode="api_key", server_url=free_enrollment.ORIGIN,
                   sensor_token=key, tenant_id=str(uuid4()), sensor_id=str(uuid4()))
        cfg.save()
    before = cfg.path.read_bytes()
    def service(request):
        calls.append(request)
        assert str(request.url) == free_enrollment.ORIGIN + "/v1/capabilities"
        assert request.headers["authorization"] == "Bearer " + key
        assert request.method == "GET" and not request.content
        if failure == "rejected":
            return httpx.Response(401, text=key)
        if failure == "redirect":
            return httpx.Response(307, headers={"location": "https://other.example/"})
        if failure == "timeout":
            raise httpx.ReadTimeout(key)
        if failure == "oversized":
            return httpx.Response(200, content=b" " * 17000)
        return httpx.Response(200, json=dict(tenant_id=tenant if failure != "malformed" else key,
            build="test", capabilities={name: "configured" for name in CAPABILITIES},
            provider_access="not_checked", investigation_worker="not_checked"))
    if failure:
        with pytest.raises(ValueError) as error:
            api_key.activate(cfg, key, transport=httpx.MockTransport(service))
        assert key not in str(error.value)
        assert cfg.path.read_bytes() == before
    else:
        result = api_key.activate(cfg, " " + key + " ", transport=httpx.MockTransport(service))
        assert key not in json.dumps(result) and pending.secret not in json.dumps(result)
        connected = Config.load(cfg.path)
        assert connected["connection_mode"] == "api_key" and connected["tenant_id"] == tenant
        assert api_key.connection(connected).api_key == key
        if os.name != "nt":
            assert cfg.path.stat().st_mode & 0o777 == 0o600
        assert api_key.activate(connected, key, transport=httpx.MockTransport(service)) == result
    assert len(calls) == (1 if failure else 2)
    assert (tmp_path / "data/free-enrollment.json").read_bytes() == saved


def test_manual_api_key_cannot_replace_an_existing_connection_or_accept_invalid_keys(tmp_path):
    from openaidr.sensor import api_key
    cfg = config(tmp_path)
    before = cfg.path.read_bytes()
    for invalid in (None, "", "oati_" + "x" * 76, "sk-provider-secret", "oasc_bad", "x" * 10000):
        with pytest.raises(ValueError, match="valid OpenSecura API key"):
            api_key.activate(cfg, invalid)
        assert cfg.path.read_bytes() == before
    cfg.update(server_url="https://organization.example", sensor_id=str(uuid4()), sensor_token="existing")
    cfg.save()
    before = cfg.path.read_bytes()
    with pytest.raises(ValueError, match="already connected"):
        api_key.activate(cfg, "oasc_" + uuid4().hex + "." + "k" * 43)
    assert cfg.path.read_bytes() == before


@pytest.mark.parametrize("tenant_matches", [True, False])
def test_api_key_heartbeat_checks_the_saved_tenant_without_exposing_response_details(tenant_matches):
    from types import SimpleNamespace
    from openaidr.sensor import api_key
    from openaidr_api_client.client import Unavailable
    from openaidr_api_client.contracts.capabilities import CAPABILITIES
    tenant = str(uuid4())
    value = dict(tenant_id=tenant if tenant_matches else str(uuid4()), build="test",
        capabilities={name: "configured" for name in CAPABILITIES},
        provider_access="not_checked", investigation_worker="not_checked")
    client = SimpleNamespace(tenant_id=tenant, request=lambda *args, **kwargs: value)
    if tenant_matches:
        assert api_key.status(client).tenant_id == tenant
    else:
        with pytest.raises(Unavailable, match="could not be verified"):
            api_key.status(client)


@pytest.mark.parametrize('lost_reply', [False, True])
def test_manual_unassigned_key_claims_once_and_recovers_a_lost_reply(tmp_path, lost_reply):
    from openaidr.sensor import api_key
    from openaidr_api_client.contracts.capabilities import CAPABILITIES
    cfg = config(tmp_path)
    key, bound, requests = 'oasc_' + uuid4().hex + '.' + 'k' * 43, None, []
    def service(request):
        nonlocal bound
        requests.append(request)
        assert request.url.path == '/v1/capabilities'
        assert request.headers['authorization'] == 'Bearer ' + key
        if bound is None:
            tenant = request.headers.get('x-opensecura-tenant-id')
            if tenant is None:
                return httpx.Response(401, json={'error': 'tenant_assignment_required'})
            assert str(UUID(tenant)) == tenant
            bound = tenant
            if lost_reply:
                raise httpx.ReadTimeout('Lost claim response')
        return httpx.Response(200, json={'tenant_id': bound, 'build': 'test',
            'capabilities': {name: 'configured' for name in CAPABILITIES},
            'provider_access': 'not_checked', 'investigation_worker': 'not_checked'})
    before = cfg.path.read_bytes()
    if lost_reply:
        with pytest.raises(ValueError, match='Could not verify'):
            api_key.activate(cfg, key, transport=httpx.MockTransport(service))
        assert cfg.path.read_bytes() == before
    api_key.activate(cfg, key, transport=httpx.MockTransport(service))
    assert Config.load(cfg.path)['tenant_id'] == bound
    assert sum('x-opensecura-tenant-id' in request.headers for request in requests) == 1
