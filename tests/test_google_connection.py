"""Desktop pairing proves both identities and survives interrupted native activation."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from openaidr_api_client.contracts.capabilities import CAPABILITIES

from openaidr.sensor import bridge, google_connection as google, usage
from openaidr.sensor.config import Config
from openaidr.sensor.telemetry import Telemetry
from test_sensor_free_runtime import free_config


class Remote:
    def __init__(self, cfg):
        self.cfg, self.tenant, self.calls = cfg, str(uuid4()), []
        self.approved, self.expired, self.lost = False, False, False
        self.expiry = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        self.bad = {}
        self.started = None

    def __call__(self, request):
        self.calls.append(request)
        assert request.url.host == 'api.opensecura.ai'
        if request.url.path == '/v1/capabilities':
            value = json.loads((Path(self.cfg['data_dir']) / 'google-connection.json').read_text())
            assert request.headers['authorization'] == 'Bearer ' + value['key']
            return httpx.Response(200, json=dict(tenant_id=self.tenant, build='test',
                capabilities={name: 'configured' for name in CAPABILITIES},
                provider_access='not_checked', investigation_worker='not_checked'))
        assert request.headers['authorization'] == 'Bearer ' + self.cfg['sensor_token']
        if request.method == 'POST':
            data = json.loads(request.content)
            if self.started is not None:
                assert data == self.started
            self.started = data
            if self.lost:
                raise httpx.ReadTimeout('secret remote message')
        assert self.started
        result = dict(status='expired' if self.expired else 'approved' if self.approved else 'pending',
            expires_at=self.expiry, verification_uri=google.CONSOLE + '/connect/?request=' + self.started['request_id'])
        if self.approved:
            result.update(tenant_id=self.tenant, email='user@example.com', key_id=self.started['key_id'])
        return httpx.Response(200, json={**result, **self.bad})


def test_pairing_retries_preserve_key_and_approved_receipts_recover_after_expiry(tmp_path, monkeypatch):
    cfg = free_config(tmp_path)
    remote = Remote(cfg)
    transport = httpx.MockTransport(remote)
    remote.lost = True
    before = cfg.path.read_bytes()
    with pytest.raises(ValueError, match='Could not complete Google sign-in'):
        google.request(cfg, start=True, transport=transport)
    path = Path(cfg['data_dir']) / 'google-connection.json'
    retained = path.read_bytes()
    key = json.loads(retained)['key']
    assert remote.started['token_hash'] == hashlib.sha256(key.encode()).hexdigest()
    assert key not in remote.calls[0].content.decode()
    remote.lost = False
    monkeypatch.setattr(google.platform, 'node', lambda: 'renamed-device')
    result = google.request(cfg, start=True, transport=transport)
    assert result['status'] == 'pending' and key not in str(result)
    assert path.read_bytes() == retained and cfg.path.read_bytes() == before
    Telemetry(cfg).close()
    original_scope = usage.local_identity(cfg)
    remote.approved = True
    remote.expiry = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    assert google.request(cfg, transport=transport)['status'] == 'approved'
    result = google.activate(cfg, transport=transport)
    current = Config.load(cfg.path)
    assert current['sensor_id'] == cfg['sensor_id'] and current['sensor_token'] == key
    assert current['tenant_id'] == remote.tenant and current['connection_mode'] == 'api_key'
    assert current['google_account']['email'] == 'user@example.com'
    assert usage.local_identity(current) == original_scope
    assert key not in str(result)
    count = len(remote.calls)
    assert google.activate(cfg, transport=transport) == result
    assert len(remote.calls) == count


def test_pairing_rejects_changed_connection_bad_approval_and_unsafe_redirect(tmp_path):
    cfg = free_config(tmp_path)
    remote, before = Remote(cfg), cfg.path.read_bytes()
    transport = httpx.MockTransport(remote)
    remote.bad = {'verification_uri': 'https://other.example/connect'}
    with pytest.raises(ValueError, match='Could not complete Google sign-in'):
        google.request(cfg, start=True, transport=transport)
    remote.bad = {}
    google.request(cfg, start=True, transport=transport)
    remote.approved = True
    for bad in ({'key_id': uuid4().hex}, {'tenant_id': 'bad'}, {'email': 'user\n@example.com'}):
        remote.bad = bad
        with pytest.raises(ValueError, match='Could not complete Google sign-in'):
            google.activate(cfg, transport=transport)
        assert cfg.path.read_bytes() == before
    remote.bad = {'tenant_id': str(uuid4())}
    with pytest.raises(ValueError, match='Could not complete Google sign-in'):
        google.activate(cfg, transport=transport)
    assert cfg.path.read_bytes() == before
    cfg['connection_mode'] = 'organization'
    cfg.save()
    count = len(remote.calls)
    with pytest.raises(ValueError, match='requires this device'):
        google.request(cfg, transport=transport)
    assert len(remote.calls) == count


def test_confirmed_expiry_replaces_only_expired_pairing_key(tmp_path):
    cfg = free_config(tmp_path)
    remote = Remote(cfg)
    transport = httpx.MockTransport(remote)
    google.request(cfg, start=True, transport=transport)
    path = Path(cfg['data_dir']) / 'google-connection.json'
    previous = path.read_bytes()
    remote.expired = True
    assert google.request(cfg, transport=transport)['status'] == 'expired'
    assert not path.exists()
    remote.expired, remote.started = False, None
    google.request(cfg, start=True, transport=transport)
    assert path.read_bytes() != previous
    assert Config.load(cfg.path)['connection_mode'] == 'free'


def test_bridge_stops_sensor_and_restarts_with_committed_account_or_old_connection(tmp_path, monkeypatch):
    cfg = free_config(tmp_path)
    remote = Remote(cfg)
    transport = httpx.MockTransport(remote)
    google.request(cfg, start=True, transport=transport)
    remote.approved = True
    calls = []
    monkeypatch.setattr(bridge, 'live_status', lambda config: {'sensor_id': cfg['sensor_id'], 'server_url': cfg['server_url']})
    monkeypatch.setattr(bridge, 'keep_existing', lambda *args: False)
    monkeypatch.setattr(bridge.service, 'stop_and_wait', lambda config: calls.append(('stop', config['tenant_id'])))
    def manage(action, config, **kwargs):
        calls.append((action, config['tenant_id']))
        return 'running'
    monkeypatch.setattr(bridge.service, 'manage', manage)
    activate = google.activate
    monkeypatch.setattr(google, 'activate', lambda config: activate(config, transport=transport))
    remote.bad = {'key_id': uuid4().hex}
    with pytest.raises(ValueError):
        bridge.handle({'action': 'google.connect', 'config_path': str(cfg.path)})
    assert calls[-2:] == [('stop', cfg['tenant_id']), ('start', cfg['tenant_id'])]
    remote.bad = {}
    bridge.handle({'action': 'google.connect', 'config_path': str(cfg.path)})
    assert calls[-2:] == [('stop', cfg['tenant_id']), ('start', remote.tenant)]
    with pytest.raises(ValueError, match='unknown action parameter'):
        bridge.handle({'action': 'google.connect', 'config_path': str(cfg.path), 'params': {'tenant_id': str(uuid4())}})
