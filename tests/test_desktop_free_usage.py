"""Monthly credit reads bind the installation and never expose provider accounting."""

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from openaidr.sensor import bridge, desktop_free_usage
from test_sensor_free_runtime import free_config


def test_bridge_reads_verified_free_balance_and_rejects_unknown_or_foreign_data(tmp_path, monkeypatch):
    cfg = free_config(tmp_path)
    now = datetime.now(timezone.utc)
    usage = dict(status='active', allowance='200', used='10.01', reserved='0.09', available='189.9',
                 starts_at=(now-timedelta(days=1)).isoformat(), resets_at=(now+timedelta(days=1)).isoformat(),
                 checked_at=now.isoformat(), provider='private detail')
    value = dict(tenant_id=cfg['tenant_id'], plan='free', status='available', guardrail_configured=True,
                 guardrail_available=True, credit_status='active', credits_per_usd='100', reset_at=None, usage=usage)
    requests = []
    def remote(request):
        requests.append(request)
        assert request.method == 'GET' and request.url.path == '/v1/free/usage'
        assert request.headers['authorization'] == 'Bearer ' + cfg['sensor_token']
        return httpx.Response(200, json=value)
    original = desktop_free_usage.read
    monkeypatch.setattr(desktop_free_usage, 'read', lambda config: original(config, transport=httpx.MockTransport(remote)))
    def read():
        return bridge.handle(dict(action='free.usage', config_path=str(cfg.path)))
    result = read()
    assert result['usage']['used'] == '10.01'
    assert set(result) == {'sensor_id', 'server_url', 'usage', 'configured'}
    assert 'provider' not in result['usage'] and cfg['sensor_token'] not in str(result)
    for invalid in ({'available':'200'}, {'used':'-1'}, {'checked_at':(now-timedelta(minutes=5)).isoformat()}, {'status':'unknown'}):
        value['usage'] = {**usage, **invalid}
        with pytest.raises(ValueError, match='usage is unavailable'):
            read()
    value['usage'] = usage
    value['tenant_id'] = '00000000-0000-4000-8000-000000000000'
    with pytest.raises(ValueError, match='usage is unavailable'):
        read()
    value['tenant_id'], value['usage'] = cfg['tenant_id'], None
    with pytest.raises(ValueError, match='usage is unavailable'):
        read()
    value['usage'] = dict(status='disabled', allowance=None, used=None, reserved=None, available=None, starts_at=None, resets_at=None, checked_at=now.isoformat())
    assert read()['usage']['status'] == 'disabled'
    before = len(requests)
    with pytest.raises(ValueError, match='unknown action parameter'):
        bridge.handle(dict(action='free.usage', config_path=str(cfg.path), params={'tenant_id':'other'}))
    cfg['connection_mode'] = 'organization'
    cfg.save()
    with pytest.raises(ValueError, match='free-plan connection'):
        read()
    assert len(requests) == before


@pytest.mark.parametrize('failure', ['redirect', 'oversize', 'timeout'])
def test_free_usage_transport_is_bounded_and_does_not_forward_credentials(tmp_path, failure):
    cfg = free_config(tmp_path)
    requests = []
    def remote(request):
        requests.append(request)
        if failure == 'redirect':
            return httpx.Response(307, headers={'location':'https://other.example/collect'})
        if failure == 'oversize':
            return httpx.Response(200, content=b' ' * 4097)
        raise httpx.ReadTimeout('sensitive upstream detail')
    with pytest.raises(ValueError, match='Free plan usage is unavailable') as error:
        desktop_free_usage.read(cfg, transport=httpx.MockTransport(remote))
    assert len(requests) == 1 and requests[0].url.host == 'api.opensecura.ai'
    assert 'sensitive' not in str(error.value) and cfg['sensor_token'] not in str(error.value)
