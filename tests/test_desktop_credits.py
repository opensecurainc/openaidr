"""Credit summaries bind saved identities and expose only confirmed customer totals."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import httpx
import pytest

from openaidr.core import desktop_credits as credits
from openaidr.sensor import bridge, desktop_credits, usage
from test_sensor_free_runtime import free_config
from test_hooks_setup import sensor_config
from test_app_inventory_server import inventory  # noqa: F401


def paid_snapshot(tenant, now=None):
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(days=90)
    day = start.replace(hour=0, minute=0, second=0, microsecond=0)
    series = []
    while day < now:
        total = dict(credits_charged='1', operations=1, pending_operations=0, unrated_operations=0)
        series.append(dict(time=day.isoformat(), **total, by_service=[dict(service='guardrail', **total)]))
        day += timedelta(days=1)
    summary = dict(credits_charged=str(len(series)), operations=len(series), pending_operations=0, unrated_operations=0)
    return dict(schema_version=1, tenant_id=tenant, status='active', rate_version='test-v1', credits_per_usd='100',
        since=start.isoformat(), until=now.isoformat(), bucket_seconds=86400,
        balance=dict(available='985.82', reserved='0'), summary=summary,
        by_service=[dict(service='guardrail', **summary)], series=series)


def free_usage():
    now = datetime.now(timezone.utc)
    return dict(status='active', allowance='200', used='14.18', reserved='0', available='185.82',
        starts_at=(now-timedelta(days=1)).isoformat(), resets_at=(now+timedelta(days=6)).isoformat(), checked_at=now.isoformat())


def test_personal_credits_use_saved_identity_and_reject_foreign_stale_or_partial_data(tmp_path, monkeypatch):
    cfg = free_config(tmp_path, 'api_key')
    value = paid_snapshot(cfg['tenant_id'])
    received = []
    def remote(request):
        received.append(request)
        assert request.url.path == '/v1/credits' and dict(request.url.params) == {'range': '90d'}
        assert request.headers['authorization'] == 'Bearer ' + cfg['sensor_token']
        return httpx.Response(200, json=value)
    original = desktop_credits.read
    monkeypatch.setattr(desktop_credits, 'read', lambda config: original(config, transport=httpx.MockTransport(remote)))
    def call(**params):
        return bridge.handle(dict(action='credits.summary', config_path=str(cfg.path), params=params))
    result = call()
    assert set(result) == {'sensor_id', 'server_url', 'scope', 'plan', 'usage'}
    assert result['scope'] == usage.identity(cfg) and result['plan'] == 'paid'
    assert result['usage']['used'] == str(datetime.fromisoformat(value['until']).day)
    assert result['usage']['available'] == '985.82'
    assert set(result['usage']) == {'status', 'used', 'available', 'starts_at', 'checked_at'}
    with pytest.raises(ValueError, match='unknown action parameter'):
        call(tenant_id=str(uuid4()))
    assert len(received) == 1
    good = deepcopy(value)
    for bad in ({**good, 'tenant_id': str(uuid4())}, paid_snapshot(cfg['tenant_id'], datetime.now(timezone.utc)-timedelta(minutes=4)),
                {**good, 'balance': {'available': '-1', 'reserved': '0'}}, {**good, 'series': []}):
        value = bad
        with pytest.raises(ValueError, match='Credit usage is unavailable'):
            call()
    cfg['connection_mode'] = 'free'
    cfg.save()
    original_async = httpx.AsyncClient
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: original_async(**{**kwargs, 'transport': httpx.MockTransport(
        lambda req: httpx.Response(200, json=dict(tenant_id=cfg['tenant_id'], plan='free', usage=free_usage())))}))
    assert call()['usage']['used'] == '14.18'


def test_organization_bridge_projects_only_credits_and_preserves_unavailable(tmp_path, monkeypatch):
    cfg = sensor_config(tmp_path)
    response = dict(plan='free', usage=free_usage(), sensor_token='private', sensor_id='foreign')
    code = 200
    received = []
    def remote(request):
        received.append(request)
        assert request.url.path == '/ingest/v1/credits/summary' and json.loads(request.content) == {}
        assert request.headers['authorization'] == 'Bearer ' + cfg['sensor_token']
        return httpx.Response(code, json=response)
    original = httpx.Client
    monkeypatch.setattr(httpx, 'Client', lambda **kwargs: original(**{**kwargs, 'transport': httpx.MockTransport(remote)}))
    result = desktop_credits.read(cfg)
    assert result['sensor_id'] == cfg['sensor_id'] and result['usage'] == response['usage']
    assert 'private' not in str(result)
    for code in (404, 401, 503):
        with pytest.raises(ValueError, match='Credit usage is unavailable'):
            desktop_credits.read(cfg)
    code, response = 200, dict(plan='paid', usage=free_usage())
    with pytest.raises(ValueError, match='Credit usage is unavailable'):
        desktop_credits.read(cfg)


def test_sensor_credit_endpoint_enforces_auth_tenant_plan_and_safe_projection(inventory, monkeypatch):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    cfg.tenant_id = sensor['tenant_id']
    cfg.intelligence_origin = 'https://api.opensecura.ai'
    cfg.intelligence_api_key = 'oasc_' + 'a'*32 + '.' + 'b'*43
    requests = []
    value = paid_snapshot(cfg.tenant_id)
    def remote(request):
        requests.append(request)
        assert request.headers['authorization'] == 'Bearer ' + cfg.intelligence_api_key
        return httpx.Response(200, json=value)
    original = httpx.AsyncClient
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: original(**{**kwargs, 'transport': httpx.MockTransport(remote)}))
    path = '/ingest/v1/credits/summary'
    headers = {'authorization': 'Bearer ' + token}
    assert client.post(path, json={}).status_code == 401
    for bad in ({'tenant_id': identities[1][0]['tenant_id']}, {'range': '90d'}, [], True):
        assert client.post(path, json=bad, headers=headers).status_code == 400
    assert client.post(path, json={}, headers={'authorization': 'Bearer ' + identities[1][1]}).status_code == 403
    assert requests == []
    result = client.post(path, json={}, headers=headers)
    assert result.status_code == 200 and result.headers['cache-control'] == 'no-store'
    assert set(result.json()) == {'plan', 'usage'} and result.json()['plan'] == 'paid'
    assert 'tenant_id' not in result.text and cfg.intelligence_api_key not in result.text and 'service' not in result.text
    cfg.free_installation_id, cfg.free_secret = str(uuid4()), 'b'*43
    cfg.intelligence_api_key = 'oasc_' + cfg.free_installation_id.replace('-', '') + '.' + cfg.free_secret
    value = dict(tenant_id=cfg.tenant_id, plan='free', usage=free_usage())
    result = client.post(path, json={}, headers=headers)
    assert result.status_code == 200 and result.json()['plan'] == 'free'
    assert requests[-1].url.path == '/v1/free/usage'
    value['tenant_id'] = str(uuid4())
    assert client.post(path, json={}, headers=headers).status_code == 503
    before = len(requests)
    st.update_sensor(sensor['tenant_id'], sensor['id'], disabled=True)
    assert client.post(path, json={}, headers=headers).status_code == 403
    assert len(requests) == before


@pytest.mark.parametrize('stamp,expected', [('2028-03-01T00:00:00+00:00', '0'), ('2028-02-29T23:59:59+00:00', '29'), ('2027-01-01T12:00:00+00:00', '1')])
def test_paid_month_uses_utc_calendar_buckets_and_requires_complete_rated_data(monkeypatch, stamp, expected):
    from openaidr_api_client.contracts.credits import CreditSnapshot
    now = datetime.fromisoformat(stamp)
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return now
    monkeypatch.setattr(credits, 'datetime', Clock)
    value = paid_snapshot(str(uuid4()), now)
    assert credits.paid_usage(CreditSnapshot.model_validate(value))['used'] == expected
    if expected != '0':
        snapshot = CreditSnapshot.model_validate(value)
        snapshot.series[-1].unrated_operations = 1
        with pytest.raises(ValueError, match='not confirmed'):
            credits.paid_usage(snapshot)
        snapshot.series.pop()
        with pytest.raises(ValueError, match='Incomplete monthly credit buckets'):
            credits.paid_usage(snapshot)


def test_starter_and_google_allowances_are_explicit_and_bound_to_saved_connection(tmp_path):
    cfg = free_config(tmp_path)
    value = dict(tenant_id=cfg['tenant_id'], plan='free', policy='anonymous_trial',
                 usage={**free_usage(), 'resets_at': None})
    remote = httpx.MockTransport(lambda request: httpx.Response(200, json=value))
    result = desktop_credits.read(cfg, transport=remote)
    assert result['policy'] == 'anonymous_trial' and result['usage']['resets_at'] is None
    value['usage'].update(status='exhausted', allowance='0', used='0', reserved='0', available='0')
    assert desktop_credits.read(cfg, transport=remote)['usage']['status'] == 'exhausted'
    value.pop('policy')
    with pytest.raises(ValueError, match='Credit usage is unavailable'):
        desktop_credits.read(cfg, transport=remote)
    cfg.update(connection_mode='api_key', google_account={'email': 'user@example.com'})
    cfg.save()
    value = dict(tenant_id=cfg['tenant_id'], policy='google_weekly', usage=free_usage())
    calls = []
    def account(request):
        calls.append(request)
        assert request.url.path == '/v1/credits/allowance'
        assert request.headers['authorization'] == 'Bearer ' + cfg['sensor_token']
        return httpx.Response(200, json=value)
    result = desktop_credits.read(cfg, transport=httpx.MockTransport(account))
    assert result['policy'] == 'google_weekly' and result['plan'] == 'free'
    assert result['usage']['allowance'] == '200'
    for bad in ({**value, 'tenant_id': str(uuid4())}, {**value, 'policy': 'anonymous_trial'},
                {**value, 'usage': {**value['usage'], 'resets_at': None}}):
        with pytest.raises(ValueError, match='Credit usage is unavailable'):
            desktop_credits.read(cfg, transport=httpx.MockTransport(lambda request: httpx.Response(200, json=bad)))
