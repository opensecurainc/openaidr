"""Durable desktop pairing. Only verified credentials can replace a free connection."""

import asyncio
from datetime import datetime
import hashlib
import json
from pathlib import Path
import platform
import secrets
from uuid import UUID, uuid4

import httpx
from openaidr_api_client.client import TOKEN, Unavailable

from openaidr.core.files import atomic_write
from .config import Config, IDENTITY_FIELDS, configuration_lock
from .free_enrollment import ORIGIN, prepare

CONSOLE = 'https://console.opensecura.ai'
MESSAGE = 'Could not complete Google sign-in. Check your connection and try again.'


def saved(config, *, create=False):
    if config.get('connection_mode') != 'free' or config.get('disabled') or config.get('desktop_removal'):
        raise ValueError('Google sign-in requires this device\'s free connection.')
    enrollment = prepare(config)
    path = Path(config['data_dir']) / 'google-connection.json'
    try:
        with path.open(encoding='utf-8') as stream:
            value = json.loads(stream.read(4097))
        if (not isinstance(value, dict) or set(value) != {'request_id', 'installation_id', 'key', 'device_name'}
                or str(UUID(value['request_id'])) != value['request_id']
                or value['installation_id'] != enrollment.installation_id or not TOKEN.fullmatch(value['key'])
                or not isinstance(value['device_name'], str) or not 1 <= len(value['device_name']) <= 80
                or not value['device_name'].isprintable()):
            raise ValueError()
    except FileNotFoundError:
        if not create:
            raise ValueError('Start Google sign-in from this app first.') from None
        value = dict(request_id=str(uuid4()), installation_id=enrollment.installation_id,
                     key='oasc_' + uuid4().hex + '.' + secrets.token_urlsafe(32),
                     device_name=''.join(c for c in platform.node() if c.isprintable())[:80] or 'OpenAIDR desktop')
        atomic_write(path, json.dumps(value))
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError('The saved Google sign-in request is invalid. It was not replaced.') from None
    return enrollment, value, path


async def exchange(config, enrollment, value, *, start=False, transport=None):
    if transport is None:
        from . import network_proxy
        transport = network_proxy.async_transport(config, ORIGIN)
    path = '/v1/desktop/connections/' + ('start' if start else value['request_id'])
    payload = dict(request_id=value['request_id'], key_id=value['key'][5:37],
                   token_hash=hashlib.sha256(value['key'].encode()).hexdigest(),
                   device_name=value['device_name']) if start else None
    async with asyncio.timeout(10):
        async with httpx.AsyncClient(base_url=ORIGIN, transport=transport, trust_env=False, follow_redirects=False,
                timeout=10, headers={'Authorization': 'Bearer ' + enrollment.connection.api_key, 'Accept-Encoding': 'identity'}) as client:
            async with client.stream('POST' if start else 'GET', path, **({'json': payload} if start else {})) as response:
                if response.status_code != 200 or response.headers.get('content-encoding', 'identity') != 'identity':
                    raise ValueError(MESSAGE)
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 4096:
                        raise ValueError(MESSAGE)
    result = json.loads(body)
    if not isinstance(result, dict) or result.get('status') not in ('pending', 'approved', 'expired'):
        raise ValueError(MESSAGE)
    expires = datetime.fromisoformat(result['expires_at'].replace('Z', '+00:00'))
    if expires.tzinfo is None:
        raise ValueError(MESSAGE)
    public = dict(status=result['status'], expires_at=expires.isoformat())
    if result['status'] == 'approved':
        tenant, email = result['tenant_id'], result['email']
        if (result.get('key_id') != value['key'][5:37] or str(UUID(tenant)) != tenant
                or not isinstance(email, str) or not 3 <= len(email) <= 254 or '@' not in email or any(ord(c) < 32 for c in email)):
            raise ValueError(MESSAGE)
        public.update(tenant_id=tenant, email=email)
    if start:
        expected = CONSOLE + '/connect/?request=' + value['request_id']
        if result.get('verification_uri') != expected:
            raise ValueError(MESSAGE)
        public['verification_uri'] = expected
    return public


def request(config, *, start=False, transport=None):
    with configuration_lock(config.path):
        config = Config.load(config.path)
        enrollment, value, path = saved(config, create=start)
        try:
            result = asyncio.run(exchange(config, enrollment, value, start=start, transport=transport))
        except (httpx.HTTPError, TimeoutError, ValueError, KeyError, TypeError, AttributeError):
            raise ValueError(MESSAGE) from None
        if result['status'] == 'expired':
            # The server has confirmed this request can no longer grant a credential.
            path.unlink(missing_ok=True)
        return result


def activate(config, *, transport=None):
    with configuration_lock(config.path):
        config = Config.load(config.path)
        if config.get('connection_mode') == 'api_key' and config.get('google_account'):
            return {'enrolled': True, 'sensor_id': config['sensor_id'], 'connection_mode': 'api_key'}
        enrollment, value, _ = saved(config)
        try:
            approved = asyncio.run(exchange(config, enrollment, value, transport=transport))
            if approved['status'] != 'approved':
                raise ValueError(MESSAGE)
            from .api_key import verify
            if transport is None:
                from . import network_proxy
                transport = network_proxy.async_transport(config, ORIGIN)
            verified = asyncio.run(verify(value['key'], transport, approved['tenant_id']))
            if verified.tenant_id != approved['tenant_id']:
                raise ValueError(MESSAGE)
        except (Unavailable, httpx.HTTPError, TimeoutError, ValueError, KeyError, TypeError, AttributeError):
            raise ValueError(MESSAGE) from None
        candidate = Config(config.path, **{key: item for key, item in config.items() if key not in IDENTITY_FIELDS})
        candidate.update(connection_mode='api_key', auth_mode='bearer', server_url=ORIGIN,
            sensor_id=enrollment.device_id, sensor_token=value['key'], tenant_id=approved['tenant_id'],
            google_account={'email': approved['email'], 'request_id': value['request_id']})
        candidate.validate()
        candidate.save()
        return {'enrolled': True, 'sensor_id': enrollment.device_id, 'connection_mode': 'api_key'}
