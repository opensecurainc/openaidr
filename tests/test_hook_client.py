"""Exercise the Windows forwarding client against the actual local sensor."""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

import httpx
import pytest

from openaidr.sensor import hooks
from openaidr.sensor.config import Config


CLIENT_ENTRY = """
import multiprocessing, os, sys
from types import SimpleNamespace
if __name__ == '__main__':
    multiprocessing.freeze_support()
    from openaidr.sensor import cli
    cli.os = SimpleNamespace(**(vars(os) | {'name': 'nt'}))
    result = cli.main()
    # Real forwarding must not load the service or either HTTP client stack.
    for name in ('openaidr.sensor.runtime', 'openaidr.sensor.hooks',
                 'openaidr.sensor.telemetry', 'httpx', 'psutil'):
        assert name not in sys.modules, name
    raise SystemExit(result)
"""


@pytest.fixture
def local_hook_sensor(tmp_path):
    # A short socket path also lets these TCP tests run on macOS.
    with tempfile.TemporaryDirectory(dir='/tmp' if os.name != 'nt' else None) as data:
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        config = Config(tmp_path / 'sensor.yaml', data_dir=data, listen=f'127.0.0.1:{port}',
                        telemetry={'local_token': 'test-account-token'})
        config.save()
        events = []
        server = hooks.HookServer(config['listen'], Path(data) / 'sensor.sock', events.append,
                                  lambda: {}, {}, token='test-account-token')
        stop = threading.Event()
        thread = threading.Thread(target=server.run, args=(stop,), daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            with httpx.Client(trust_env=False) as client:
                while True:
                    try:
                        response = client.get('http://' + config['listen'] + '/healthz',
                                              headers={'Authorization': 'Bearer test-account-token'})
                        assert response.status_code == 200
                        break
                    except httpx.TransportError:
                        assert time.monotonic() < deadline
                        time.sleep(0.01)
            yield config, server, events
        finally:
            stop.set()
            thread.join(5)
            assert not thread.is_alive()


def client_environment(*, age_ns=0, seconds=3):
    started = time.time_ns() - age_ns
    return {**{key: value for key, value in os.environ.items()
               if key not in ('OPENAIDR_MANAGED_BRIDGE', 'OPENAIDR_SENSOR_CONFIG')},
            'OPENAIDR_HOOK_TIMEOUT_OWNER': 'agent', 'OPENAIDR_HOOK_WRAPPED': '1',
            'OPENAIDR_HOOK_EXECUTION_ID': 'abcdef1234567890',
            'OPENAIDR_HOOK_STARTED_NS': str(started),
            'OPENAIDR_HOOK_DEADLINE_NS': str(started + seconds * 1_000_000_000),
            'HTTP_PROXY': 'http://127.0.0.1:1', 'ALL_PROXY': 'http://127.0.0.1:1',
            'PYTHONIOENCODING': 'utf-8'}


def hook_payload():
    return {'session_id': 'windows-client-test', 'tool_name': 'Bash',
            'tool_input': {'command': 'echo café 中文'}}


@pytest.mark.parametrize('seconds', [-1, 0, 2, 3, 4])
@pytest.mark.parametrize('action', ['allow', 'deny'])
def test_windows_sensor_preserves_original_agent_deadline(
    local_hook_sensor, backend_hook, monkeypatch, seconds, action,
):
    config, server, events = local_hook_sensor
    backend = backend_hook(action=action)
    server.check = backend
    now = time.time_ns()
    monkeypatch.setattr(hooks.time, 'time_ns', lambda: now)
    # A response at 2.5 seconds is timely only for the new three-second hook.
    started = now - 2_500_000_000
    response = httpx.post(
        'http://' + config['listen'] + '/v1/hooks/codex',
        params={'event': 'PreToolUse', 'timeout_owner': 'agent', 'started': started,
                'deadline': started + seconds * 1_000_000_000, 'execution': 'abcdef1234567890'},
        json=hook_payload(), headers={'Authorization': 'Bearer test-account-token'}, trust_env=False,
    )
    if seconds not in (2, 3):
        assert response.status_code == 400
        assert not backend.requests and not events
    else:
        assert response.status_code == 200 and len(backend.requests) == 1
        reply = response.json()
        if seconds == 2:
            assert reply['failed'] and reply['output'] == {}
            assert events[-1]['hook']['failure_reason'] == 'deadline_expired'
        else:
            assert not reply.get('failed')
            assert reply['decision'] == action
            assert bool(reply['output']) == (action == 'deny')


@pytest.mark.parametrize('agent', ['claude', 'codex'])
@pytest.mark.parametrize('seconds', [2, 3])
@pytest.mark.parametrize('case', ['allow', 'deny', 'allow_after_two_seconds', 'deny_after_two_seconds',
                                'shadow', 'backend_failure', 'unauthorized', 'late'])
def test_windows_client_preserves_policy_and_fails_open(local_hook_sensor, backend_hook, agent, seconds, case):
    config, server, events = local_hook_sensor
    backend = backend_hook(action='allow' if case.startswith('allow') else 'deny',
                           mode='shadow' if case == 'shadow' else 'enforce')
    after_two_seconds = case.endswith('_after_two_seconds')

    def check(request, deadline):
        if case == 'backend_failure':
            raise OSError('synthetic private error')
        if case == 'late':
            time.sleep(seconds + 0.05)
        elif after_two_seconds:
            time.sleep(2.1)
        return backend(request, deadline)

    server.check = check
    if case == 'unauthorized':
        config['telemetry']['local_token'] = 'wrong-token'
        config.save()
    result = subprocess.run(
        [sys.executable, '-c', CLIENT_ENTRY, 'hook', '--config', str(config.path),
         '--agent', agent, 'PreToolUse'],
        input=json.dumps(hook_payload()), capture_output=True, text=True, timeout=5,
        env=client_environment(seconds=seconds),
    )
    expired = case == 'late' or (after_two_seconds and seconds == 2)
    failed = case in ('backend_failure', 'unauthorized') or expired
    assert (result.returncode, result.stderr) == (int(failed), '')
    if case.startswith('deny') and not failed:
        assert json.loads(result.stdout)['hookSpecificOutput']['permissionDecision'] == 'deny'
    else:
        assert result.stdout == ''
    if case == 'unauthorized':
        assert server.stats['received'] == 0 and events == []
    elif expired:
        assert events[-1]['hook']['failure_reason'] == 'deadline_expired'
    elif not failed:
        assert len(backend.requests) == 1
        assert backend.requests[0]['path_home'] == str(Path.home())


@pytest.mark.parametrize('case', ['expired', 'invalid_deadline', 'nonlocal', 'oversized', 'malformed'])
def test_windows_client_rejects_invalid_input_without_output(local_hook_sensor, case):
    config, server, _ = local_hook_sensor
    env = client_environment(age_ns=3_000_000_000 if case == 'expired' else 0)
    if case == 'invalid_deadline':
        env['OPENAIDR_HOOK_DEADLINE_NS'] = str(int(env['OPENAIDR_HOOK_STARTED_NS']) + 10_000_000_000)
    if case == 'nonlocal':
        config['listen'] = '192.0.2.1:8377'
        config.save()
    body = 'x' * ((4 << 20) + 1) if case == 'oversized' else '{'
    result = subprocess.run(
        [sys.executable, '-c', CLIENT_ENTRY, 'hook', '--config', str(config.path), 'PreToolUse'],
        input=body, capture_output=True, text=True, timeout=3, env=env,
    )
    assert (result.returncode, result.stdout, result.stderr) == (1, '', '')
    assert server.stats['received'] == 0


def test_windows_client_resolves_result_capability_in_sensor(local_hook_sensor, backend_hook, monkeypatch):
    config, server, _ = local_hook_sensor
    server.check = backend_hook()
    checked = []
    monkeypatch.setattr(hooks, 'result_capable',
                        lambda cfg, agent, *, pid: checked.append((cfg['data_dir'], agent, pid)) or False)
    payload = {**hook_payload(), 'tool_response': 'result'}
    process = subprocess.Popen(
        [sys.executable, '-c', CLIENT_ENTRY, 'hook', '--config', str(config.path),
         '--agent', 'codex', 'PostToolUse'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=client_environment(),
    )
    stdout, stderr = process.communicate(json.dumps(payload), timeout=3)
    assert (process.returncode, stdout, stderr) == (0, '', '')
    assert checked == [(config['data_dir'], 'codex', process.pid)]
