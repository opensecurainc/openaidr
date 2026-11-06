"""Verify downloads and installation at the network and macOS process boundaries."""
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import sys
from types import SimpleNamespace

import httpx
import pytest

from openaidr.sensor import docker_setup as docker
from openaidr.sensor import local_runtime as runtime


@pytest.mark.parametrize('architecture', ['arm64', 'x86_64'])
@pytest.mark.parametrize('failure', ['', 'checksum', 'redirect', 'metadata'])
def test_download_requires_verified_vendor_image(tmp_path, monkeypatch, architecture, failure):
    content = b'vendor disk image'
    requests = []
    monkeypatch.setattr(docker.platform, 'machine', lambda: architecture)

    def respond(request):
        requests.append(str(request.url))
        if request.url.path.endswith('checksums.txt'):
            data = hashlib.sha256(content).hexdigest().encode() + b' *Docker.dmg\n'
            return httpx.Response(200, content=b'x' * 65537 if failure == 'metadata' else data)
        if failure == 'redirect':
            return httpx.Response(302, headers={'Location': 'https://other.example/image'})
        return httpx.Response(200, content=b'corrupt' if failure == 'checksum' else content)

    client = httpx.Client
    monkeypatch.setattr(docker.httpx, 'Client', lambda **kwargs: client(transport=httpx.MockTransport(respond), **kwargs))
    target = tmp_path / 'Docker.dmg'
    if failure:
        with pytest.raises(ValueError, match='Docker'):
            docker.download(target)
    else:
        docker.download(target)
        assert target.read_bytes() == content
    arch = 'arm64' if architecture == 'arm64' else 'amd64'
    assert all(url.startswith(f'https://desktop.docker.com/mac/main/{arch}/') for url in requests)
    assert len(requests) == (1 if failure == 'metadata' else 2)


@pytest.mark.parametrize('failure', ['', 'codesign', 'spctl', 'osascript'])
def test_install_verifies_before_authorization_and_cleans_up(tmp_path, monkeypatch, failure):
    config = SimpleNamespace(path=tmp_path / "data with ' quotes" / 'config.yaml')
    calls = []
    installed = False
    monkeypatch.setattr(docker.sys, 'platform', 'darwin')
    monkeypatch.setattr(docker.platform, 'machine', lambda: 'arm64')
    monkeypatch.setattr(docker, 'desktop', lambda: Path('/Applications/Docker.app') if installed else None)
    monkeypatch.setattr(docker, 'download', lambda target: target.write_bytes(b'verified image'))

    def execute(args, **kwargs):
        nonlocal installed
        calls.append(args)
        assert kwargs['stdin'] == subprocess.DEVNULL
        if Path(args[0]).name == failure:
            return subprocess.CompletedProcess(args, 1)
        if args[0] == '/usr/bin/osascript':
            installed = True
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(docker.subprocess, 'run', execute)
    if failure:
        with pytest.raises(ValueError, match='cancelled'):
            docker.start(config)
    else:
        docker.start(config)
    names = [Path(args[0]).name for args in calls]
    expected = ['hdiutil', 'codesign', 'spctl', 'osascript']
    assert names == (expected[:expected.index(failure) + 1] + ['hdiutil'] if failure else expected + ['hdiutil', 'open'])
    assert calls[0][2:][-1].startswith(str(config.path.parent / 'downloads'))
    assert '9BNSXJN65R' in calls[1][-2] and 'com.docker.docker' in calls[1][-2]
    assert calls[1][-2].startswith('=anchor ')
    if 'osascript' in names:
        mount = calls[0][-1]
        assert calls[names.index('osascript')][-1] == 'test ! -e /Applications/Docker.app && ' + shlex.join([str(Path(mount) / 'Docker.app/Contents/MacOS/install')])
    assert all('--accept-license' not in str(args) for args in calls)
    assert list((config.path.parent / 'downloads').iterdir()) == []


def test_existing_desktop_is_started_without_reinstallation(tmp_path, monkeypatch):
    monkeypatch.setattr(docker.sys, 'platform', 'darwin')
    monkeypatch.setattr(docker.platform, 'machine', lambda: 'arm64')
    app = tmp_path / 'Docker.app'
    monkeypatch.setattr(docker, 'desktop', lambda: app)
    monkeypatch.setattr(docker, 'download', lambda *_: pytest.fail('Do not replace installed Docker'))
    calls = []
    monkeypatch.setattr(docker.subprocess, 'run', lambda args, **kw: calls.append(args) or subprocess.CompletedProcess(args, 0))
    docker.start(SimpleNamespace(path=tmp_path / 'config.yaml'))
    assert calls == [['/usr/bin/open', '-a', str(app)]]
    monkeypatch.setattr(docker.sys, 'platform', 'win32')
    with pytest.raises(ValueError, match='Start the local Docker engine'):
        docker.start(None)
    assert len(calls) == 1


def test_gui_finds_docker_without_shell_path(tmp_path, monkeypatch):
    monkeypatch.setattr(docker.sys, 'platform', 'darwin')
    monkeypatch.setattr(docker.shutil, 'which', lambda _: None)
    monkeypatch.setattr(docker.Path, 'home', lambda: tmp_path)
    app = tmp_path / 'Docker.app'
    monkeypatch.setattr(docker, 'desktop', lambda: app)
    cli = app / 'Contents/Resources/bin/docker'
    cli.parent.mkdir(parents=True)
    cli.touch()
    assert docker.executable() == str(cli)
    user_cli = tmp_path / '.docker/bin/docker'
    user_cli.parent.mkdir(parents=True)
    user_cli.touch()
    assert docker.executable() == str(user_cli)


@pytest.mark.parametrize('path', ['/usr/bin:/bin:/usr/sbin:/sbin', None])
def test_gui_runtime_can_launch_docker_credential_helper(tmp_path, monkeypatch, path):
    monkeypatch.setattr(docker.sys, 'platform', 'darwin')
    app = tmp_path / 'Applications with spaces' / 'Docker.app'
    monkeypatch.setattr(docker, 'desktop', lambda: app)
    helper = app / 'Contents/Resources/bin' / ('docker-credential-desktop.exe' if os.name == 'nt' else 'docker-credential-desktop')
    helper.parent.mkdir(parents=True)
    helper.write_text('print("credential helper available")\n')
    helper.chmod(0o755)
    if path is None:
        monkeypatch.delenv('PATH', raising=False)
    else:
        monkeypatch.setenv('PATH', path)
    blocked = ('OPENAIDR_BIND_ADDRESS', 'COMPOSE_FILE', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY')
    for key in blocked:
        monkeypatch.setenv(key, 'must-not-reach-docker')
    output = runtime.run([sys.executable, '-c',
        'import os, shutil, subprocess, sys; '
        f'assert not any(key in os.environ for key in {blocked!r}); '
        'helper = shutil.which("docker-credential-desktop"); '
        'assert helper; subprocess.run([sys.executable, helper], check=True)'])
    assert output.strip() == 'credential helper available'
    assert os.environ.get('PATH') == path
