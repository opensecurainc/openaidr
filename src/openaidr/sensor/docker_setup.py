"""Prepare Docker Desktop on macOS through Docker's signed installer."""

import hashlib
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

import httpx

from openaidr.core.files import durable_directory


def environment():
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('OPENAIDR_', 'COMPOSE_', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS'))}
    if sys.platform == 'darwin' and (app := desktop()):
        env['PATH'] = os.pathsep.join([env.get('PATH', os.defpath), str(app / 'Contents/Resources/bin')])
    return env


def desktop():
    return next((path for path in (Path('/Applications/Docker.app'), Path.home() / 'Applications/Docker.app')
                 if (path / 'Contents/Info.plist').is_file()), None)


def desktop_host():
    return 'unix://' + str(Path.home() / '.docker/run/docker.sock')


def executable():
    candidates = [shutil.which('docker'), str(Path.home() / '.docker/bin/docker')]
    if sys.platform == 'darwin' and (app := desktop()):
        candidates.append(str(app / 'Contents/Resources/bin/docker'))
    candidates.extend(['/usr/local/bin/docker', '/opt/homebrew/bin/docker',
                       str(Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Docker/Docker/resources/bin/docker.exe')])
    return next((str(path) for path in candidates if path and Path(path).is_file()), None)


def action(host=None):
    if sys.platform != 'darwin' or platform.machine() not in ('arm64', 'x86_64'):
        return 'manual'
    if host and host != desktop_host():
        return 'manual'
    return 'start' if desktop() else 'install'


def native(args, *, timeout=60):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout, env=environment())
        if result.returncode:
            raise ValueError('Docker setup was cancelled or could not finish. Retry setup to continue.')
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('Docker setup did not finish. Complete any Docker or macOS prompts, then retry.') from None


def download(target):
    architecture = {'arm64': 'arm64', 'x86_64': 'amd64'}[platform.machine()]
    origin = f'https://desktop.docker.com/mac/main/{architecture}/'
    deadline = time.monotonic() + 600
    digest = hashlib.sha256()
    size = 0
    try:
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=30,
                          headers={'Accept-Encoding': 'identity'}) as client:
            with client.stream('GET', origin + 'checksums.txt') as response:
                response.raise_for_status()
                checksums = bytearray()
                for chunk in response.iter_bytes(65536):
                    checksums.extend(chunk)
                    if len(checksums) > 65536 or time.monotonic() > deadline:
                        raise ValueError('Docker download verification is unavailable. Retry setup.')
            expected = re.findall(rb'^([a-f0-9]{64}) \*Docker\.dmg\r?$', checksums, re.M)
            if len(expected) != 1:
                raise ValueError('Docker download verification is unavailable. Retry setup.')
            with client.stream('GET', origin + 'Docker.dmg') as response, target.open('xb') as output:
                response.raise_for_status()
                for chunk in response.iter_bytes(1 << 20):
                    size += len(chunk)
                    if size > 2 << 30 or time.monotonic() > deadline:
                        raise ValueError('Docker download exceeded its limit. Check your connection and retry.')
                    output.write(chunk)
                    digest.update(chunk)
            if not size or digest.hexdigest().encode() != expected[0]:
                raise ValueError('Docker download could not be verified. Retry setup.')
    except (httpx.HTTPError, OSError):
        raise ValueError('Docker could not be downloaded. Check your connection and available disk space, then retry.') from None


def install(config):
    if desktop():
        return
    root = Path(tempfile.mkdtemp(prefix='docker-', dir=durable_directory(config.path.parent / 'downloads')))
    mount = root / 'installer'
    mount.mkdir()
    mounted = False
    try:
        image = root / 'Docker.dmg'
        download(image)
        if desktop():
            return
        mounted = True
        native(['/usr/bin/hdiutil', 'attach', str(image), '-readonly', '-nobrowse', '-noautoopen', '-mountpoint', str(mount)])
        app = mount / 'Docker.app'
        native(['/usr/bin/codesign', '--verify', '--deep', '--strict', '-R',
                '=anchor apple generic and identifier "com.docker.docker" and certificate leaf[subject.OU] = "9BNSXJN65R"', str(app)])
        native(['/usr/sbin/spctl', '--assess', '--type', 'execute', str(app)])
        # Keep Docker's terms in its own first-launch window. Never accept them silently.
        command = 'test ! -e /Applications/Docker.app && ' + shlex.join([str(app / 'Contents/MacOS/install')])
        if not desktop():
            native(['/usr/bin/osascript', '-e', 'on run argv', '-e',
                    'do shell script (item 1 of argv) with administrator privileges', '-e', 'end run', command], timeout=600)
        if not desktop():
            raise ValueError('Docker installation did not complete. Retry setup.')
    finally:
        if mounted:
            try:
                native(['/usr/bin/hdiutil', 'detach', str(mount)], timeout=30)
                mounted = False
            except ValueError:
                # Do not traverse or delete a mounted installer if macOS cannot eject it.
                mounted = mount.is_mount()
        if not mounted:
            shutil.rmtree(root)


def start(config, host=None):
    requested = action(host)
    if requested == 'manual':
        raise ValueError('Start the local Docker engine used by this runtime, then check again.')
    if requested == 'install':
        install(config)
    app = desktop()
    if not app:
        raise ValueError('Docker installation did not complete. Retry setup.')
    native(['/usr/bin/open', '-a', str(app)])
