"""Desktop-owned, loopback-only Compose runtime. Never changes another stack."""

import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import time
from uuid import UUID, uuid4

import httpx

from openaidr.core.files import atomic_write, durable_directory
from . import docker_setup
from .docker_setup import environment
from .config import configuration_lock

ORIGIN = "http://localhost:8080"
SOURCE = "ade7e73ea7b5661f41598e3026688ed5cb4ab60b"
SOURCE_TIME = "1793926234"
COMPATIBLE_SOURCES = (
    "4d52ae0063d7af8ec18267041f6fd66866d03d5b",
    "cb7471e3bf24b75451b4e89e7a0b78295d33bd7a",
)
ARCHIVE = Path(__file__).with_name("local_runtime_source.tar.gz")
ARCHIVE_SHA256 = "3a15376ed53682c1c5aa4727a49eaec14260764d579fafe8789eb3ac8f68c996"


def directory(config):
    return config.path.parent / "local-runtime"


def project(config):
    return "openaidr-desktop-" + hashlib.sha256(str(directory(config).resolve()).encode()).hexdigest()[:12]


def run(args, *, timeout=8, output=True):
    try:
        result = subprocess.run(args, env=environment(), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE if output else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        if result.returncode:
            raise ValueError("Docker could not complete the operation. Check Docker and your internet connection, then retry.")
        return result.stdout.decode() if output else ""
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("Docker is unavailable or did not finish in time. Start Docker with Compose, then retry.") from None


def saved_host(config, *, current_source=True):
    return state(config, current_source=current_source).get("docker_host") if (directory(config) / "state.json").exists() else None


def docker(config=None, *, current_source=True):
    executable = docker_setup.executable()
    if not executable:
        raise ValueError("Install Docker with Compose, then start Docker and check again.")
    bound = saved_host(config, current_source=current_source) if config else None
    endpoints = [bound] if bound else []
    if not bound:
        try:
            context = json.loads(run([executable, "context", "inspect"], timeout=3))
            endpoints.append(context[0]["Endpoints"]["docker"]["Host"])
        except (ValueError, KeyError, IndexError, TypeError):
            pass
        if docker_setup.action() == "start" and not (config and (directory(config) / "state.json").exists()):
            endpoints.append(docker_setup.desktop_host())
    for endpoint in endpoints:
        if not isinstance(endpoint, str) or not endpoint.startswith(("unix:///", "npipe:////./pipe/")):
            continue
        command = [executable, "--host", endpoint]
        try:
            run([*command, "info", "--format", "{{.ServerVersion}}"], timeout=3)
            run([*command, "compose", "version", "--short"], timeout=3)
            return command
        except ValueError:
            pass
    raise ValueError("Docker is not responding. Start a local Docker engine with Compose. A remote Docker engine cannot be used.")


def owned(config, command):
    ids = run([*command, "ps", "--filter", "label=com.docker.compose.project=" + project(config),
               "--filter", "label=com.docker.compose.service=dashboard", "--format", "{{.ID}}"])
    if not ids.strip():
        return False
    rows = json.loads(run([*command, "inspect", *ids.split()]))
    return any(row["State"]["Running"] and row["NetworkSettings"]["Ports"].get("3000/tcp") ==
               [{"HostIp": "127.0.0.1", "HostPort": "8080"}] for row in rows)


def reachable():
    try:
        with httpx.Client(trust_env=False, timeout=3) as client:
            response = client.get(ORIGIN + "/api/v1/auth/config")
            response.raise_for_status()
            return response.json().get("mode") == "local" and response.json().get("password_login") is True
    except (httpx.HTTPError, ValueError):
        return False


def connected(config):
    if not config.enrolled() or config.get("server_url") != ORIGIN:
        return False
    from .runtime import Client

    client = Client.from_config(config)
    try:
        client.post("version", {}, timeout=3)
        return True
    except httpx.HTTPError:
        return False
    finally:
        client.close()


def check(config):
    result = dict(docker_ready=False, docker_action="manual", existing=False, managed=False, connected=False, server_url=ORIGIN)
    try:
        bound = saved_host(config)
        if bound or not (directory(config) / "state.json").exists():
            result["docker_action"] = docker_setup.action(bound)
        command = docker(config)
        result.update(docker_ready=True, existing=reachable(), managed=owned(config, command))
        result["connected"] = result["existing"] and connected(config)
    except ValueError as error:
        result["message"] = str(error)
    except (KeyError, IndexError, TypeError):
        result["message"] = "Docker settings could not be read. Open Docker and finish its setup, then check again."
    return result


def prepare_docker(config):
    with configuration_lock(config.path.parent / "docker-setup"):
        current = check(config)
        if current["docker_ready"]:
            return current
        if current["docker_action"] == "manual":
            raise ValueError(current.get("message", "Start the local Docker engine, then check again."))
        docker_setup.start(config, saved_host(config))
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        current = check(config)
        if current["docker_ready"]:
            return current
        time.sleep(2)
    raise ValueError("Docker was opened but is not ready. Finish any setup prompts in Docker. If it remains unresponsive, restart Docker and retry.")


def state(config, *, current_source=True):
    try:
        value = json.loads((directory(config) / "state.json").read_text())
        if (current_source and value["source"] not in (SOURCE, *COMPATIBLE_SOURCES)) or not all(isinstance(v, str) and v and "\n" not in v for v in value["env"].values()):
            raise ValueError
        return value
    except (OSError, ValueError, KeyError, TypeError):
        raise ValueError("The saved local runtime configuration is unavailable. Restore it before retrying; existing data was kept.") from None


def compose(config, command, *args, timeout=1800):
    root = directory(config)
    return run([*command, "compose", "--project-directory", str(root / "source"),
                "--env-file", str(root / ".env"), "--project-name", project(config),
                "-f", str(root / "source/compose.yaml"), "-f", str(root / "desktop-compose.json"),
                *args], timeout=timeout, output=False)


def prepare(config):
    command = docker(config)
    root = durable_directory(directory(config))
    with configuration_lock(root / "state.json"):
        if reachable() and not owned(config, command):
            raise ValueError("A local runtime already exists. Connect with its administrator password; no runtime was replaced.")
        if not (root / "state.json").exists():
            if (root / "source").exists() or (root / ".env").exists():
                raise ValueError("Restore the saved runtime configuration before retrying. Existing files were kept.")
            device = config.path.parent / "free-device-id"
            if not device.exists():
                atomic_write(device, str(uuid4()))
            device_id = str(UUID(device.read_text().strip()))
            identity = dict(installation_id=str(uuid4()), device_id=device_id, secret=secrets.token_urlsafe(32))
            if config.get("connection_mode") == "free":
                from .free_enrollment import prepare as free_identity

                enrolled = free_identity(config)
                identity = dict(installation_id=enrolled.installation_id, device_id=enrolled.device_id, secret=enrolled.secret)
            atomic_write(root / "state.json", json.dumps(dict(source=SOURCE, docker_host=command[2], env={
                "POSTGRES_PASSWORD": secrets.token_hex(24), "OPENAIDR_ADMIN_EMAIL": "admin@localhost",
                "OPENAIDR_ADMIN_PASSWORD": secrets.token_urlsafe(24), "OPENAIDR_PUBLIC_URL": ORIGIN,
                "OPENAIDR_FREE_INSTALLATION_ID": identity["installation_id"], "OPENAIDR_FREE_DEVICE_ID": identity["device_id"],
                "OPENAIDR_FREE_SECRET": identity["secret"],
                "OPENAIDR_BUILD_COMMIT": SOURCE, "OPENAIDR_COMMIT_TIMESTAMP": SOURCE_TIME,
                "OPENAIDR_BIND_ADDRESS": "127.0.0.1", "OPENAIDR_PORT": "8080",
            })))
        saved = state(config)
        if not saved.get("docker_host"):
            saved["docker_host"] = command[2]
            atomic_write(root / "state.json", json.dumps(saved))
        if not (root / "source").exists():
            if hashlib.sha256(ARCHIVE.read_bytes()).hexdigest() != ARCHIVE_SHA256:
                raise ValueError("The bundled local runtime is damaged. Reinstall OpenAIDR before retrying.")
            if saved["source"] != SOURCE:
                saved["source"] = SOURCE
                saved["env"].update(OPENAIDR_BUILD_COMMIT=SOURCE, OPENAIDR_COMMIT_TIMESTAMP=SOURCE_TIME)
                atomic_write(root / "state.json", json.dumps(saved))
            with tempfile.TemporaryDirectory(dir=root) as temporary, tarfile.open(ARCHIVE) as archive:
                staging = Path(temporary) / "source"
                staging.mkdir()
                for member in archive:
                    path = Path(member.name)
                    if not member.isfile() or path.is_absolute() or ".." in path.parts:
                        raise ValueError("Invalid bundled runtime path")
                    target = staging / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.extractfile(member) as src, target.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
                os.replace(staging, root / "source")
        atomic_write(root / ".env", "".join(f"{k}={v}\n" for k, v in saved["env"].items()))
        # Scope image names as well as containers and volumes to this install.
        atomic_write(root / "desktop-compose.json", json.dumps({"services": {
            name: {"image": project(config) + ("-dashboard" if name == "dashboard" else "-server")}
            for name in ("bootstrap", "server", "dashboard")}}))
        compose(config, command, "build")
    return {"prepared": True}


def start(config, *, current_source=True):
    command = docker(config, current_source=current_source)
    with configuration_lock(directory(config) / "state.json"):
        state(config, current_source=current_source)
        if reachable() and not owned(config, command):
            raise ValueError("Another local runtime is using port 8080. It was not changed.")
        compose(config, command, "up", "-d", "--wait", "--wait-timeout", "180", timeout=240)
        deadline = time.monotonic() + 20
        while not reachable() and time.monotonic() < deadline:
            time.sleep(.5)
        if not owned(config, command) or not reachable():
            raise ValueError("The local dashboard is not responding yet. Retry setup; saved data is kept.")
    return {"running": True}


def cleanup(config, *, delete=False):
    """Stop or remove only this installation's Docker project, including stopped containers."""
    root = directory(config)
    if root.is_symlink():
        raise ValueError("The local runtime uses a linked folder. Restore its original folder before retrying uninstall.")
    if not root.exists():
        return
    if not (root / "state.json").exists():
        if any(path.name != "state.json.lock" for path in root.iterdir()):
            raise ValueError("Restore the saved local runtime configuration before retrying uninstall. Runtime data was kept.")
        return
    # Use project labels rather than Compose files, which can be incomplete after
    # interrupted setup. The saved engine and project remain valid across upgrades.
    command = docker(config, current_source=False)
    selector = ["--filter", "label=com.docker.compose.project=" + project(config)]
    containers = run([*command, "ps", "--all", "--quiet", *selector]).split()
    if containers:
        run([*command, "stop", "--time", "10", *containers], timeout=45, output=False)
    if run([*command, "ps", "--quiet", *selector]).strip():
        raise ValueError("The local runtime is still running. Retry uninstall before removing the app.")
    if not delete:
        return
    if containers:
        run([*command, "rm", *containers], timeout=15, output=False)
    for resource in ("volume", "network"):
        identifiers = run([*command, resource, "ls", "--quiet", *selector]).split()
        if identifiers:
            run([*command, resource, "rm", *identifiers], timeout=15, output=False)
    # Remove only our generated image tags. Shared images and build caches stay.
    for component in ("server", "dashboard"):
        name = project(config) + "-" + component + ":latest"
        if run([*command, "image", "ls", "--quiet", "--filter", "reference=" + name]).strip():
            run([*command, "image", "rm", name], timeout=15, output=False)


def credentials(config):
    saved = state(config, current_source=False)["env"]
    return {"email": saved["OPENAIDR_ADMIN_EMAIL"], "password": saved["OPENAIDR_ADMIN_PASSWORD"]}


def dashboard(config):
    """Give the native browser handoff a session, never the administrator password."""
    if not (directory(config) / "state.json").exists():
        return {"managed": False}
    if not owned(config, docker(config, current_source=False)) or not reachable():
        raise ValueError("Start your local runtime, then open the dashboard again.")
    with httpx.Client(base_url=ORIGIN, trust_env=False, timeout=15,
                      headers={"X-OpenAIDR-CSRF": "1"}) as client:
        try:
            response = client.post("/api/v1/auth/login", json=credentials(config))
            response.raise_for_status()
            # Use only the host-only session issued by this exact local origin.
            cookies = [cookie for cookie in client.cookies.jar
                       if cookie.name == "openaidr_session" and not cookie.domain_specified
                       and cookie.path == "/" and not cookie.secure]
            if len(cookies) != 1 or not cookies[0].value.startswith("oass_"):
                raise ValueError
            session = cookies[0].value
            if len(session) != 48 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in session):
                raise ValueError
        except (httpx.HTTPError, ValueError):
            raise ValueError("Could not sign in to your local dashboard. Use Show dashboard sign-in to check its saved credentials.") from None
    return {"managed": True, "session": session, "nonce": secrets.token_urlsafe(32)}


def connect(config, password=""):
    from . import bridge

    if not isinstance(password, str) or len(password) > 1024:
        raise ValueError("Enter a valid local administrator password.")
    command = docker(config)
    if not reachable():
        raise ValueError("Start the local runtime before connecting this device.")
    if connected(config):
        # A retry after a lost desktop reply must not consume another enrollment.
        return {"enrolled": True, "sensor_id": config["sensor_id"]}
    email = "admin@localhost"
    if not password and owned(config, command):
        login = credentials(config)
        email, password = login["email"], login["password"]
    if not password:
        raise ValueError("Enter the existing local runtime's administrator password.")
    with httpx.Client(base_url=ORIGIN, trust_env=False, timeout=15,
                      headers={"X-OpenAIDR-CSRF": "1"}) as client:
        try:
            response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
            response.raise_for_status()
            response = client.post("/api/v1/sensors/enrollment-links", json={
                "label": "Desktop local runtime", "expires_in_hours": 1, "max_uses": 1})
            response.raise_for_status()
            link = response.json()["enrollment_url"]
            from openaidr.core.enrollment import parse_enrollment_link

            if parse_enrollment_link(link)[0] != ORIGIN:
                raise ValueError("The local runtime returned a different server address. The current connection was kept.")
        except (httpx.HTTPError, KeyError):
            raise ValueError("Could not authenticate with the local runtime. Check its administrator password and retry.") from None
        finally:
            try:
                client.post("/api/v1/auth/logout")
            except httpx.HTTPError:
                pass
    preview = bridge.preview_enrollment(config, link)
    return bridge.connect_enrollment(config, {"link": link, "tenant_id": preview["tenant"]["id"]})
