#!/bin/bash
set -euo pipefail

if ! command -v python3 >/dev/null || ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
  echo "Install Python 3.11 or newer, then run setup.sh again." >&2
  exit 1
fi

OPENAIDR_SETUP_SOURCE="$0" python3 - "$@" <<'PY'
"""Install published OpenAIDR builds and open an authenticated local dashboard."""
import argparse
import errno
import hashlib
import http.cookiejar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener, urlopen

REPO = "opensecurainc/openaidr"
STATE = Path.home() / "Library/Application Support/OpenAIDR/local"
VERSION = re.compile(r"20[0-9]{2}\.[0-9]{1,2}\.[0-9]{1,2}\+[0-9a-f]{7,40}")
INSTALL_APP = """
on run argv
    set sourceApp to POSIX file (item 1 of argv) as alias
    set applicationsFolder to POSIX file (item 2 of argv) as alias
    tell application "Finder"
        duplicate sourceApp to applicationsFolder with replacing
    end tell
end run
"""


def run(args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def output(args, **kwargs):
    return run(args, stdout=subprocess.PIPE, **kwargs).stdout


def docker_ready(docker):
    try:
        return subprocess.run(docker + ["info"], timeout=10,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def open_public_url(url):
    request = Request(url, headers={"User-Agent": "OpenAIDR-setup"})
    try:
        return urlopen(request, timeout=60)
    except HTTPError as error:
        if error.code == 404:
            error.close()
            raise RuntimeError("OpenAIDR releases or source files are not publicly accessible. "
                               "Check that the repository and release are public, then run setup.sh again.") from error
        if error.code == 429 or (error.code == 403 and error.headers.get("X-RateLimit-Remaining") == "0"):
            error.close()
            raise RuntimeError("GitHub's public download rate limit was reached. Wait and run setup.sh again.") from error
        raise


def fetch_releases():
    releases = []
    page = 1
    while True:
        with open_public_url(f"https://api.github.com/repos/{REPO}/releases?per_page=100&page={page}") as response:
            items = json.load(response)
        releases.extend(items)
        if len(items) < 100:
            return releases
        page += 1


def release_assets(release):
    tag = release["tag_name"]
    names = ("build.json", "openaidr-backend.tar.gz", f"OpenAIDR_{tag}_aarch64.dmg", "client-release.json")
    assets = {item["name"]: item for item in release.get("assets", [])}
    if release.get("draft") or not VERSION.fullmatch(tag) or not all(name in assets for name in names):
        return None
    return [assets[name] for name in names]


def select_release(releases, tag=None):
    for release in sorted(releases, key=lambda item: item.get("published_at") or "", reverse=True):
        if (tag is None or release["tag_name"] == tag) and release_assets(release):
            return release
    raise RuntimeError("No complete full-client release is available. Build the current checkout using docs/guide.md#start-the-local-server.")


def digest(path):
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def download_asset(asset, directory):
    target = directory / asset["name"]
    expected = asset.get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected):
        raise RuntimeError(f"Release asset has no SHA-256 checksum: {target.name}")
    if target.is_file() and digest(target) == expected:
        return target
    with open_public_url(asset["browser_download_url"]) as response, target.open("wb") as stream:
        shutil.copyfileobj(response, stream)
    if digest(target) != expected:
        target.unlink()
        raise RuntimeError(f"Checksum mismatch: {target.name}. Run setup.sh again to retry.")
    return target


def read_build(path, tag):
    info = json.loads(path.read_text())
    if (info.get("version") != tag
            or not re.fullmatch(r"[0-9a-f]{40}", info.get("source_commit", ""))
            or type(info.get("source_timestamp")) is not int
            or info["source_timestamp"] <= 0
            or not info["source_commit"].startswith(tag.split("+")[1])):
        raise RuntimeError("The release build metadata does not match its tag.")
    return info


def read_client_release(path, info, assets):
    manifest = json.loads(path.read_text())
    expected = {asset["name"]: asset.get("digest", "") for asset in assets if asset["name"] != "client-release.json"}
    if (manifest.get("format") != 1 or manifest.get("product") != "openaidr-full-client"
            or manifest.get("source_commit") != info["source_commit"]
            or manifest.get("version") != info["version"]
            or not re.fullmatch(r"[0-9a-f]{64}", manifest.get("publication_sha256", ""))
            or any(manifest.get("assets", {}).get(name) != checksum for name, checksum in expected.items())):
        raise RuntimeError("The full-client release manifest does not match the selected artifacts.")
    return manifest


def available_dashboard_port(start=8080):
    for port in range(start, min(start + 20, 65536)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            try:
                listener.bind(("127.0.0.1", port))
                return port
            except OSError as error:
                if error.errno != errno.EADDRINUSE:
                    raise
    raise RuntimeError("No free dashboard port. Set OPENAIDR_PORT and OPENAIDR_PUBLIC_URL in the local .env.")


def prepare_config(directory, info, existing_env=None):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    env_file = directory / ".env"
    if not env_file.exists() and existing_env and existing_env.is_file():
        shutil.copyfile(existing_env, env_file)
    first_setup = not env_file.exists()
    if env_file.exists():
        env_file.chmod(0o600)
    for name in ("compose.yaml", "scripts/local_stack.py", "src/openaidr/build_info.py"):
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with open_public_url(f"https://raw.githubusercontent.com/{REPO}/{info['source_commit']}/{name}") as response:
            target.write_bytes(response.read())
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("OPENAIDR_") and key != "POSTGRES_PASSWORD"}
    env.update(OPENAIDR_BUILD_COMMIT=info["source_commit"],
               OPENAIDR_COMMIT_TIMESTAMP=str(info["source_timestamp"]),
               DOCKER_DEFAULT_PLATFORM="linux/amd64")
    run([sys.executable, directory / "scripts/local_stack.py", "configure"], env=env)
    if first_setup:
        port = available_dashboard_port()
        if port != 8080:
            content = env_file.read_text().replace("OPENAIDR_PUBLIC_URL=http://localhost:8080\n",
                                                   f"OPENAIDR_PUBLIC_URL=http://localhost:{port}\nOPENAIDR_PORT={port}\n")
            env_file.write_text(content)
            print(f"Port 8080 is in use. The dashboard will use http://localhost:{port}.", flush=True)
    return env


def local_settings(config):
    services = config["services"]
    settings = services["bootstrap"]["environment"]
    url = settings["OPENAIDR_PUBLIC_URL"]
    parsed = urlsplit(url)
    ports = services["dashboard"].get("ports", [])
    if (parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1")
            or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment
            or len(ports) != 1 or ports[0].get("host_ip") not in ("127.0.0.1", "::1")
            or int(ports[0]["published"]) != (parsed.port or 80)):
        raise RuntimeError("Automatic setup requires a loopback-only HTTP dashboard. Check the local .env.")
    command = services["bootstrap"]["command"]
    email = command[command.index("--email") + 1]
    return url, email, settings["OPENAIDR_ADMIN_PASSWORD"]


def wait_for_dashboard(url, timeout=180):
    client = build_opener(ProxyHandler({}))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            for path in ("/healthz", "/api/v1/auth/config"):
                with client.open(url + path, timeout=5) as response:
                    if response.status != 200:
                        raise RuntimeError("Dashboard is not ready.")
            return
        except (OSError, URLError, RuntimeError):
            time.sleep(2)
    raise RuntimeError("Dashboard startup timed out. Check the Docker Compose logs.")


def install_app(dmg, version, destination=Path("/Applications/OpenAIDR.app")):
    if destination.exists():
        with (destination / "Contents/Info.plist").open("rb") as stream:
            installed = plistlib.load(stream)
        if installed.get("CFBundleIdentifier") != "com.opensecura.openaidr.sensor":
            raise RuntimeError("A different app already exists at /Applications/OpenAIDR.app.")
        if installed.get("OpenAIDRVersion") == version:
            return destination
        if subprocess.run(["/usr/bin/pgrep", "-f", str(destination) + "/Contents/MacOS/"],
                          stdout=subprocess.DEVNULL).returncode == 0:
            raise RuntimeError("Quit OpenAIDR before replacing the installed app, then run setup.sh again.")
    mounted = plistlib.loads(output(["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-plist", dmg]))
    mounts = [Path(item["mount-point"]) for item in mounted["system-entities"] if "mount-point" in item]
    try:
        source = next((mount / "OpenAIDR.app" for mount in mounts if (mount / "OpenAIDR.app").is_dir()), None)
        if source is None:
            raise RuntimeError("The installer does not contain OpenAIDR.app.")
        with (source / "Contents/Info.plist").open("rb") as stream:
            info = plistlib.load(stream)
        if info.get("OpenAIDRVersion") != version or info.get("CFBundleIdentifier") != "com.opensecura.openaidr.sensor":
            raise RuntimeError("The desktop app does not match the selected release.")
        run(["/usr/bin/osascript", "-", source, destination.parent], input=INSTALL_APP.encode())
    finally:
        for mount in mounts:
            subprocess.run(["/usr/bin/hdiutil", "detach", str(mount)], check=False)
    return destination


def authenticate(url, email, password):
    cookies = http.cookiejar.CookieJar()
    client = build_opener(ProxyHandler({}), HTTPCookieProcessor(cookies))
    request = Request(url + "/api/v1/auth/login",
                      data=json.dumps({"email": email, "password": password}).encode(),
                      headers={"Content-Type": "application/json", "X-OpenAIDR-CSRF": "1", "Origin": url})
    with client.open(request, timeout=15) as response:
        headers = response.headers.get_all("Set-Cookie", [])
    if not headers or not any(cookie.name == "openaidr_session" for cookie in cookies):
        raise RuntimeError("The server did not return a dashboard session.")
    return client, headers


def open_dashboard(url, cookies, timeout=60):
    # Cookies are scoped by host, not port. Transfer the normal HttpOnly cookie
    # from a one-use loopback URL, then redirect to the existing dashboard.
    claimed = threading.Event()
    claim_lock = threading.Lock()
    nonce = "/" + secrets.token_urlsafe(32)
    hostname = urlsplit(url).hostname

    class Handoff(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(5)
            super().setup()

        def log_message(self, *_args):
            pass

        def do_GET(self):
            with claim_lock:
                valid = (self.headers.get("Host") == address and self.path == nonce
                         and self.headers.get("Origin", origin) == origin
                         and self.headers.get("Sec-Fetch-Site", "none") in ("none", "same-origin")
                         and not claimed.is_set() and time.monotonic() < deadline)
                self.send_response(303 if valid else 404)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Length", "0")
                if valid:
                    for cookie in cookies:
                        self.send_header("Set-Cookie", cookie)
                    self.send_header("Location", url + "/")
                self.end_headers()
                if valid:
                    claimed.set()

    with ThreadingHTTPServer(("127.0.0.1", 0), Handoff) as server:
        address = f"{hostname}:{server.server_port}"
        origin = "http://" + address
        deadline = time.monotonic() + timeout
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            run(["/usr/bin/open", origin + nonce])
            return claimed.wait(timeout)
        finally:
            server.shutdown()
            thread.join()


def main():
    parser = argparse.ArgumentParser(prog="setup.sh", description=__doc__)
    parser.add_argument("release", nargs="?", help="release tag; defaults to the newest complete full-client release")
    args = parser.parse_args()
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        raise RuntimeError("This installer requires an Apple Silicon Mac.")
    if os.geteuid() == 0:
        raise RuntimeError("Run setup.sh as your normal macOS user, without sudo.")
    docker_app = next((path for path in (Path("/Applications/Docker.app"), Path.home() / "Applications/Docker.app")
                       if path.is_dir()), None)
    if docker_app is None:
        raise RuntimeError("Install Docker Desktop, then run setup.sh again.")
    docker = [str(docker_app / "Contents/Resources/bin/docker"), "--context", "desktop-linux"]
    print("Checking published OpenAIDR releases...", flush=True)
    release = select_release(fetch_releases(), args.release)
    tag = release["tag_name"]
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    STATE.chmod(0o700)
    downloads = STATE / "downloads" / tag
    downloads.mkdir(parents=True, exist_ok=True)
    print(f"Downloading and verifying {tag}...", flush=True)
    assets = [download_asset(asset, downloads) for asset in release_assets(release)]
    info = read_build(assets[0], tag)
    read_client_release(assets[3], info, release_assets(release))
    if not docker_ready(docker):
        print("Starting Docker Desktop. Complete its first-run prompts if shown...", flush=True)
        run(["/usr/bin/open", "-a", docker_app])
        deadline = time.monotonic() + 180
        while not docker_ready(docker):
            if time.monotonic() >= deadline:
                raise RuntimeError("Docker Desktop did not become ready. Finish its setup and try again.")
            time.sleep(2)
    run(docker + ["compose", "version"])
    existing_env = Path(os.environ["OPENAIDR_SETUP_SOURCE"]).resolve().parent / ".env"
    if not (STATE / ".env").exists() and not existing_env.is_file():
        if subprocess.run(docker + ["volume", "inspect", "openaidr_database"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            raise RuntimeError(f"An OpenAIDR database already exists. Copy its original .env to {STATE / '.env'} and retry.")
    env = prepare_config(STATE, info, existing_env)
    compose = docker + ["compose", "--project-directory", str(STATE), "--env-file", str(STATE / ".env"),
                        "-f", str(STATE / "compose.yaml"), "-p", "openaidr"]
    config = json.loads(output(compose + ["config", "--format", "json"], env=env))
    url, email, password = local_settings(config)
    print("Loading the published images and starting the local server...", flush=True)
    run(docker + ["load", "-i", assets[1]])
    run(compose + ["pull", "db"], env=env)
    run(compose + ["up", "-d", "--no-build", "--pull", "never"], env=env)
    wait_for_dashboard(url)
    print("Installing OpenAIDR in Applications. Allow Finder automation if macOS asks...", flush=True)
    app = install_app(assets[2], tag)
    run(["/usr/bin/open", app])
    try:
        client, cookies = authenticate(url, email, password)
    except (HTTPError, URLError, RuntimeError):
        print(f"Automatic sign-in failed. Sign in at {url} with your existing account. Credentials: {STATE / '.env'}")
        run(["/usr/bin/open", url + "/login"])
        return
    transferred = False
    try:
        transferred = open_dashboard(url, cookies)
    finally:
        if not transferred:
            try:
                with client.open(Request(url + "/api/v1/auth/logout", data=b"{}",
                                         headers={"Content-Type": "application/json", "X-OpenAIDR-CSRF": "1"}), timeout=5):
                    pass
            except (OSError, URLError):
                pass
    if not transferred:
        print(f"Browser sign-in timed out. Open {url} and use the credentials in {STATE / '.env'}.")
    else:
        print(f"Dashboard opened at {url}. Create an App Enrollment link there and paste it into OpenAIDR.")
    print(f"Local configuration and credentials: {STATE / '.env'}")


if __name__ == "__main__":
    os.umask(0o077)
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Setup failed: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nSetup interrupted. Run setup.sh again to continue.", file=sys.stderr)
        sys.exit(130)
PY
