"""Installer boundaries, runnable with unittest without project dependencies."""
import base64
import contextlib
import copy
import hashlib
import http.cookiejar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import plistlib
import runpy
import socket
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "setup.sh").read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
setup = types.ModuleType("openaidr_setup")
exec(compile(source, str(ROOT / "setup.sh"), "exec"), setup.__dict__)
TAG = "2026.10.20+97107e2"
INFO = {
    "version": TAG,
    "source_commit": "97107e22775950e6c943afc8222869015f16285b",
    "source_timestamp": 1792483050,
    "built_at": "2026-10-20T08:00:06+00:00",
}


def release(tag=TAG):
    return {
        "tag_name": tag, "published_at": "2026-10-20T08:00:39Z", "prerelease": True,
        "assets": [{"name": name,
                    "browser_download_url": f"https://github.com/{setup.REPO}/releases/download/{tag}/{name}"} for name in
                   ("build.json", "openaidr-backend.tar.gz", f"OpenAIDR_{tag}_aarch64.dmg", "client-release.json")],
    }


def compose_config():
    return {"services": {
        "bootstrap": {"command": ["bootstrap", "--email", "admin@localhost"],
                      "environment": {"OPENAIDR_PUBLIC_URL": "http://localhost:8080",
                                      "OPENAIDR_ADMIN_PASSWORD": "private-password"}},
        "dashboard": {"ports": [{"host_ip": "127.0.0.1", "published": "8080", "target": 3000}]},
    }}


class Releases(unittest.TestCase):
    def test_public_requests_follow_redirects_without_authentication(self):
        seen = []

        class Downloads(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                seen.append((self.path, self.headers.get("Authorization"), self.headers.get("User-Agent")))
                self.send_response(302 if self.path == "/download" else 200)
                if self.path == "/download":
                    self.send_header("Location", "/asset")
                self.end_headers()
                if self.path == "/asset":
                    self.wfile.write(b"public artifact")

        with ThreadingHTTPServer(("127.0.0.1", 0), Downloads) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                with patch.dict(os.environ, {"GH_TOKEN": "unused", "GITHUB_TOKEN": "unused"}), \
                     setup.open_public_url(f"http://127.0.0.1:{server.server_port}/download") as response:
                    self.assertEqual(response.read(), b"public artifact")
                self.assertEqual(seen, [("/download", None, "OpenAIDR-setup"), ("/asset", None, "OpenAIDR-setup")])
            finally:
                server.shutdown()
                thread.join()

    def test_public_rate_limit_explains_retry_and_other_http_errors_propagate(self):
        for status, headers, limited in ((403, {"X-RateLimit-Remaining": "0"}, True),
                                         (429, {}, True), (403, {}, False), (500, {}, False)):
            error = HTTPError("https://api.github.com/releases", status, "error", headers, io.BytesIO())
            with self.subTest(status=status, headers=headers), \
                 patch.object(setup, "urlopen", side_effect=error):
                if limited:
                    with self.assertRaisesRegex(RuntimeError, "rate limit.*Wait and run setup.sh again"):
                        setup.open_public_url(error.url)
                else:
                    with self.assertRaises(HTTPError) as caught:
                        setup.open_public_url(error.url)
                    self.assertIs(caught.exception, error)
            error.close()

    def test_unavailable_public_releases_and_source_have_actionable_errors(self):
        checks = (
            (f"https://api.github.com/repos/{setup.REPO}/releases?per_page=100&page=1",
             lambda directory: setup.fetch_releases()),
            (f"https://raw.githubusercontent.com/{setup.REPO}/{INFO['source_commit']}/compose.yaml",
             lambda directory: setup.prepare_config(directory, INFO)),
        )
        for url, check in checks:
            error = HTTPError(url, 404, "Not Found", {}, io.BytesIO())
            with self.subTest(url=url), tempfile.TemporaryDirectory() as directory, \
                 patch.object(setup, "urlopen", side_effect=error) as request:
                with self.assertRaisesRegex(RuntimeError, "not publicly accessible.*repository and release are public"):
                    check(Path(directory))
                self.assertEqual(request.call_args.args[0].full_url, url)
            error.close()

    def test_release_pagination_includes_older_complete_releases(self):
        incomplete = release("2026.10.21+abcdef0")
        incomplete["assets"].pop()
        complete = release()
        pages = [io.BytesIO(json.dumps(page).encode()) for page in ([incomplete] * 100, [complete])]
        with patch.object(setup, "open_public_url", side_effect=pages) as fetch:
            releases = setup.fetch_releases()
        self.assertEqual(len(releases), 101)
        self.assertEqual(setup.select_release(releases), complete)
        self.assertEqual(setup.select_release(releases, TAG), complete)
        self.assertEqual([call.args[0] for call in fetch.call_args_list],
                         [f"https://api.github.com/repos/{setup.REPO}/releases?per_page=100&page={page}"
                          for page in (1, 2)])

    def test_newest_complete_prerelease_is_used(self):
        complete = release()
        incomplete = release("2026.10.20+abcdef0")
        incomplete["published_at"] = "2026-10-21T00:00:00Z"
        incomplete["assets"].pop()
        draft = copy.deepcopy(complete)
        draft["draft"] = True
        draft["published_at"] = "2026-10-22T00:00:00Z"
        self.assertIs(setup.select_release([draft, incomplete, complete]), complete)
        with self.assertRaisesRegex(RuntimeError, "No complete full-client release"):
            setup.select_release([incomplete, complete], incomplete["tag_name"])

    def test_reduced_releases_are_rejected_even_when_explicit(self):
        old = release()
        old["assets"] = [asset for asset in old["assets"] if asset["name"] != "client-release.json"]
        for tag in (None, old["tag_name"]):
            with self.assertRaisesRegex(RuntimeError, "full-client"):
                setup.select_release([old], tag)

    def test_manifest_binds_full_client_and_artifact_digests(self):
        assets = [{"name": name, "digest": "sha256:" + "a" * 64} for name in
                  ("build.json", "openaidr-backend.tar.gz", f"OpenAIDR_{TAG}_aarch64.dmg")]
        good = dict(format=1, product="openaidr-full-client", source_commit=INFO["source_commit"], version=TAG,
                    publication_sha256="b" * 64, assets={asset["name"]: asset["digest"] for asset in assets})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "client-release.json"
            path.write_text(json.dumps(good))
            self.assertEqual(setup.read_client_release(path, INFO, assets), good)
            for change in ({"product": "reduced"}, {"source_commit": "f" * 40}, {"assets": {}}):
                path.write_text(json.dumps({**good, **change}))
                with self.assertRaisesRegex(RuntimeError, "manifest"):
                    setup.read_client_release(path, INFO, assets)

    def test_asset_checksum_controls_download_reuse(self):
        content = b"published artifact"
        asset = {"name": "openaidr-backend.tar.gz",
                 "browser_download_url": "https://github.com/public/artifact",
                 "digest": "sha256:" + hashlib.sha256(content).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            path = directory / asset["name"]
            path.write_bytes(b"interrupted download")
            with patch.object(setup, "open_public_url", return_value=io.BytesIO(content)) as download:
                self.assertEqual(setup.download_asset(asset, directory), path)
                setup.download_asset(asset, directory)
                download.assert_called_once_with(asset["browser_download_url"])
            path.write_bytes(b"corrupted download")
            with patch.object(setup, "open_public_url", return_value=io.BytesIO(b"corrupted download")), \
                 self.assertRaisesRegex(RuntimeError, "Checksum mismatch"):
                setup.download_asset(asset, directory)
            self.assertFalse(path.exists())
            with self.assertRaisesRegex(RuntimeError, "no SHA-256"):
                setup.download_asset({"name": path.name}, directory)

    def test_build_metadata_must_match_release(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build.json"
            path.write_text(json.dumps(INFO))
            self.assertEqual(setup.read_build(path, TAG), INFO)
            for changed in ({"version": "2026.10.20+abcdef0"},
                            {"source_commit": "f" * 40}, {"source_timestamp": True}):
                path.write_text(json.dumps({**INFO, **changed}))
                with self.assertRaisesRegex(RuntimeError, "does not match"):
                    setup.read_build(path, TAG)


class Configuration(unittest.TestCase):
    def test_device_id_is_random_private_and_stable_across_workspaces(self):
        helper = runpy.run_path(str(ROOT / 'scripts/local_stack.py'))['free_device_id']
        with tempfile.TemporaryDirectory() as directory, \
             patch('pathlib.Path.home', return_value=Path(directory)), \
             patch.dict(os.environ, {'LOCALAPPDATA': directory, 'XDG_CONFIG_HOME': directory}):
            first = helper()
            self.assertEqual(helper(), first)
            from uuid import UUID
            self.assertEqual(UUID(first).version, 4)
            files = list(Path(directory).rglob('free-device-id'))
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)

    def test_local_configuration_preserves_credentials_without_creating_knowledge_keys(self):
        name = "OPENAIDR_KNOWLEDGE_MCP_KEY"
        existing = base64.urlsafe_b64encode(b"x" * 32).decode()
        env = {key: value for key, value in os.environ.items() if not key.startswith("OPENAIDR_")}
        env.update(OPENAIDR_BUILD_COMMIT=INFO["source_commit"], OPENAIDR_COMMIT_TIMESTAMP=str(INFO["source_timestamp"]))
        for initial in ("", name + "=\n", name + "=  \n", name + "=" + existing + "\n"):
            with self.subTest(initial=initial), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for relative in ("scripts/local_stack.py", "src/openaidr/build_info.py"):
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes((ROOT / relative).read_bytes())
                config = root / ".env"
                config.write_text("POSTGRES_PASSWORD=keep-database-password\n" + initial)
                command = [sys.executable, str(root / "scripts/local_stack.py"), "configure"]
                result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                before = config.read_text()
                keys = [line.split("=", 1)[1] for line in before.splitlines() if line.startswith(name + "=")]
                self.assertEqual(keys, [initial.split("=", 1)[1].rstrip("\n")] if initial else [])
                if existing in initial:
                    self.assertEqual(keys[0], existing)
                self.assertIn("POSTGRES_PASSWORD=keep-database-password\n", before)
                self.assertNotIn(existing, result.stdout + result.stderr)
                result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(config.read_text(), before)

    def test_new_workspace_generates_and_preserves_private_free_identity(self):
        env = {key: value for key, value in os.environ.items() if not key.startswith("OPENAIDR_")}
        env.update(OPENAIDR_BUILD_COMMIT=INFO["source_commit"], OPENAIDR_COMMIT_TIMESTAMP=str(INFO["source_timestamp"]))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env.update(HOME=str(root / 'profile'), LOCALAPPDATA=str(root / 'profile'),
                       XDG_CONFIG_HOME=str(root / 'profile'))
            for relative in ("scripts/local_stack.py", "src/openaidr/build_info.py"):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            command = [sys.executable, str(root / "scripts/local_stack.py"), "configure"]
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            path = root / ".env"
            before = path.read_text()
            fields = dict(line.split("=", 1) for line in before.splitlines())
            for field in ("INSTALLATION_ID", "DEVICE_ID", "SECRET"):
                self.assertTrue(fields["OPENAIDR_FREE_" + field])
                self.assertNotIn(fields["OPENAIDR_FREE_" + field], result.stdout + result.stderr)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(path.read_text(), before)

    def test_port_selection_skips_an_existing_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            occupied = listener.getsockname()[1]
            selected = setup.available_dashboard_port(occupied)
            self.assertGreater(selected, occupied)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", selected))

    def test_first_setup_saves_free_port_and_reruns_keep_it(self):
        def source_file(url):
            name = url.split(INFO["source_commit"] + "/", 1)[1]
            return io.BytesIO((ROOT / name).read_bytes())

        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {'HOME': directory, 'LOCALAPPDATA': directory, 'XDG_CONFIG_HOME': directory}), \
             patch.object(setup, "open_public_url", side_effect=source_file), \
             patch.object(setup, "available_dashboard_port", return_value=8082) as select_port:
            state = Path(directory)
            setup.prepare_config(state, INFO)
            before = (state / ".env").read_bytes()
            self.assertIn(b"OPENAIDR_PUBLIC_URL=http://localhost:8082\n", before)
            self.assertIn(b"OPENAIDR_PORT=8082\n", before)
            setup.prepare_config(state, INFO)
            self.assertEqual((state / ".env").read_bytes(), before)
            select_port.assert_called_once()

    def test_slow_docker_startup_does_not_block_readiness_forever(self):
        with patch.object(setup.subprocess, "run", side_effect=subprocess.TimeoutExpired("docker info", 10)):
            self.assertFalse(setup.docker_ready(["docker"]))

    def test_uses_release_source_and_preserves_existing_credentials(self):
        def source_file(url):
            prefix = f"https://raw.githubusercontent.com/{setup.REPO}/{INFO['source_commit']}/"
            self.assertTrue(url.startswith(prefix))
            return io.BytesIO((ROOT / url.removeprefix(prefix)).read_bytes())

        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            original = directory / ".env"
            original.write_text("POSTGRES_PASSWORD=existing-database-password\n"
                                "OPENAIDR_ADMIN_PASSWORD=existing-admin-password\n"
                                "OPENAIDR_ADMIN_EMAIL=admin@localhost\n"
                                "OPENAIDR_PUBLIC_URL=http://localhost:8080\n")
            state = directory / "state with spaces"
            with patch.object(setup, "open_public_url", side_effect=source_file):
                env = setup.prepare_config(state, INFO, original)
                before = (state / ".env").read_bytes()
                original.write_text("must not overwrite the saved credentials")
                setup.prepare_config(state, INFO, original)
            self.assertEqual((state / ".env").read_bytes(), before)
            self.assertIn(b"existing-admin-password", before)
            self.assertIn(b"existing-database-password", before)
            self.assertIn(INFO["source_commit"].encode(), before)
            self.assertEqual((state / ".env").stat().st_mode & 0o777, 0o600)
            self.assertEqual(state.stat().st_mode & 0o777, 0o700)
            self.assertEqual(env["DOCKER_DEFAULT_PLATFORM"], "linux/amd64")

    def test_automatic_login_requires_local_binding_and_matching_origin(self):
        config = compose_config()
        self.assertEqual(setup.local_settings(config),
                         ("http://localhost:8080", "admin@localhost", "private-password"))
        for url in ("https://localhost:8080", "http://example.com:8080",
                    "http://user@localhost:8080", "http://localhost:8081", "http://localhost:8080/path"):
            changed = copy.deepcopy(config)
            changed["services"]["bootstrap"]["environment"]["OPENAIDR_PUBLIC_URL"] = url
            with self.assertRaisesRegex(RuntimeError, "loopback-only"):
                setup.local_settings(changed)
        config["services"]["dashboard"]["ports"][0]["host_ip"] = "0.0.0.0"
        with self.assertRaisesRegex(RuntimeError, "loopback-only"):
            setup.local_settings(config)


class DesktopInstall(unittest.TestCase):
    def test_apple_script_receives_paths_as_arguments_and_disk_is_detached(self):
        with tempfile.TemporaryDirectory(prefix="openaidr ' ") as directory:
            directory = Path(directory)
            mount = directory / "mounted disk"
            source_app = mount / "OpenAIDR.app"
            contents = source_app / "Contents"
            contents.mkdir(parents=True)
            (contents / "Info.plist").write_bytes(plistlib.dumps({
                "OpenAIDRVersion": TAG, "CFBundleIdentifier": "com.opensecura.openaidr.sensor",
            }))
            destination = directory / "Applications/OpenAIDR.app"
            mounted = plistlib.dumps({"system-entities": [{"mount-point": str(mount)}]})
            for canceled in (False, True):
                with self.subTest(canceled=canceled), \
                     patch.object(setup, "output", return_value=mounted), \
                     patch.object(setup, "run") as install, \
                     patch.object(setup.subprocess, "run") as detach:
                    if canceled:
                        install.side_effect = subprocess.CalledProcessError(1, "osascript")
                        with self.assertRaises(subprocess.CalledProcessError):
                            setup.install_app(directory / "app.dmg", TAG, destination)
                    else:
                        self.assertEqual(setup.install_app(directory / "app.dmg", TAG, destination), destination)
                    self.assertEqual(install.call_args.args[0],
                                     ["/usr/bin/osascript", "-", source_app, destination.parent])
                    self.assertNotIn(str(directory), install.call_args.kwargs["input"].decode())
                    detach.assert_called_once_with(["/usr/bin/hdiutil", "detach", str(mount)], check=False)


class BrowserLogin(unittest.TestCase):
    def test_login_transfers_http_only_cookie_once_and_rejects_other_requests(self):
        seen = []

        class Backend(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append((data, self.headers.get("X-OpenAIDR-CSRF"), self.headers.get("Origin")))
                self.send_response(200)
                self.send_header("Set-Cookie", "openaidr_session=test-session; Path=/; HttpOnly; SameSite=Lax")
                self.end_headers()

            def do_GET(self):
                self.send_response(200 if self.headers.get("Cookie") == "openaidr_session=test-session" else 401)
                self.end_headers()

        with ThreadingHTTPServer(("127.0.0.1", 0), Backend) as backend:
            thread = threading.Thread(target=backend.serve_forever)
            thread.start()
            try:
                url = f"http://localhost:{backend.server_port}"
                _client, headers = setup.authenticate(url, "admin@localhost", "private-password")
                self.assertEqual(seen, [({"email": "admin@localhost", "password": "private-password"}, "1", url)])
                browser_cookies = http.cookiejar.CookieJar()
                browser = build_opener(ProxyHandler({}), HTTPCookieProcessor(browser_cookies))

                def open_browser(args):
                    link = args[1]
                    self.assertNotIn("private-password", link)
                    self.assertNotIn("test-session", link)
                    for request in (Request(link + "-wrong"),
                                    Request(link, headers={"Host": "evil.test"}),
                                    Request(link, headers={"Origin": "http://evil.test"}),
                                    Request(link, headers={"Sec-Fetch-Site": "cross-site"})):
                        with self.assertRaises(HTTPError) as error:
                            browser.open(request)
                        self.assertEqual(error.exception.code, 404)
                        self.assertIsNone(error.exception.headers.get("Set-Cookie"))
                        error.exception.close()
                    with browser.open(link) as result:
                        self.assertEqual(result.url, url + "/")
                        self.assertEqual(result.status, 200)
                    with self.assertRaises(HTTPError) as replay:
                        browser.open(link)
                    self.assertEqual(replay.exception.code, 404)
                    replay.exception.close()

                with patch.object(setup, "run", side_effect=open_browser):
                    self.assertTrue(setup.open_dashboard(url, headers, timeout=5))
                cookie = next(iter(browser_cookies))
                self.assertEqual(cookie.name, "openaidr_session")
                self.assertTrue(cookie.has_nonstandard_attr("HttpOnly"))
            finally:
                backend.shutdown()
                thread.join()

    def test_unused_login_handoff_expires(self):
        with patch.object(setup, "run"):
            self.assertFalse(setup.open_dashboard("http://localhost:8080", ["openaidr_session=unused"], timeout=0.01))


class SetupFlow(unittest.TestCase):
    def test_repeat_setup_without_github_cli_loads_images_without_building_or_resetting_credentials(self):
        current_release = release()
        payloads = {
            "build.json": json.dumps(INFO).encode(),
            "openaidr-backend.tar.gz": b"backend image archive",
            f"OpenAIDR_{TAG}_aarch64.dmg": b"macOS installer",
        }
        payloads["client-release.json"] = json.dumps(dict(
            format=1, product="openaidr-full-client", source_commit=INFO["source_commit"], version=TAG,
            publication_sha256="b" * 64,
            assets={name: "sha256:" + hashlib.sha256(content).hexdigest() for name, content in payloads.items()},
        )).encode()
        for asset in current_release["assets"]:
            asset["digest"] = "sha256:" + hashlib.sha256(payloads[asset["name"]]).hexdigest()
        commands = []
        requests = []
        real_run = setup.run
        real_is_dir = Path.is_dir

        def public_response(request, **kwargs):
            url = request.full_url
            requests.append(url)
            self.assertIsNone(request.get_header("Authorization"))
            self.assertEqual(kwargs["timeout"], 60)
            prefix = f"https://raw.githubusercontent.com/{setup.REPO}/{INFO['source_commit']}/"
            if url.startswith(prefix):
                return io.BytesIO((ROOT / url.removeprefix(prefix)).read_bytes())
            if url == f"https://api.github.com/repos/{setup.REPO}/releases?per_page=100&page=1":
                return io.BytesIO(json.dumps([current_release]).encode())
            for asset in current_release["assets"]:
                if url == asset["browser_download_url"]:
                    return io.BytesIO(payloads[asset["name"]])
            self.fail(f"Unexpected download: {url}")

        def tool_output(args, **_kwargs):
            commands.append([str(arg) for arg in args])
            return json.dumps(compose_config()).encode()

        def tool_run(args, **kwargs):
            commands.append([str(arg) for arg in args])
            if str(args[0]) == setup.sys.executable:
                return real_run(args, **kwargs)

        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            directory = Path(directory)
            stack.enter_context(patch.object(setup, "STATE", directory / "state"))
            stack.enter_context(patch.object(setup, "available_dashboard_port", return_value=8080))
            stack.enter_context(patch.dict(os.environ, {
                "OPENAIDR_SETUP_SOURCE": str(directory / "setup.sh"), "HOME": str(directory / 'profile'),
                "LOCALAPPDATA": str(directory / 'profile'), "XDG_CONFIG_HOME": str(directory / 'profile')}))
            stack.enter_context(patch.object(setup.sys, "argv", ["setup.sh"]))
            stack.enter_context(patch.object(setup.sys, "platform", "darwin"))
            stack.enter_context(patch.object(setup.os, "uname", return_value=types.SimpleNamespace(machine="arm64")))
            stack.enter_context(patch.object(setup.os, "geteuid", return_value=501))
            stack.enter_context(patch.object(setup.shutil, "which", return_value=None))
            stack.enter_context(patch.object(setup, "urlopen", side_effect=public_response))
            stack.enter_context(patch.object(Path, "is_dir", lambda path:
                                            str(path) == "/Applications/Docker.app" or real_is_dir(path)))
            stack.enter_context(patch.object(setup, "output", side_effect=tool_output))
            stack.enter_context(patch.object(setup, "run", side_effect=tool_run))
            # Only the Docker readiness/volume probes use subprocess.run directly.
            real_subprocess = subprocess.run

            def probe(args, **kwargs):
                if "info" in args or "inspect" in args:
                    return subprocess.CompletedProcess(args, 1 if "inspect" in args else 0)
                return real_subprocess(args, **kwargs)

            stack.enter_context(patch.object(setup.subprocess, "run", side_effect=probe))
            stack.enter_context(patch.object(setup, "wait_for_dashboard"))
            stack.enter_context(patch.object(setup, "install_app", return_value=directory / "OpenAIDR.app"))
            stack.enter_context(patch.object(setup, "authenticate", return_value=(None, ["test-session"])))
            stack.enter_context(patch.object(setup, "open_dashboard", return_value=True))
            captured = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            setup.main()
            credentials = (setup.STATE / ".env").read_bytes()
            setup.main()
            self.assertEqual((setup.STATE / ".env").read_bytes(), credentials)
            self.assertNotIn("private-password", captured.getvalue())
        self.assertFalse(any(command[0] == "gh" for command in commands))
        downloads = [url for url in requests if "/releases/download/" in url]
        self.assertEqual(len(downloads), 4)
        launches = [command for command in commands if "up" in command]
        self.assertEqual(len(launches), 2)
        for command in launches:
            self.assertEqual(command[-5:], ["up", "-d", "--no-build", "--pull", "never"])
        self.assertTrue(any(command[-2:] == ["pull", "db"] for command in commands))
        self.assertFalse(any("build" in command for command in commands))


if __name__ == "__main__":
    unittest.main()
