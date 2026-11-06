"""Exercise the public bootstrap without changing the host or consuming a token."""

import hashlib
import json
import os
import select
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import urllib.error

SCRIPT = Path(__file__).resolve().parents[1] / "apps/dashboard/public/install-linux.py"
installer = types.ModuleType("install_linux")
# Load the standalone asset without placing bytecode in the public web directory.
exec(compile(SCRIPT.read_text(), str(SCRIPT), "exec"), installer.__dict__)
LINK = "https://tenant.example/enroll#token=oaet_" + "a" * 43
PREVIEW = {"tenant": {"id": "tenant-id", "name": "Example"}, "server_url": "https://tenant.example"}


class LinuxInstallTests(unittest.TestCase):
    if sys.platform.startswith("linux"):
        def test_protected_package_resists_replacement_and_cleans_up_on_failure(self):
            with tempfile.TemporaryDirectory() as temporary:
                package = Path(temporary) / "download.deb"
                package.write_bytes(b"verified package")
                with self.assertRaisesRegex(ValueError, "verification failed"):
                    with installer.protected_package(package) as protected:
                        self.assertEqual(protected.stat().st_uid, 0)
                        self.assertEqual(protected.parent.stat().st_uid, 0)
                        self.assertFalse(protected.stat().st_mode & 0o022)
                        self.assertFalse(protected.parent.stat().st_mode & 0o022)
                        package.write_bytes(b"replaced download")
                        self.assertEqual(protected.read_bytes(), b"verified package")
                        # CI runs this as the desktop user; root containers use nobody.
                        command = (["sudo", "-u", "nobody"] if not os.geteuid() else [])
                        for operation in ("write_bytes(b'tampered')", "unlink()"):
                            code = "import pathlib, sys; pathlib.Path(sys.argv[1])." + operation
                            result = subprocess.run(command + ["python3", "-c", code, str(protected)], capture_output=True)
                            self.assertNotEqual(result.returncode, 0)
                            self.assertIn(b"PermissionError", result.stderr)
                        raise ValueError("verification failed")
                self.assertFalse(protected.parent.exists())

    def test_terminal_confirmation_preserves_enrollment_stdin_and_handles_cancellation(self):
        code = ("import io, runpy, sys; script = runpy.run_path(sys.argv[1]); "
                "sys.stdin = io.StringIO(sys.argv[2]); "
                "script['confirm']('Confirm organization'); "
                "assert sys.stdin.read() == sys.argv[2]; print('confirmed')")
        command = [sys.executable, "-c", code, str(SCRIPT), LINK]
        terminal = (["script", "-q", "/dev/null", *command] if sys.platform == "darwin" else
                    ["script", "-q", "-e", "-c", shlex.join(command), "/dev/null"])
        for answer in ("YES", "NO"):
            with self.subTest(answer=answer):
                with subprocess.Popen(terminal, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
                    output = b""
                    try:
                        while b"Type YES to continue:" not in output:
                            self.assertTrue(select.select([process.stdout], [], [], 10)[0], "No terminal prompt")
                            chunk = os.read(process.stdout.fileno(), 4096)
                            self.assertTrue(chunk, output.decode())
                            output += chunk
                        process.stdin.write((answer + "\n").encode())
                        process.stdin.flush()
                        process.wait(timeout=10)
                        tail, _ = process.communicate(timeout=10)
                        output = (output + tail).decode()
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.communicate()
                if answer == "YES":
                    self.assertEqual(process.returncode, 0, output)
                    self.assertIn("confirmed", output)
                    self.assertNotIn("Traceback", output)
                else:
                    self.assertIn("Installation cancelled", output)

    def test_connect_confirms_before_consuming_once_and_sets_up_without_sudo(self):
        calls = []

        def bridge(action, params):
            calls.append((action, params))
            return {"status": {"enrolled": False}, "enrollment.preview": PREVIEW,
                    "enrollment.connect": {"enrolled": True}}[action]

        def confirm(message):
            self.assertIn("Example at https://tenant.example", message)
            self.assertEqual([call[0] for call in calls], ["status", "enrollment.preview"])

        with patch.object(installer, "bridge", side_effect=bridge), patch.object(installer, "confirm", side_effect=confirm), \
                patch.object(installer, "run") as run:
            installer.connect(LINK)
        self.assertEqual(calls[-1], ("enrollment.connect", {"link": LINK, "tenant_id": "tenant-id"}))
        run.assert_called_once_with(["/usr/bin/openaidr", "setup"], timeout=180)

    def test_cancellation_existing_enrollment_and_setup_failure_do_not_reconsume(self):
        with patch.object(installer, "bridge", return_value={"enrolled": True}) as bridge, \
                patch.object(installer, "confirm") as confirm, patch.object(installer, "run") as run:
            installer.connect(LINK)
            bridge.assert_called_once_with("status", {})
            confirm.assert_not_called()
            run.assert_not_called()
        for cancel in (True, False):
            with self.subTest(cancel=cancel), \
                    patch.object(installer, "bridge", side_effect=[{"enrolled": False}, PREVIEW, {"enrolled": True}]) as bridge, \
                    patch.object(installer, "confirm", side_effect=ValueError("cancelled") if cancel else None), \
                    patch.object(installer, "run", side_effect=subprocess.CalledProcessError(1, "setup")):
                with self.assertRaisesRegex(ValueError, "cancelled" if cancel else "Enrollment succeeded"):
                    installer.connect(LINK)
                self.assertEqual(bridge.call_count, 2 if cancel else 3)

    def test_bridge_uses_stdin_and_suppresses_secret_in_errors(self):
        with patch.object(installer, "run", return_value=subprocess.CompletedProcess([], 0, '{"ok":true,"data":{"enrolled":true}}')) as run:
            self.assertTrue(installer.bridge("enrollment.connect", {"link": LINK})["enrolled"])
            args, kwargs = run.call_args
            self.assertEqual(args[0], ["/usr/bin/openaidr", "desktop-bridge"])
            self.assertEqual(json.loads(kwargs["input"])["params"]["link"], LINK)
        with patch.object(installer, "run", side_effect=subprocess.CalledProcessError(1, LINK, stderr=LINK)):
            with self.assertRaises(ValueError) as error:
                installer.bridge("enrollment.connect", {"link": LINK})
            self.assertNotIn(LINK, str(error.exception))

    def test_manifest_fallback_only_on_missing_feed_and_rejects_untrusted_url(self):
        version = "2026.10.19+73302c5"
        metadata = {"version": version, "downloads": {"linux-x86_64": {"url": "https://other.example/app.deb", "sha256": "a" * 64}}}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            urls = []

            def download(url, destination):
                urls.append(url)
                if url.endswith("rollout-v2.json"):
                    raise urllib.error.HTTPError(url, 404, "missing", {}, None)
                destination.write_text(json.dumps(metadata))

            with patch.object(installer, "download", side_effect=download), patch.object(installer, "run") as run:
                with self.assertRaisesRegex(ValueError, "location"):
                    installer.release_package(directory)
                self.assertEqual(len(urls), 2)
                run.assert_not_called()
            with patch.object(installer, "download", side_effect=urllib.error.HTTPError("url", 500, "error", {}, None)) as download:
                with self.assertRaises(urllib.error.HTTPError):
                    installer.release_package(directory)
                self.assertEqual(download.call_count, 1)

    def test_root_and_wrong_architecture_cannot_install(self):
        with patch.object(installer.platform, "system", return_value="Linux"), \
                patch.object(installer.platform, "machine", return_value="x86_64"), \
                patch.object(Path, "exists", return_value=True), patch.object(installer.os, "geteuid", return_value=0), \
                patch.object(installer, "run") as run:
            with self.assertRaisesRegex(ValueError, "without sudo"):
                installer.install()
            run.assert_not_called()
        with patch.object(installer.platform, "system", return_value="Linux"), \
                patch.object(installer.platform, "machine", return_value="aarch64"):
            with self.assertRaisesRegex(ValueError, "x64"):
                installer.install()

    def test_release_package_checks_bytes_and_identity_after_signature_verification(self):
        version = "2026.10.19+73302c5"
        base = installer.RELEASES + version + "/linux/"
        filename = f"OpenAIDR_{version}_amd64.deb"
        metadata = {"version": version, "downloads": {"linux-x86_64": {
            "url": base + filename, "sha256": hashlib.sha256(b"package bytes").hexdigest()}}}

        def download(url, destination):
            destination.write_bytes(json.dumps(metadata).encode() if url.endswith(".json") else b"package bytes")

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for case in ("valid", "wrong-package", "checksum"):
                fields = f"Package: open-aidr\nArchitecture: amd64\nVersion: {version}\n"
                if case == "wrong-package":
                    fields = fields.replace("amd64", "arm64")
                if case == "checksum":
                    metadata["downloads"]["linux-x86_64"]["sha256"] = "0" * 64
                with self.subTest(case=case), patch.object(installer, "download", side_effect=download), \
                        patch.object(installer, "verify_package") as verify, \
                        patch.object(installer, "run", return_value=subprocess.CompletedProcess([], 0, fields)) as run:
                    if case == "valid":
                        self.assertEqual(installer.release_package(directory), directory / filename)
                        verify.assert_called_once()
                    else:
                        with self.assertRaisesRegex(ValueError, "architecture" if case == "wrong-package" else "checksum"):
                            installer.release_package(directory)
                    if case == "checksum":
                        verify.assert_not_called()
                        run.assert_not_called()

    def test_package_signature_accepts_pinned_key_and_rejects_tamper_and_other_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            home = directory / "signer"
            home.mkdir(mode=0o700)
            gpg = ["gpg", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
            subprocess.run(gpg + ["--quick-generate-key", "Bootstrap Test", "ed25519", "sign", "1d"], check=True, capture_output=True)
            listing = subprocess.run(gpg + ["--with-colons", "--list-keys"], check=True, capture_output=True, text=True).stdout
            fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
            key, package, signature = (directory / name for name in ("key.asc", "test.deb", "test.asc"))
            key.write_bytes(subprocess.run(gpg + ["--armor", "--export"], check=True, capture_output=True).stdout)
            package.write_bytes(b"signed package contents")
            subprocess.run(gpg + ["--armor", "--detach-sign", "--output", str(signature), str(package)], check=True, capture_output=True)
            for case in ("valid", "wrong-key", "tamper"):
                verify = directory / case
                verify.mkdir()
                with self.subTest(case=case), patch.object(installer, "SIGNING_KEY", fingerprint if case != "wrong-key" else "0" * 40):
                    if case == "valid":
                        installer.verify_package(verify, package, signature, key)
                    elif case == "wrong-key":
                        with self.assertRaisesRegex(ValueError, "OpenSecura"):
                            installer.verify_package(verify, package, signature, key)
                    else:
                        package.write_bytes(b"tampered package")
                        with self.assertRaisesRegex(ValueError, "signature could not be verified"):
                            installer.verify_package(verify, package, signature, key)


if __name__ == "__main__":
    unittest.main()
