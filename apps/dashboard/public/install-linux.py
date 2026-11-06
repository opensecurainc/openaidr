"""Install the signed Ubuntu/Debian x64 package, then enroll as the desktop user."""

import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

RELEASES = "https://releases.opensecura.ai/openaidr/"
SIGNING_KEY = "C895B756FF62548D25905AD6ED0C23BEE88C436B"
APP = Path("/usr/bin/openaidr-desktop")
SENSOR = Path("/usr/bin/openaidr")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def download(url, path):
    # Every URL is constructed below from the fixed release origin.
    with urllib.request.build_opener(NoRedirect).open(url, timeout=60) as response:
        with path.open("wb") as output:
            shutil.copyfileobj(response, output)


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def confirm(message):
    # stdin contains the enrollment link in the copied command; prompts use the terminal.
    with open("/dev/tty", "w") as output, open("/dev/tty", "r") as response:
        output.write(message + "\nType YES to continue: ")
        output.flush()
        if response.readline().strip() != "YES":
            raise ValueError("Installation cancelled. Any completed installation is kept.")


def release_package(directory):
    manifest = directory / "release.json"
    try:
        download(RELEASES + "rollout-v2.json", manifest)
    except urllib.error.HTTPError as error:
        error.close()
        if error.code != 404:
            raise
        # Older publications predate v2. Never fall back after a verification failure.
        download(RELEASES + "rollout-v1.json", manifest)
    metadata = json.loads(manifest.read_text())
    version = metadata.get("version", "")
    if not re.fullmatch(r"\d{4}\.\d{1,2}\.\d{1,2}\+[a-f0-9]{7,40}", version):
        raise ValueError("The release version is invalid.")
    filename = f"OpenAIDR_{version}_amd64.deb"
    base = RELEASES + version + "/linux/"
    artifact = metadata["downloads"]["linux-x86_64"]
    if artifact.get("url") != base + filename or not re.fullmatch(r"[a-f0-9]{64}", artifact.get("sha256", "")):
        raise ValueError("The Linux release location or checksum is invalid.")
    package = directory / filename
    print("Downloading OpenAIDR...", flush=True)
    download(base + filename, package)
    with package.open("rb") as source:
        digest = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != artifact["sha256"]:
        raise ValueError("The downloaded package checksum does not match.")
    signature = directory / "package.asc"
    key = directory / "key.asc"
    download(base + filename + ".asc", signature)
    download(base + "openaidr-linux-signing.asc", key)
    verify_release(directory, package, version)
    return package


def verify_release(directory, package, version):
    verify_package(directory, package, directory / "package.asc", directory / "key.asc")
    fields = run(["dpkg-deb", "--field", str(package), "Package", "Architecture", "Version"], capture_output=True).stdout
    if set(fields.splitlines()) != {"Package: open-aidr", "Architecture: amd64", "Version: " + version}:
        raise ValueError("The package name, architecture, or version is invalid.")


def verify_package(directory, package, signature, key):
    home = directory / "gnupg"
    home.mkdir(mode=0o700, exist_ok=True)
    gpg = ["gpg", "--homedir", str(home), "--batch", "--no-auto-key-retrieve"]
    try:
        run(gpg + ["--import", str(key)], capture_output=True)
        result = run(gpg + ["--status-fd", "1", "--verify", str(signature), str(package)], capture_output=True)
    except subprocess.CalledProcessError:
        raise ValueError("The OpenSecura package signature could not be verified. Installation stopped.") from None
    # A valid signature by a downloaded but unrelated key must never authorize installation.
    valid = [line.split() for line in result.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    rejected = re.search(r"\[GNUPG:\] (BADSIG|EXPSIG|EXPKEYSIG|REVKEYSIG) ", result.stdout)
    if rejected or len(valid) != 1 or valid[0][-1] != SIGNING_KEY:
        raise ValueError("The package was not signed by the OpenSecura Linux signing key.")


@contextmanager
def protected_package(package):
    # Root owns both the copy and its parent before verification. The desktop user
    # can read them but cannot replace the verified bytes while sudo or apt waits.
    staging = run(["sudo", "sh", "-c", '''set -eu
umask 077
staging=$(mktemp -d /var/tmp/openaidr-install.XXXXXXXXXX)
trap 'rm -rf -- "$staging"' EXIT
install -m 0644 -- "$1" "$staging/OpenAIDR.deb"
chmod 0755 "$staging"
printf '%s\\n' "$staging"
trap - EXIT
''', "openaidr-install", str(package)], capture_output=True).stdout.strip()
    if not re.fullmatch(r"/var/tmp/openaidr-install\.[A-Za-z0-9]{10}", staging):
        raise ValueError("Could not create the protected installer directory.")
    try:
        yield Path(staging) / "OpenAIDR.deb"
    finally:
        run(["sudo", "rm", "-rf", "--", staging])


def bridge(action, params):
    try:
        result = run([str(SENSOR), "desktop-bridge"], input=json.dumps({"action": action, "params": params}),
                     capture_output=True, timeout=180)
        response = json.loads(result.stdout)
        if response.get("ok") is True and isinstance(response.get("data"), dict):
            return response["data"]
    except (subprocess.SubprocessError, ValueError):
        pass
    raise ValueError("Could not confirm the connection. Open OpenAIDR to check before retrying. "
                     "Use the app for private server certificates.")


def install():
    if platform.system() != "Linux" or platform.machine() != "x86_64" or not Path("/etc/debian_version").exists():
        raise ValueError("This command supports Ubuntu/Debian x64. Use a published installer for your platform.")
    if os.geteuid() == 0:
        raise ValueError("Run this command as your normal desktop user, without sudo.")
    for command in ("sudo", "apt-get", "dpkg-deb", "gpg"):
        if not shutil.which(command):
            raise ValueError(f"Install {command} with your system package manager, then run this command again.")
    custom = shutil.which("openaidr-desktop")
    data_home = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
    if (data_home / "openaidr/desktop/OpenAIDR.AppImage").exists() or (custom and Path(custom).resolve() != APP.resolve()):
        raise ValueError("A custom OpenAIDR installation exists. Open that app to connect this device.")
    if not APP.exists():
        confirm("Download the signed OpenAIDR Debian package and install it with sudo? "
                "Enrollment and sensor setup will run as your signed-in user.")
        with tempfile.TemporaryDirectory(prefix="openaidr-install-") as temporary:
            package = release_package(Path(temporary))
            with protected_package(package) as protected:
                version = package.name.removeprefix("OpenAIDR_").removesuffix("_amd64.deb")
                verify_release(Path(temporary), protected, version)
                # apt resolves dependencies using the configured system repositories.
                run(["sudo", "apt-get", "install", "-y", str(protected)])
    for executable in (APP, SENSOR):
        resolved = executable.resolve(strict=True)
        # Reuse only system-owned binaries. Do not execute a user-writable replacement.
        for path in (resolved, *resolved.parents):
            stat = path.stat()
            if stat.st_uid != 0 or stat.st_mode & 0o022:
                raise ValueError("The installed OpenAIDR files are not protected. Reinstall using your package manager.")


def connect(link):
    state = bridge("status", {})
    if not isinstance(state.get("enrolled"), bool):
        raise ValueError("Cannot verify the existing enrollment. Open OpenAIDR to check its status.")
    if state["enrolled"]:
        print("OpenAIDR is already enrolled. The existing connection is kept. Open the app to manage it.")
        return
    preview = bridge("enrollment.preview", {"link": link})
    tenant = preview.get("tenant", {})
    if not tenant.get("id") or not tenant.get("name") or not preview.get("server_url"):
        raise ValueError("The enrollment preview is incomplete. Open OpenAIDR to connect.")
    confirm(f"Connect this device to {tenant['name']} at {preview['server_url']}? "
            "OpenAIDR will set up its sensor and detected coding agents.")
    connected = bridge("enrollment.connect", {"link": link, "tenant_id": tenant["id"]})
    if connected.get("enrolled") is not True:
        raise ValueError("Enrollment could not be confirmed. Check the app before trying again.")
    try:
        run([str(SENSOR), "setup"], timeout=180)
    except (OSError, subprocess.SubprocessError):
        raise ValueError("Enrollment succeeded. Run openaidr setup or open OpenAIDR to finish setup. Do not reuse the link.") from None
    print("This device is enrolled and setup is complete. Restart coding-agent sessions, then check OpenAIDR.")


def main():
    if sys.argv[1:] != ["--enrollment-stdin"]:
        raise ValueError("Usage: python3 install-linux.py --enrollment-stdin")
    link = sys.stdin.read(4097).strip()
    if len(link) > 4096 or not re.fullmatch(r"https://[^\s?#@\\]+/enroll#token=oaet_[A-Za-z0-9_-]{43}", link):
        raise ValueError("Supply the complete HTTPS enrollment link from your administrator.")
    install()
    connect(link)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        # Never print bridge request data or process output containing enrollment credentials.
        print(str(error) if isinstance(error, ValueError) else
              "Installation could not finish. Check your network and package manager, then open OpenAIDR to check its status.",
              file=sys.stderr)
        sys.exit(1)
