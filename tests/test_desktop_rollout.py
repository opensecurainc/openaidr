"""Cross-platform artifact handoff, publication ordering, and small policy edits."""

from copy import deepcopy
import base64
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib
import io
import json
from pathlib import Path
import subprocess
import threading
import zipfile

import pytest

from test_desktop_release import INFO, VERSION, artifacts as make_artifacts
from test_linux_release_ci import appimage_bytes, key_material, signing, SELECTED
from test_publish_desktop_release import MemoryStorage, release


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def rollout(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    module = importlib.import_module("desktop_rollout")

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 16, 16, tzinfo=timezone.utc).astimezone(tz)

    monkeypatch.setattr(module, "datetime", Clock)
    return module


@pytest.fixture
def prepared(rollout, release, signing, tmp_path):
    ci, staged, private, signed, marker = signing
    (staged / "release-notes.md").write_bytes((release / "release-notes.md").read_bytes())
    (staged / "SHA256SUMS").write_text(ci.checksums(staged))
    ci.sign(staged, SELECTED, private, signed)
    windows = tmp_path / "windows"
    windows.mkdir()
    name = f"OpenAIDR_{VERSION}_signed-{INFO['source_commit'][:7]}_x64-setup.exe"
    installer = windows / name
    installer.write_bytes(b"native CI installer fixture")
    rollout.write_json(windows / "build.json", {
        "schema": "openaidr.windows-test.v1", "version": VERSION, "commit": INFO["source_commit"],
        "filename": name, "sha256": rollout.digest(installer), "run_id": "12345",
        "authenticode": 'CN=OpenSecura, Inc., O="OpenSecura, Inc.", C=US',
    })
    output = tmp_path / "rollout"
    rollout.prepare(release, windows, signed, rollout.default_policy("2026-10-16T16:00:00Z"), output)
    assert not marker.exists()
    return output


def delivery(storage):
    def check(name, path, *, redirect_to=None):
        if storage.objects[name][0] != path.read_bytes():
            raise ValueError("public bytes differ")
        if redirect_to:
            pointer = f"openaidr/latest-redirects/{name.rsplit('/', 1)[1]}.txt"
            assert storage.objects[pointer][0].decode() == redirect_to
    return check


@pytest.fixture
def renamed_app(rollout, prepared):
    root = prepared.parent
    artifacts = make_artifacts(root / "renamed-artifacts", application_id="com.opensecura.openaidr")
    macos = root / "renamed-macos"
    rollout.release.manifest(VERSION, prepared / "macos/release-notes.md", artifacts, macos)
    output = root / "renamed-rollout"
    rollout.prepare(macos, root / "windows", prepared / "linux",
                    rollout.read_json(prepared / "release.json")["rollout"], output)
    return output


def migration_bridge(rollout, prepared, storage):
    bridge = rollout.read_json(prepared / "release.json")
    legacy = rollout.read_json(prepared / "macos/latest.json")
    for manifest in (bridge, legacy):
        manifest["version"] = "2026.10.6+bbbbbbb"
        manifest["build"].update(version=manifest["version"], source_commit="b" * 40,
                                 publication_timestamp=1791341999, published_at="2026-10-07T02:59:59+00:00")
        manifest["pub_date"] = manifest["build"]["published_at"]
    bridge["rollout"]["steps"] = [{"after_hours": 0, "percent": 100}]
    storage.objects[rollout.COMPATIBILITY_FEED] = (json.dumps(bridge).encode(), 1)
    storage.objects["openaidr/latest.json"] = (json.dumps(legacy).encode(), 1)


@pytest.mark.parametrize("damage", [None, "missing", "paused", "unpromoted", "different_release", "no_migration"])
def test_renamed_app_cannot_skip_or_overwrite_the_migration_bridge(rollout, prepared, renamed_app, damage):
    storage = MemoryStorage()
    migration_bridge(rollout, prepared, storage)
    if damage == "missing":
        storage.objects.pop(rollout.COMPATIBILITY_FEED)
    elif damage == "unpromoted":
        storage.objects.pop("openaidr/latest.json")
    elif damage:
        bridge = json.loads(storage.objects[rollout.COMPATIBILITY_FEED][0])
        if damage == "paused":
            bridge["rollout"]["paused"] = True
        elif damage == "different_release":
            bridge["version"] = VERSION
            bridge["build"] = INFO
            bridge["pub_date"] = INFO["published_at"]
        else:
            bridge["identity_migration"] = 0
        storage.objects[rollout.COMPATIBILITY_FEED] = (json.dumps(bridge).encode(), 1)
    before = dict(storage.objects)
    if damage:
        with pytest.raises(ValueError):
            rollout.publish(renamed_app, storage, delivery(storage))
        assert storage.objects == before and not storage.uploads
    else:
        rollout.publish(renamed_app, storage, delivery(storage))
        assert storage.objects[rollout.FEED][0] == (renamed_app / "release.json").read_bytes()
        for feed in (rollout.COMPATIBILITY_FEED, "openaidr/latest.json"):
            assert storage.objects[feed] == before[feed]


def sign_update(path, key):
    signature = path.with_name(path.name + ".sig")
    subprocess.run(["minisign", "-S", "-s", key, "-m", path, "-x", signature], check=True, capture_output=True)
    signature.write_bytes(base64.b64encode(signature.read_bytes()))


@pytest.fixture
def signed_windows(rollout, prepared, monkeypatch):
    source = prepared.parent / "windows"
    info = rollout.read_json(source / "build.json")
    info.update({"schema": "openaidr.windows-release.v1", "build": dict(INFO)})
    installer = source / info["filename"]
    key, public = prepared.parent / "test.key", prepared.parent / "test.pub"
    subprocess.run(["minisign", "-G", "-W", "-s", key, "-p", public], check=True, capture_output=True)
    monkeypatch.setattr(rollout, "UPDATER_PUBLIC_KEY", public)
    sign_update(installer, key)
    (source / "release-notes.md").write_bytes((prepared / "macos/release-notes.md").read_bytes())
    rollout.write_json(source / "build.json", info)
    sign_update(source / "build.json", key)
    return source, key


@pytest.fixture
def windows_prepared(rollout, prepared, signed_windows):
    source, _ = signed_windows
    output = prepared.parent / "windows-update"
    policy = rollout.read_json(prepared / "release.json")["rollout"]
    rollout.prepare(prepared / "macos", source, prepared / "linux", policy, output)
    return output


@pytest.mark.parametrize("bridge_layout", [None, 0, 1, 2])
def test_windows_layout_migration_requires_its_bridge_and_keeps_old_feeds(
    rollout, prepared, signed_windows, bridge_layout,
):
    source, private = signed_windows
    info = rollout.read_json(source / "build.json")
    info["windows_layout"] = 2
    rollout.write_json(source / "build.json", info)
    sign_update(source / "build.json", private)
    output = prepared.parent / "layout-update"
    rollout.prepare(prepared / "macos", source, prepared / "linux",
                    rollout.read_json(prepared / "release.json")["rollout"], output)
    storage = MemoryStorage()
    migration_bridge(rollout, prepared, storage)
    if bridge_layout is not None:
        bridge = json.loads(storage.objects[rollout.COMPATIBILITY_FEED][0])
        bridge["platforms"]["windows-x86_64"] = {
            "metadata": base64.b64encode(json.dumps({"windows_layout": bridge_layout}).encode()).decode(),
        }
        storage.objects[rollout.COMPATIBILITY_FEED] = (json.dumps(bridge).encode(), 1)
    before = dict(storage.objects)
    if bridge_layout != 1:
        with pytest.raises(ValueError):
            rollout.publish(output, storage, delivery(storage))
        assert storage.objects == before and not storage.uploads
    else:
        rollout.publish(output, storage, delivery(storage))
        for feed in (rollout.COMPATIBILITY_FEED, "openaidr/latest.json"):
            assert storage.objects[feed] == before[feed]
    with pytest.raises(ValueError, match="Legacy feeds"):
        rollout.require_compatibility_release(rollout.read_json(output / "release.json"))


@pytest.mark.parametrize("damage", [None, "signature", "installer", "publication", "metadata", "notes"])
def test_windows_updater_requires_trusted_signature_and_matching_release(rollout, prepared, signed_windows, damage):
    source, key = signed_windows
    info = rollout.read_json(source / "build.json")
    installer = source / info["filename"]
    signature = source / (installer.name + ".sig")
    if damage == "signature":
        data = bytearray(base64.b64decode(signature.read_bytes()))
        data[70] = ord("A") if data[70] != ord("A") else ord("B")
        signature.write_bytes(base64.b64encode(data))
    elif damage == "installer":
        installer.write_bytes(b"changed installer with matching untrusted checksum")
        info["sha256"] = rollout.digest(installer)
    elif damage == "publication":
        info["build"]["published_at"] = "2026-10-07T04:00:00+00:00"
        info["build"]["publication_timestamp"] += 3600
    elif damage == "notes":
        (source / "release-notes.md").write_text("different notes")
    rollout.write_json(source / "build.json", info)
    record_signature = source / "build.json.sig"
    sign_update(source / "build.json", key)
    if damage == "metadata":
        info["run_id"] = "changed after signing"
        rollout.write_json(source / "build.json", info)
    output = prepared.parent / "windows-update"
    policy = rollout.read_json(prepared / "release.json")["rollout"]
    if damage:
        with pytest.raises((ValueError, subprocess.CalledProcessError)):
            rollout.prepare(prepared / "macos", source, prepared / "linux", policy, output)
        assert not output.exists()
        return
    rollout.prepare(prepared / "macos", source, prepared / "linux", policy, output)
    storage = MemoryStorage()
    rollout.publish(output, storage, delivery(storage))
    document = json.loads(storage.objects[rollout.FEED][0])
    update = document["platforms"]["windows-x86_64"]
    name = f"openaidr/{VERSION}/windows/{installer.name}"
    assert update == {"url": rollout.ORIGIN + "/" + name, "signature": signature.read_text().strip(),
                      "metadata": base64.b64encode((source / "build.json").read_bytes()).decode("ascii"),
                      "metadata_signature": record_signature.read_text().strip()}
    assert storage.objects[name][0] == installer.read_bytes()
    with zipfile.ZipFile(output / "windows" / rollout.windows_archive_name(installer.name)) as bundle:
        assert bundle.read(installer.name) == storage.objects[name][0]
    # Revalidate retained bytes before every publication, including retries.
    (output / "windows" / installer.name).write_bytes(b"changed after preparation")
    uploads = list(storage.uploads)
    with pytest.raises(subprocess.CalledProcessError):
        rollout.publish(output, storage, delivery(storage))
    assert storage.uploads == uploads


@pytest.mark.parametrize("protocol", [None, 1])
def test_linux_feed_requires_signed_update_capability_and_preserves_deb_download(rollout, prepared, signing, monkeypatch, protocol):
    ci, staged, private, _, _ = signing
    image = staged / ci.appimage_name(SELECTED)
    image.write_bytes(appimage_bytes())
    info = json.loads((staged / "build.json").read_text())
    (staged / "appimage.json").write_text(json.dumps(ci.appimage_record(image, info, SELECTED, protocol)))
    (staged / "SHA256SUMS").write_text(ci.checksums(staged))
    key, public = prepared.parent / "linux-update.key", prepared.parent / "linux-update.pub"
    subprocess.run(["minisign", "-G", "-W", "-s", key, "-p", public], check=True, capture_output=True)
    monkeypatch.setattr(ci, "UPDATER_PUBLIC_KEY", public)
    original = subprocess.run

    def signer(command, **kwargs):
        if command[1:5] == ["exec", "tauri", "signer", "sign"]:
            path = Path(command[5])
            signature = path.with_name(path.name + ".sig")
            result = original(["minisign", "-S", "-s", key, "-m", path, "-x", signature], check=True, capture_output=True)
            signature.write_bytes(base64.b64encode(signature.read_bytes()))
            return result
        return original(command, **kwargs)

    monkeypatch.setattr(subprocess, "run", signer)
    signed = prepared.parent / "linux-appimage-signed"
    ci.sign(staged, SELECTED, private, signed)
    output = prepared.parent / "linux-update"
    policy = rollout.read_json(prepared / "release.json")["rollout"]
    rollout.prepare(prepared / "macos", prepared.parent / "windows", signed, policy, output)
    storage = MemoryStorage()
    rollout.publish(output, storage, delivery(storage))
    document = json.loads(storage.objects[rollout.FEED][0])
    assert document["downloads"]["linux-x86_64"]["url"].endswith(".deb")
    download = document["downloads"]["linux-x86_64-appimage"]
    assert download["url"].endswith("/" + image.name)
    assert download.get("updater_protocol") == protocol
    assert ("linux-x86_64" in document["platforms"]) == (protocol == 1)
    if protocol == 1:
        target = document["platforms"]["linux-x86_64"]
        assert target["url"] == download["url"]
        assert base64.b64decode(target["metadata"]) == (signed / "appimage.json").read_bytes()
        assert target["metadata_signature"] == (signed / "appimage.json.sig").read_text().strip()
        assert target["signature"] == (signed / (image.name + ".sig")).read_text().strip()
    before = list(storage.uploads)
    (output / "linux" / image.name).write_bytes(b"changed after preparation")
    with pytest.raises(ValueError):
        rollout.publish(output, storage, delivery(storage))
    assert storage.uploads == before


def test_publish_resumes_after_upload_failure_and_keeps_legacy_feed(rollout, prepared):
    storage = MemoryStorage()
    legacy = b'{"version":"0.3.0"}'
    storage.objects["openaidr/latest.json"] = (legacy, 1)
    storage.fail_name = f"openaidr/{VERSION}/linux/SHA256SUMS"
    with pytest.raises(OSError, match="unavailable"):
        rollout.publish(prepared, storage, delivery(storage))
    assert rollout.FEED not in storage.objects
    completed = list(storage.uploads)
    storage.fail_name = None
    assert rollout.publish(prepared, storage, delivery(storage)) == VERSION
    # The active feed goes live first; the fixed download links follow it. The
    # universal Mac DMG also serves the Intel link.
    fixed = {**{name: target for target, name in rollout.LINKS.items()}, rollout.INTEL_LINK: "darwin-aarch64"}
    links = [f"{rollout.LATEST}/{name}" for name in sorted(fixed)]
    expected = [(rollout.FEED, True)]
    for link in links:
        expected += [(link, False), (f"{rollout.REDIRECTS}/{link.rsplit('/', 1)[1]}.txt", False)]
    assert storage.uploads[-len(expected):] == expected
    assert storage.objects["openaidr/latest.json"] == (legacy, 1)
    assert all(storage.uploads.count(item) == 1 for item in completed)
    document = json.loads(storage.objects[rollout.FEED][0])
    assert set(document["downloads"]) == {"darwin-aarch64", "windows-x86_64", "linux-x86_64"}
    assert set(document["platforms"]) == {"darwin-aarch64"}
    assert [step["percent"] for step in document["rollout"]["steps"]] == [1, 5, 10, 25, 50, 75, 100]
    assert storage.objects[f"openaidr/{VERSION}/release.json"][0] == storage.objects[rollout.FEED][0]
    for file in document["downloads"].values():
        assert file["url"].removeprefix(rollout.ORIGIN + "/") in storage.objects
    # Windows is published only as a zip holding the unchanged signed installer.
    installer = f"OpenAIDR_{VERSION}_signed-{INFO['source_commit'][:7]}_x64-setup.exe"
    package = document["downloads"]["windows-x86_64"]["url"].removeprefix(rollout.ORIGIN + "/")
    assert package == f"openaidr/{VERSION}/windows/{installer.removesuffix('.exe')}.zip"
    assert not any(name.endswith(".exe") for name in storage.objects)
    with zipfile.ZipFile(io.BytesIO(storage.objects[package][0])) as bundle:
        assert bundle.namelist() == [installer]
        assert bundle.read(installer) == b"native CI installer fixture"
    for name, target in fixed.items():
        link = f"{rollout.LATEST}/{name}"
        versioned = document["downloads"][target]["url"].removeprefix(rollout.ORIGIN + "/")
        assert storage.objects[link][0] == storage.objects[versioned][0]
        assert storage.labels[link]["openaidr-version"] == VERSION
        pointer = f"{rollout.REDIRECTS}/{name}.txt"
        assert storage.objects[pointer][0] == document["downloads"][target]["url"].encode()
    uploads = list(storage.uploads)
    rollout.publish(prepared, storage, delivery(storage))
    assert storage.uploads == uploads
    assert rollout.verify(prepared, delivery(storage), lambda: document) == VERSION


def test_fixed_links_move_forward_only(rollout, prepared):
    storage = MemoryStorage()
    rollout.publish(prepared, storage, delivery(storage))
    manifest, files = rollout.staged(prepared)
    link = f"{rollout.LATEST}/OpenAIDR-windows-x64.zip"
    order = int(storage.labels[link]["openaidr-publication-timestamp"])
    count = len(storage.uploads)

    # A link that records a later publication is left alone.
    storage.labels[link] = {**storage.labels[link], "openaidr-publication-timestamp": str(order + 60)}
    rollout.advance_links(storage, manifest, files, delivery(storage))
    assert len(storage.uploads) == count

    # A link from an earlier publication is replaced at its current generation.
    storage.objects[link] = (b"older release", 7)
    storage.labels[link] = {"openaidr-version": "2026.10.5+0b0b0b0", "openaidr-publication-timestamp": str(order - 60)}
    rollout.advance_links(storage, manifest, files, delivery(storage))
    assert storage.objects[link][1] == 8 and storage.labels[link]["openaidr-version"] == VERSION

    # The same publication with different bytes, or a link without order, is refused.
    storage.objects[link] = (b"tampered", 8)
    with pytest.raises(ValueError, match="differs from this release"):
        rollout.advance_links(storage, manifest, files, delivery(storage))
    storage.labels[link] = None
    with pytest.raises(ValueError, match="no publication order"):
        rollout.advance_links(storage, manifest, files, delivery(storage))


def test_fixed_links_wait_while_paused_and_catch_up_after_unpausing(rollout, prepared):
    storage = MemoryStorage()
    with pytest.raises(ValueError, match="not the active release"):
        rollout.links(prepared, storage, delivery(storage))
    rollout.publish(prepared, storage, delivery(storage))
    link = f"{rollout.LATEST}/OpenAIDR-aarch64.dmg"
    paused = json.loads(storage.objects[rollout.FEED][0])["rollout"]
    paused["paused"] = True
    rollout.update_policy(storage, VERSION, paused, prepared.parent / "paused.json", delivery(storage))
    del storage.objects[link]
    assert rollout.links(prepared, storage, delivery(storage)) == VERSION
    assert link not in storage.objects
    paused["paused"] = False
    rollout.update_policy(storage, VERSION, paused, prepared.parent / "resumed.json", delivery(storage))
    rollout.links(prepared, storage, delivery(storage))
    assert storage.objects[link][0] == (prepared / "macos/OpenAIDR-aarch64.dmg").read_bytes()


def test_link_failure_after_the_release_is_live_is_recoverable(rollout, prepared):
    storage = MemoryStorage()
    storage.fail_name = f"{rollout.LATEST}/OpenAIDR-linux-amd64.deb"
    with pytest.raises(ValueError, match="release is live.*Run `links`"):
        rollout.publish(prepared, storage, delivery(storage))
    assert rollout.FEED in storage.objects and storage.fail_name not in storage.objects
    storage.fail_name = None
    rollout.links(prepared, storage, delivery(storage))
    assert all(f"{rollout.LATEST}/{name}" in storage.objects for name in rollout.LINKS.values())


def test_redirect_failure_is_retryable_and_cannot_move_backwards(rollout, prepared):
    storage = MemoryStorage()
    pointer = f"{rollout.REDIRECTS}/OpenAIDR-linux-amd64.deb.txt"
    storage.fail_name = pointer
    with pytest.raises(ValueError, match="release is live"):
        rollout.publish(prepared, storage, delivery(storage))
    assert pointer not in storage.objects
    storage.fail_name = None
    rollout.links(prepared, storage, delivery(storage))
    initial = storage.objects[pointer]
    labels = storage.labels[pointer]
    older = {**labels, "openaidr-publication-timestamp": str(int(labels["openaidr-publication-timestamp"]) - 1)}
    rollout.advance_redirect(storage, "OpenAIDR-linux-amd64.deb", "older", older)
    assert storage.objects[pointer] == initial
    with pytest.raises(ValueError, match="differs from this release"):
        rollout.advance_redirect(storage, "OpenAIDR-linux-amd64.deb", "different", labels)


def test_policy_edits_transfer_only_json_and_preserve_the_snapshot(rollout, prepared):
    storage = MemoryStorage()
    rollout.publish(prepared, storage, delivery(storage))
    snapshot = dict(storage.objects)
    initial = json.loads(snapshot[rollout.FEED][0])
    paused = deepcopy(initial["rollout"])
    paused["paused"] = True
    requests = []
    uploads = len(storage.uploads)

    def check(name, path):
        requests.append((name, path.stat().st_size))
        delivery(storage)(name, path)

    rollout.update_policy(storage, VERSION, paused, prepared.parent / ("paused.json" if paused["paused"] else "resumed.json"), check)
    assert storage.uploads[uploads:] == [(rollout.FEED, True)]
    assert requests == [(rollout.FEED, len(storage.objects[rollout.FEED][0]))]
    assert all(storage.objects[name] == value for name, value in snapshot.items() if name != rollout.FEED)
    current = json.loads(storage.objects[rollout.FEED][0])
    assert current == {**initial, "rollout": paused}
    assert json.loads((prepared.parent / "paused.json").read_text()) == current
    assert rollout.verify(prepared, delivery(storage), lambda: current) == VERSION
    # Repeating the exact policy is read-only. Republishing the original directory
    # must not undo an operator's pause or modified schedule.
    rollout.update_policy(storage, VERSION, paused, prepared.parent / ("paused.json" if paused["paused"] else "resumed.json"), check)
    assert len(storage.uploads) == uploads + 1
    with pytest.raises(ValueError, match="reset its edited policy"):
        rollout.publish(prepared, storage, delivery(storage))
    paused["paused"] = False
    paused["steps"] = [{"after_hours": 0, "percent": 0}, {"after_hours": 240, "percent": 100}]
    rollout.update_policy(storage, VERSION, paused, prepared.parent / ("paused.json" if paused["paused"] else "resumed.json"), check)
    assert json.loads(storage.objects[rollout.FEED][0])["rollout"] == paused
    assert all(name == rollout.FEED for name, _ in requests)
    paused["starts_at"] = "2026-10-17T16:00:00Z"
    with pytest.raises(ValueError, match="start time"):
        rollout.update_policy(storage, VERSION, paused, prepared.parent / ("paused.json" if paused["paused"] else "resumed.json"), check)
    with pytest.raises(ValueError, match="exact active"):
        rollout.update_policy(storage, "2026.10.6+aaaaaaa", paused, prepared.parent / "wrong.json", check)


@pytest.mark.parametrize("operation", ["publish", "policy"])
def test_concurrent_feed_write_is_rejected(rollout, prepared, operation):
    class RacingStorage(MemoryStorage):
        racing = False

        def upload(self, path, name, generation, *, feed=False, labels=None):
            if name == rollout.FEED and self.racing:
                self.objects[name] = (b"another publisher's feed", generation + 1)
            super().upload(path, name, generation, feed=feed, labels=labels)

    storage = RacingStorage()
    if operation == "policy":
        rollout.publish(prepared, storage, delivery(storage))
    storage.racing = True
    with pytest.raises(OSError, match="generation precondition"):
        if operation == "publish":
            rollout.publish(prepared, storage, delivery(storage))
        else:
            updated = json.loads(storage.objects[rollout.FEED][0])["rollout"]
            updated["paused"] = True
            rollout.update_policy(storage, VERSION, updated, prepared.parent / "edited.json", delivery(storage))
    assert storage.objects[rollout.FEED][0] == b"another publisher's feed"


def test_public_verification_failure_never_rolls_back_live_feed(rollout, prepared):
    storage = MemoryStorage()

    def missing_installer(name, path):
        if name.endswith(".dmg"):
            raise OSError("public installer unavailable")
        delivery(storage)(name, path)

    with pytest.raises(OSError, match="public installer unavailable"):
        rollout.publish(prepared, storage, missing_installer)
    assert rollout.FEED not in storage.objects

    def stale(name, path):
        if name == rollout.FEED:
            raise ValueError("stale cache")
        delivery(storage)(name, path)

    with pytest.raises(ValueError, match="may already be live"):
        rollout.publish(prepared, storage, stale)
    before = dict(storage.objects)
    assert rollout.verify(prepared, delivery(storage), lambda: json.loads(before[rollout.FEED][0])) == VERSION
    assert storage.objects == before
    storage.objects[f"openaidr/{VERSION}/OpenAIDR-aarch64.dmg"] = (b"different bytes", 2)
    with pytest.raises(ValueError, match="Immutable"):
        rollout.publish(prepared, storage, delivery(storage))
    assert storage.objects[rollout.FEED] == before[rollout.FEED]


@pytest.mark.parametrize("case", [
    "windows_hash", "windows_commit", "windows_unsigned", "windows_shape",
    "windows_extra_entry", "windows_changed_installer", "windows_raw_exe",
    "linux_signature", "windows_edition", "linux_edition", "notes", "page",
])
def test_rejects_mismatched_or_tampered_handoff_before_writing(rollout, prepared, case):
    package = next((prepared / "windows").glob("*.zip"))
    installer = package.name.removesuffix(".zip") + ".exe"
    if case in ("windows_extra_entry", "windows_changed_installer"):
        with zipfile.ZipFile(package, "w") as bundle:
            changed = case == "windows_changed_installer"
            bundle.writestr(installer, b"other installer" if changed else b"native CI installer fixture")
            if not changed:
                bundle.writestr("readme.txt", b"unexpected")
    elif case == "windows_raw_exe":
        (prepared / "windows" / installer).write_bytes(b"native CI installer fixture")
    elif case.startswith("windows"):
        path = prepared / "windows/build.json"
        info = json.loads(path.read_text())
        if case == "windows_shape":
            info = []
        elif case == "windows_edition":
            info["schema"] = "openaidr.windows-release.v1"
            info["build"] = {**INFO, "desktop_edition": "enterprise"}
        else:
            info[{"windows_hash": "sha256", "windows_commit": "commit", "windows_unsigned": "authenticode"}[case]] = "invalid"
        rollout.write_json(path, info)
    elif case == "linux_edition":
        path = prepared / "linux/build.json"
        info = json.loads(path.read_text())
        info["desktop_edition"] = "enterprise"
        rollout.write_json(path, info)
    elif case == "linux_signature":
        next((prepared / "linux").glob("*.deb.asc")).write_text("invalid signature")
    elif case == "notes":
        (prepared / "macos/release-notes.md").write_text("notes from another build")
    else:
        (prepared / "index.html").write_text("modified page")
    storage = MemoryStorage()
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        rollout.publish(prepared, storage, delivery(storage))
    assert not storage.uploads


@pytest.mark.parametrize("missing", [None, "darwin-aarch64", "windows-x86_64", "linux-x86_64"])
def test_publish_retires_only_intel_macs_and_preserves_old_files(rollout, prepared, missing):
    manifest = rollout.read_json(prepared / "release.json")
    previous = deepcopy(manifest)
    previous["version"] = previous["build"]["version"] = "2026.10.6+2b2b2b2"
    previous["build"]["source_commit"] = "2b" * 20
    previous["build"]["publication_timestamp"] -= 60
    previous["pub_date"] = previous["build"]["published_at"] = "2026-10-07T02:59:00+00:00"
    for key in ("platforms", "downloads"):
        previous[key]["darwin-x86_64"] = {"url": "https://releases.opensecura.ai/old-intel"}
    if missing:
        # A previously activated Windows or Linux updater must also be retained.
        for key in ("platforms", "downloads"):
            prior = deepcopy(previous)
            prior[key].setdefault(missing, {"url": "https://releases.opensecura.ai/previous"})
            candidate = deepcopy(manifest)
            candidate[key].pop(missing, None)
            with pytest.raises(ValueError, match=f"remove advertised {key}"):
                rollout.check_advance(prior, candidate)
        return
    storage = MemoryStorage()
    storage.objects[rollout.FEED] = (json.dumps(previous).encode(), 1)
    historical = "openaidr/2026.10.6+2b2b2b2/OpenAIDR-x86_64.dmg"
    link = f"{rollout.LATEST}/{rollout.INTEL_LINK}"
    storage.objects[historical] = storage.objects[link] = (b"last Intel installer", 1)
    storage.labels[link] = {"openaidr-version": previous["version"],
                            "openaidr-publication-timestamp": str(previous["build"]["publication_timestamp"])}
    rollout.publish(prepared, storage, delivery(storage))
    assert json.loads(storage.objects[rollout.FEED][0]) == manifest
    assert storage.objects[historical] == (b"last Intel installer", 1)
    # The fixed Intel link moves to the verified universal DMG; the feed lists no Intel updater.
    assert storage.objects[link] == ((prepared / "macos/OpenAIDR-aarch64.dmg").read_bytes(), 2)
    pointer = f"{rollout.REDIRECTS}/{rollout.INTEL_LINK}.txt"
    assert storage.objects[pointer][0] == manifest["downloads"]["darwin-aarch64"]["url"].encode()
    assert [name for name, _ in storage.uploads if "OpenAIDR-x86_64" in name] == [link, pointer]


def test_new_mac_release_must_be_universal(rollout, prepared):
    root = prepared.parent
    artifacts = make_artifacts(root / "thin-artifacts", universal=False)
    macos = root / "thin-macos"
    rollout.release.manifest(VERSION, prepared / "macos/release-notes.md", artifacts, macos)
    _, files = rollout.release_files(macos)
    assert not rollout.universal_mac(files)
    assert rollout.universal_mac(rollout.staged(prepared)[1])
    with pytest.raises(ValueError, match="must be universal"):
        rollout.prepare(macos, root / "windows", prepared / "linux",
                        rollout.read_json(prepared / "release.json")["rollout"], root / "thin-rollout")
    assert not (root / "thin-rollout").exists()


def test_publication_order_retained_targets_and_legacy_bypass(rollout, prepared):
    manifest = json.loads((prepared / "release.json").read_text())
    later = deepcopy(manifest)
    later["build"].update({"published_at": "2026-10-07T04:00:00+00:00", "publication_timestamp": 1791345600})
    later["pub_date"] = later["build"]["published_at"]
    # Publication order, not the lexical hash or date, selects the newer release.
    later["build"].update({"source_commit": "0a" * 20, "version": "2026.10.6+0a0a0a0"})
    later["version"] = later["build"]["version"]
    rollout.check_advance(manifest, later)
    with pytest.raises(ValueError, match="downgrade"):
        rollout.check_advance(later, manifest)
    equal_time = deepcopy(later)
    equal_time["build"].update({"published_at": INFO["published_at"], "publication_timestamp": INFO["publication_timestamp"]})
    equal_time["pub_date"] = INFO["published_at"]
    with pytest.raises(ValueError, match="replace"):
        rollout.check_advance(manifest, equal_time)
    del later["downloads"]["linux-x86_64"]
    with pytest.raises(ValueError, match="remove advertised"):
        rollout.check_advance(manifest, later)
    storage = MemoryStorage()
    storage.objects["openaidr/latest.json"] = ((prepared / "macos/latest.json").read_bytes(), 1)
    with pytest.raises(ValueError, match="already advertised"):
        rollout.publish(prepared, storage, delivery(storage))
    assert not storage.uploads
    # A broadly available release can seed the page, without pretending its
    # existing legacy downloads are gated by a new partial policy.
    manifest["rollout"] = {"schema_version": 1, "starts_at": "2026-10-07T03:00:00Z",
                           "paused": False, "steps": [{"after_hours": 0, "percent": 100}]}
    rollout.write_json(prepared / "release.json", manifest)
    rollout.publish(prepared, storage, delivery(storage))
    assert storage.objects["openaidr/latest.json"][1] == 1


@pytest.mark.parametrize("change", [
    {"schema_version": True}, {"schema_version": 2}, {"paused": 1}, {"extra": 1},
    {"starts_at": "2026-10-16T16:00:00"}, {"starts_at": "2026-10-16T16:00:00.5Z"},
    {"starts_at": "2026-10-16T16:00:00-07:00"}, {"starts_at": "2026-02-30T16:00:00Z"},
    {"steps": []}, {"steps": [{"after_hours": 1, "percent": 100}]},
    {"steps": [{"after_hours": 0, "percent": 101}]}, {"steps": [{"after_hours": 0, "percent": True}]},
    {"steps": [{"after_hours": -1, "percent": 100}]}, {"steps": [{"after_hours": 0, "percent": 90}]},
    {"steps": [{"after_hours": 0, "percent": 50}, {"after_hours": 24, "percent": 40}, {"after_hours": 48, "percent": 100}]},
    {"steps": [{"after_hours": 0, "percent": 1}, {"after_hours": 0, "percent": 100}]},
    {"steps": [{"after_hours": 0, "percent": 1}, {"after_hours": 2**63, "percent": 100}]},
    {"steps": [{"after_hours": False, "percent": 100}]},
])
def test_invalid_policy_is_rejected(rollout, change):
    with pytest.raises(ValueError):
        rollout.policy({**rollout.default_policy("2026-10-16T16:00:00Z"), **change})


def test_json_html_and_immutable_metadata_use_correct_cache_headers(rollout, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda args, **kwargs: calls.append(args))
    storage = rollout.Storage("release-bucket")
    for filename, mutable, mime in (("release.json", False, "application/json"),
                                    ("rollout-v2.json", True, "application/json"),
                                    ("index.html", True, "text/html; charset=utf-8")):
        storage.upload(tmp_path / filename, filename, 7, feed=mutable)
        assert f"--content-type={mime}" in calls[-1]
        assert "--if-generation-match=7" in calls[-1]
        cache = "public,max-age=60,must-revalidate" if mutable else "public,max-age=31536000,immutable"
        assert f"--cache-control={cache}" in calls[-1]
    storage.upload(tmp_path / "revision-1", rollout.FEED, 8, feed=True)
    assert "--content-type=application/json" in calls[-1]


@pytest.mark.parametrize("response", ["valid", "redirect", "oversized", "unavailable"])
def test_public_manifest_delivery_uses_a_bounded_direct_request(rollout, monkeypatch, response):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, self.headers.get("Cache-Control"), self.headers.get("User-Agent")))
            if response == "redirect" and self.path != "/redirected":
                self.send_response(302)
                self.send_header("Location", "/redirected")
                self.end_headers()
                return
            self.send_response(503 if response == "unavailable" else 200)
            self.end_headers()
            try:
                self.wfile.write(b" " * (rollout.LIMIT + 1) if response == "oversized" else b'{"version":"test"}')
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(rollout, "ORIGIN", f"http://127.0.0.1:{server.server_port}")
    try:
        if response == "valid":
            assert rollout.public_manifest() == {"version": "test"}
        else:
            with pytest.raises((ValueError, OSError)):
                rollout.public_manifest()
        assert requests[0] == ("/openaidr/rollout-v2.json", "no-cache", "OpenAIDR-release-verifier/1.0")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("start,paused,expected", [
    ("2026-10-16T16:00:01Z", False, 0),
    ("2026-10-16T16:00:00Z", False, 1),
    ("2026-10-15T16:00:01Z", False, 1),
    ("2026-10-15T16:00:00Z", False, 5),
    ("2026-10-10T16:00:01Z", False, 75),
    ("2026-10-10T16:00:00Z", False, 100),
    ("2026-10-10T16:00:00Z", True, 0),
])
def test_promotion_uses_elapsed_utc_schedule(rollout, start, paused, expected):
    policy = rollout.default_policy(start)
    policy["paused"] = paused
    assert rollout.percentage(policy) == expected
