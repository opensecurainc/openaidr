"""Release channels select the update feed and verification key at build time."""

import base64
import importlib
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def builder(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("build_desktop")


def test_enterprise_channel_is_the_default(builder, monkeypatch):
    monkeypatch.delenv("OPENAIDR_RELEASE_CHANNEL", raising=False)
    assert builder.release_channel() == "openaidr"
    assert builder.release_feed("openaidr") == "https://releases.opensecura.ai/openaidr/rollout-v2.json"
    assert builder.updater_public_key("openaidr") == ROOT / "deploy/desktop/updater.pub"


def test_oss_channel_uses_its_own_feed_and_key(builder, monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAIDR_RELEASE_CHANNEL", "openaidr-oss")
    assert builder.release_channel() == "openaidr-oss"
    assert builder.release_feed("openaidr-oss") == "https://releases.opensecura.ai/openaidr-oss/rollout-v2.json"
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="deploy/desktop/updater-oss.pub"):
        builder.updater_public_key("openaidr-oss")
    key = tmp_path / "deploy/desktop/updater-oss.pub"
    key.parent.mkdir(parents=True)
    key.write_text("untrusted comment: test key\n")
    assert builder.updater_public_key("openaidr-oss") == key


def test_unknown_channel_is_rejected(builder, monkeypatch):
    monkeypatch.setenv("OPENAIDR_RELEASE_CHANNEL", "staging")
    with pytest.raises(ValueError, match="OPENAIDR_RELEASE_CHANNEL"):
        builder.release_channel()


def test_oss_updater_pins_external_public_key_without_an_enterprise_fallback(builder, monkeypatch, tmp_path):
    public = b"untrusted comment: minisign public key\n" + base64.b64encode(b"Ed" + b"a" * 40) + b"\n"
    path = tmp_path / "oss.pub"
    path.write_bytes(public)
    monkeypatch.setenv("OPENAIDR_OSS_UPDATER_PUBLIC_KEY_FILE", str(path))
    monkeypatch.setenv("OPENAIDR_RELEASE_CHANNEL", "openaidr-oss")
    monkeypatch.setenv("OPENAIDR_RELEASE_DATE", "2026-11-07T12:00:00Z")
    assert builder.updater_public_key("openaidr") == ROOT / "deploy/desktop/updater.pub"
    settings = builder.oss_updater_settings()["updater"]
    assert base64.b64decode(settings["pubkey"]) == public
    assert settings["endpoints"] == ["https://releases.opensecura.ai/openaidr-oss/rollout-v2.json"]
    enterprise = (ROOT / "deploy/desktop/updater.pub").read_bytes().splitlines()[1]
    path.write_bytes(b"untrusted comment: different label, same signing key\n" + enterprise + b"\n")
    with pytest.raises(ValueError, match="separate key"):
        builder.oss_updater_settings()
    path.unlink()
    with pytest.raises(ValueError, match="release channel requires"):
        builder.oss_updater_settings()


@pytest.mark.parametrize("contents", [b"", b"secret key", b"untrusted comment: test\nnot-base64\n",
                                      b"untrusted comment: test\n" + base64.b64encode(b"Ed" + b"a" * 39)])
def test_oss_updater_rejects_invalid_verification_keys(builder, monkeypatch, tmp_path, contents):
    path = tmp_path / "oss.pub"
    path.write_bytes(contents)
    monkeypatch.setenv("OPENAIDR_RELEASE_CHANNEL", "openaidr-oss")
    monkeypatch.setenv("OPENAIDR_RELEASE_DATE", "2026-11-07T12:00:00Z")
    monkeypatch.setenv("OPENAIDR_OSS_UPDATER_PUBLIC_KEY_FILE", str(path))
    with pytest.raises(ValueError, match="Minisign public"):
        builder.oss_updater_settings()


def test_oss_updater_requires_explicit_channel_and_publication(builder, monkeypatch):
    monkeypatch.delenv("OPENAIDR_RELEASE_CHANNEL", raising=False)
    with pytest.raises(ValueError, match="OPENAIDR_RELEASE_CHANNEL"):
        builder.oss_updater_settings()
    monkeypatch.setenv("OPENAIDR_RELEASE_CHANNEL", "openaidr-oss")
    monkeypatch.delenv("OPENAIDR_RELEASE_DATE", raising=False)
    with pytest.raises(ValueError, match="OPENAIDR_RELEASE_DATE"):
        builder.oss_updater_settings()


@pytest.mark.parametrize("option", ["--sidecar-only", "--simulation", "--e2e-ui"])
def test_oss_updater_rejects_non_distribution_builds_before_building(builder, monkeypatch, tmp_path, capsys, option):
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    monkeypatch.setattr(builder.sys, "platform", "darwin")
    monkeypatch.setattr(sys, "argv", ["build_desktop.py", "--oss-updater", option])
    with pytest.raises(SystemExit) as error:
        builder.main()
    assert error.value.code == 2
    assert "--oss-updater requires a distributable desktop build" in capsys.readouterr().err
    assert not (tmp_path / "build").exists()
