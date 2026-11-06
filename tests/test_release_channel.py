"""Release channels select the update feed and verification key at build time."""

import importlib
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
