"""Asset naming and run selection for scripts/publish_app_assets.py."""
import json
from pathlib import Path
import runpy

import pytest

publish = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/publish_app_assets.py"))
TAG = "2026.10.20+827c3b5"


def test_expected_names_follow_the_installer_layout():
    assert publish["expected_names"](TAG) == [
        f"OpenAIDR_{TAG}_aarch64.dmg", f"OpenAIDR_{TAG}_x64-setup.exe",
        f"OpenAIDR_{TAG}_amd64.deb", f"OpenAIDR_{TAG}_amd64.AppImage",
    ]
    with pytest.raises(ValueError):
        publish["expected_names"]("v1.2.3")


def test_match_artifacts_requires_each_installer_once():
    names = publish["expected_names"](TAG)
    paths = [Path(f"download/{platform}/{name}") for platform, name in zip(("dmg", "nsis", "deb", "appimage"), names)]
    assert publish["match_artifacts"](paths + [Path("download/other/notes.txt")], names) == paths
    with pytest.raises(ValueError, match="missing"):
        publish["match_artifacts"](paths[:-1], names)
    with pytest.raises(ValueError, match="twice"):
        publish["match_artifacts"](paths + [Path("again/" + names[0])], names)


def test_choose_run_takes_the_newest_successful_run_for_the_commit():
    commit = "a" * 40
    runs = [
        {"databaseId": 3, "headSha": commit, "conclusion": "failure"},
        {"databaseId": 2, "headSha": commit, "conclusion": "success"},
        {"databaseId": 1, "headSha": commit, "conclusion": "success"},
    ]
    assert publish["choose_run"](runs, commit) == 2
    with pytest.raises(ValueError, match="dispatch App"):
        publish["choose_run"](runs, "b" * 40)


def test_full_client_manifest_requires_publication_boundary_and_all_artifacts():
    publication = dict(source_repository="opensecurainc/openaidr-internal", source_commit="b" * 40,
                       exclude=["src/openaidr/platform/"])
    assets = {name: "sha256:" + "c" * 64 for name in
              ["build.json", "openaidr-backend.tar.gz", *publish["expected_names"](TAG)]}
    result = publish["client_release"](TAG, "a" * 40, json.dumps(publication), assets)
    assert result["assets"] == assets and result["product"] == "openaidr-full-client"
    with pytest.raises(ValueError, match="cloud code"):
        publish["client_release"](TAG, "a" * 40, json.dumps({**publication, "exclude": []}), assets)
    with pytest.raises(ValueError, match="complete release"):
        publish["client_release"](TAG, "a" * 40, json.dumps(publication), {})
