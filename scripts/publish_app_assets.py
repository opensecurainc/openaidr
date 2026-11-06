#!/usr/bin/env python3
"""Attach the App workflow's installers to the Backend prerelease of the same version.

The Backend workflow creates the release with build.json and the Docker images.
The App workflow only keeps its installers as Actions artifacts. This script
downloads those artifacts, checks their names against what setup.sh installs,
uploads them to the release, and confirms GitHub's SHA-256 digests match.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REPO = "opensecurainc/openaidr"
VERSION = re.compile(r"\d{4}\.\d{1,2}\.\d{1,2}\+[0-9a-f]{7}")
PLATFORMS = ("aarch64.dmg", "x64-setup.exe", "amd64.deb", "amd64.AppImage")


def gh(*args, repo):
    return subprocess.check_output(["gh", *args, "--repo", repo], text=True)


def expected_names(tag):
    """Installer names Tauri produces for a version; setup.sh requires the DMG."""
    if not VERSION.fullmatch(tag):
        raise ValueError(f"not a release tag: {tag}")
    return [f"OpenAIDR_{tag}_{suffix}" for suffix in PLATFORMS]


def match_artifacts(paths, names):
    """Map each expected name to exactly one downloaded file."""
    found = {}
    for path in paths:
        if path.name in names:
            if path.name in found:
                raise ValueError(f"artifact appears twice: {path.name}")
            found[path.name] = path
    missing = [name for name in names if name not in found]
    if missing:
        raise ValueError("installers missing from the App artifacts: " + ", ".join(missing))
    return [found[name] for name in names]


def choose_run(runs, commit):
    """Newest successful App run for the release commit."""
    for run in runs:
        if run["headSha"] == commit and run["conclusion"] == "success":
            return run["databaseId"]
    raise ValueError(f"no successful App run for {commit[:7]}; dispatch App on that commit first")


def digest(path):
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def client_release(tag, commit, publication, assets):
    selected = json.loads(publication)
    if (selected.get("source_repository") != "opensecurainc/openaidr-internal"
            or not re.fullmatch(r"[0-9a-f]{40}", selected.get("source_commit", ""))
            or "src/openaidr/platform/" not in selected.get("exclude", [])):
        raise ValueError("release source is not a full client with private cloud code excluded")
    required = ["build.json", "openaidr-backend.tar.gz", *expected_names(tag)]
    if any(not re.fullmatch(r"sha256:[0-9a-f]{64}", assets.get(name, "")) for name in required):
        raise ValueError("complete release assets with SHA-256 digests are required")
    return dict(format=1, product="openaidr-full-client", source_commit=commit, version=tag,
                publication_sha256=hashlib.sha256(publication.encode()).hexdigest(),
                assets={name: assets[name] for name in required})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="release tag; defaults to this checkout's version")
    parser.add_argument("--run", type=int, help="App workflow run id; defaults to the run for the release commit")
    parser.add_argument("--repo", default=REPO)
    parser.add_argument("--dir", type=Path, default=ROOT / "build/app-assets", help="where artifacts are downloaded")
    parser.add_argument("--dry-run", action="store_true", help="download and verify, upload nothing")
    parser.add_argument("--no-download", action="store_true", help="reuse artifacts already in --dir")
    args = parser.parse_args()
    try:
        tag = args.tag or subprocess.check_output(
            [sys.executable, str(ROOT / "scripts/build_version.py"), "--format", "version"], text=True).strip()
        names = expected_names(tag)
        release = json.loads(gh("release", "view", tag, "--json", "tagName,targetCommitish,assets", repo=args.repo))
        commit = release["targetCommitish"]
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ValueError(f"release {tag} is not pinned to a commit: {commit}")
        if commit[:7] != tag.rsplit("+", 1)[1]:
            raise ValueError(f"release {tag} points at {commit[:7]}, which does not match its tag")
        run_id = args.run or choose_run(json.loads(gh(
            "run", "list", "--workflow", "App", "--limit", "50",
            "--json", "databaseId,headSha,conclusion", repo=args.repo)), commit)
        run = json.loads(gh("run", "view", str(run_id), "--json", "headSha,conclusion,workflowName", repo=args.repo))
        if run != {"headSha": commit, "conclusion": "success", "workflowName": "App"}:
            raise ValueError("App run must be successful and built from the exact release commit")
        publication = subprocess.check_output(["gh", "api", f"repos/{args.repo}/contents/PUBLICATION.json?ref={commit}",
                                               "--header", "Accept: application/vnd.github.raw+json"], text=True)
        directory = args.dir / tag
        directory.mkdir(parents=True, exist_ok=True)
        if not args.no_download:
            subprocess.check_call(["gh", "run", "download", str(run_id), "--repo", args.repo, "--dir", str(directory)])
        files = match_artifacts(sorted(directory.rglob("OpenAIDR_*")), names)
        present = {asset["name"]: asset.get("digest", "") for asset in release.get("assets", [])}
        local = {path.name: digest(path) for path in files}
        for path in files:
            if path.name in present and local[path.name] != present[path.name]:
                raise ValueError("immutable release asset differs: " + path.name)
            state = "already on release" if path.name in present else "new"
            print(f"{path.name}  {path.stat().st_size} bytes  {local[path.name]}  {state}")
        manifest = directory / "client-release.json"
        manifest.write_text(json.dumps(client_release(tag, commit, publication, {**present, **local}), indent=2) + "\n")
        if manifest.name in present and present[manifest.name] != digest(manifest):
            raise ValueError("immutable full-client manifest differs")
        if args.dry_run:
            print(f"Dry run: nothing uploaded to {tag} (App run {run_id}, commit {commit[:7]}).")
            return
        missing = [str(path) for path in files if path.name not in present]
        if missing:
            subprocess.check_call(["gh", "release", "upload", tag, *missing, "--repo", args.repo])
        uploaded = {asset["name"]: asset.get("digest", "") for asset in json.loads(
            gh("release", "view", tag, "--json", "assets", repo=args.repo))["assets"]}
        wrong = [name for name, value in local.items() if uploaded.get(name) != value]
        if wrong:
            raise ValueError("release digests do not match the uploaded files: " + ", ".join(wrong))
        if manifest.name not in present:
            subprocess.check_call(["gh", "release", "upload", tag, str(manifest), "--repo", args.repo])
        final = {asset["name"]: asset.get("digest", "") for asset in json.loads(
            gh("release", "view", tag, "--json", "assets", repo=args.repo))["assets"]}
        if final.get(manifest.name) != digest(manifest):
            raise ValueError("full-client manifest digest differs after upload")
        print(f"Published complete full-client release {tag}; installer and manifest digests verified.")
    except (OSError, ValueError, subprocess.CalledProcessError, KeyError) as error:
        parser.exit(1, f"publish app assets: {error}\n")


if __name__ == "__main__":
    main()
