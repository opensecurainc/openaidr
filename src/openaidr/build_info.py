"""Source identity shared by Python, frontend, and native builds."""

from datetime import datetime, timezone
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import subprocess
from zoneinfo import ZoneInfo


VERSION = re.compile(r"([0-9]{4})\.([1-9][0-9]?)\.([1-9][0-9]?)\+([0-9a-f]{7,40})")


def validate(info):
    """Validate transported metadata without trusting a separately supplied version."""
    if not isinstance(info, dict):
        raise ValueError("build metadata must be an object")
    commit = info.get("source_commit", "")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("build metadata requires a full lowercase source commit SHA")
    stamp = info.get("source_timestamp")
    if type(stamp) is not int or stamp <= 0:
        raise ValueError("build metadata requires the source committer timestamp")
    day = datetime.fromtimestamp(stamp, ZoneInfo("America/Los_Angeles"))
    version = info.get("version")
    match = VERSION.fullmatch(version) if isinstance(version, str) else None
    if (not match or not commit.startswith(match[4])
            or info["version"].split("+")[0] != f"{day.year}.{day.month}.{day.day}"):
        raise ValueError("build version must match the source commit and its Los Angeles date")
    if not isinstance(info.get("built_at"), str):
        raise ValueError("build timestamp must be a UTC timestamp string")
    built = datetime.fromisoformat(info["built_at"].replace("Z", "+00:00"))
    if built.tzinfo is None or built.utcoffset().total_seconds() != 0:
        raise ValueError("build timestamp must include the UTC timezone")
    published = info.get("published_at")
    if published is not None:
        if not isinstance(published, str) or type(info.get("publication_timestamp")) is not int:
            raise ValueError("publication metadata requires a UTC timestamp string and integer timestamp")
        value = datetime.fromisoformat(published.replace("Z", "+00:00"))
        if value.tzinfo is None or value.utcoffset().total_seconds() != 0 or value.microsecond:
            raise ValueError("publication time must be UTC with whole-second precision")
        if int(value.timestamp()) <= 0:
            raise ValueError("publication time must be positive")
        if info.get("publication_timestamp") != int(value.timestamp()):
            raise ValueError("publication timestamp does not match publication time")
    elif info.get("publication_timestamp") is not None:
        raise ValueError("publication timestamp requires a publication time")
    return info


# Commands that only describe or link the working tree. Every other setuptools
# command produces an artifact and requires a committed source identity.
LENIENT_COMMANDS = frozenset(("egg_info", "dist_info", "editable_wheel", "develop"))


def requires_clean_source(argv):
    """Whether a setup.py invocation must refuse uncommitted changes.

    Any command word outside the lenient set makes the whole run strict, so
    ``egg_info bdist_wheel`` and legacy commands such as ``bdist_egg`` fail
    closed the way every invocation did before editable installs were relaxed.
    """
    words = [arg for arg in argv[1:] if re.fullmatch(r"[a-z_]+", arg)]
    return not words or any(word not in LENIENT_COMMANDS for word in words)


def resolve(root, *, clean=True, environ=None):
    """Resolve a checkout or explicitly identified Git-free build context."""
    root = Path(root).resolve()
    env = os.environ if environ is None else environ
    commit = env.get("OPENAIDR_BUILD_COMMIT", "")
    stamp = env.get("OPENAIDR_COMMIT_TIMESTAMP", "")
    if (root / ".git").exists():
        def git(*args):
            return subprocess.check_output(
                ["git", *args], cwd=root, text=True, stderr=subprocess.PIPE,
            ).strip()
        if clean and git("status", "--porcelain", "--untracked-files=normal"):
            raise ValueError("commit the intended changes before building OpenAIDR")
        actual_commit, actual_stamp = git("show", "-s", "--format=%H %ct", "HEAD").split()
        if (commit and commit != actual_commit) or (stamp and str(stamp) != actual_stamp):
            raise ValueError("supplied build identity does not match the checkout")
        commit, stamp = actual_commit, actual_stamp
    else:
        # An sdist carries the exact metadata selected when it was created.
        saved = root / "src/openaidr/_build.json"
        if saved.is_file():
            info = validate(json.loads(saved.read_text()))
            for key, value in environment(info).items():
                if env.get(key) and env[key] != value:
                    raise ValueError("supplied build identity does not match the source archive")
            return info
    if not commit or not stamp:
        raise ValueError("Git-free builds require OPENAIDR_BUILD_COMMIT and OPENAIDR_COMMIT_TIMESTAMP")
    stamp = int(stamp)
    day = datetime.fromtimestamp(stamp, ZoneInfo("America/Los_Angeles"))
    info = {
        "version": env.get("OPENAIDR_VERSION") or f"{day.year}.{day.month}.{day.day}+{commit[:7]}",
        "source_commit": commit,
        "source_timestamp": stamp,
        "built_at": env.get("OPENAIDR_BUILD_DATE") or datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if env.get("OPENAIDR_RELEASE_DATE"):
        info["published_at"] = env["OPENAIDR_RELEASE_DATE"]
        info["publication_timestamp"] = int(datetime.fromisoformat(info["published_at"].replace("Z", "+00:00")).timestamp())
    return validate(info)


def environment(info):
    validate(info)
    result = {
        "OPENAIDR_VERSION": info["version"],
        "OPENAIDR_BUILD_COMMIT": info["source_commit"],
        "OPENAIDR_COMMIT_TIMESTAMP": str(info["source_timestamp"]),
        "OPENAIDR_BUILD_DATE": info["built_at"],
    }
    if info.get("published_at"):
        result["OPENAIDR_RELEASE_DATE"] = info["published_at"]
    return result


def for_version(version):
    info = current()
    return info if info["version"] == version else None


def order(info):
    """Published artifacts use publication time; local builds use source time.

    Never order hashes. A local build cannot silently replace a published one.
    Equal timestamps for distinct identities are ambiguous, so callers keep the
    existing artifact instead of assigning either one a later order.
    """
    validate(info)
    if info.get("published_at"):
        return (1, int(datetime.fromisoformat(info["published_at"].replace("Z", "+00:00")).timestamp()))
    return (0, info["source_timestamp"])


@lru_cache(maxsize=1)
def current():
    """Installed artifacts use embedded metadata, never runtime environment overrides."""
    saved = Path(__file__).with_name("_build.json")
    if saved.is_file():
        return validate(json.loads(saved.read_text()))
    # Editable/source execution may be dirty. Artifact creation always uses the
    # strict resolver above. Do not add Git work to ordinary package imports.
    return resolve(Path(__file__).resolve().parents[2], clean=False, environ={})
