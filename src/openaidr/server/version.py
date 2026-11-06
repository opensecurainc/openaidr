"""Report the shared build identity without making health depend on metadata."""

import subprocess

from openaidr import build_info


def build_metadata():
    try:
        return build_info.current()
    except (OSError, ValueError, KeyError, TypeError, OverflowError, subprocess.SubprocessError):
        # An unversioned installation can still serve traffic and report health.
        return None


def server_version():
    return (build_metadata() or {}).get("version", "")


__version__ = server_version()
