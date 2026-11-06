"""WorkBuddy profile locations shared by inventory and telemetry setup."""

import os
from pathlib import Path


def config_roots(home=None):
    """Return candidate profiles without reading or creating their directories."""
    override = os.environ.get("WORKBUDDY_CONFIG_DIR", "").strip()
    if override:
        return (Path(override).expanduser(),)
    home = Path(home) if home is not None else Path.home()
    return (home / ".workbuddy", home / ".workbuddy-ai")
