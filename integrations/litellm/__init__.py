"""Load only inside an operator-approved LiteLLM runtime."""

import json
from importlib.metadata import version
from pathlib import Path

from .handler import OpenAIDRPlugin, Settings

_build = json.loads(Path(__file__).with_name("_build.json").read_text())
plugin = OpenAIDRPlugin(Settings.from_env(), _build["version"], version("litellm"))


async def startup():
    """Called once per proxy worker through LITELLM_WORKER_STARTUP_HOOKS."""
    await plugin.start()
