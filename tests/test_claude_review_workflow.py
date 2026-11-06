"""Exercise the review workflow's executable setup without network or credentials."""
import os
from pathlib import Path
import subprocess

import pytest
import yaml


@pytest.mark.skipif(os.name == "nt", reason="The review runs on an Ubuntu runner")
@pytest.mark.parametrize("cached,install_exit", [(True, 0), (False, 0), (False, 22)])
def test_claude_executable_setup(tmp_path, cached, install_exit):
    workflow = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / ".github/workflows/claude-review.yml").read_text()
    )
    job = workflow["jobs"]["review"]
    step = next(step for step in job["steps"] if step.get("id") == "claude-cli")
    prefix = tmp_path / "installation with spaces"
    executable = prefix / "bin/claude"
    executable.parent.mkdir(parents=True)
    template = tmp_path / "claude-template"
    template.write_text('#!/bin/sh\n[ "$1" = "--version" ] || exit 1\necho "$CLAUDE_CODE_VERSION (Claude Code)"\n')
    template.chmod(0o755)
    if cached:
        executable.write_bytes(template.read_bytes())
        executable.chmod(0o755)

    tools = tmp_path / "tools"
    tools.mkdir()
    npm = tools / "npm"
    npm.write_text(
        '#!/bin/sh\nset -eu\n'
        'printf "%s\\n" "$@" > "$NPM_CALL"\n'
        '[ "$INSTALL_EXIT" = 0 ] || exit "$INSTALL_EXIT"\n'
        'cp "$CLAUDE_TEMPLATE" "$CLAUDE_CODE_PREFIX/bin/claude"\n'
        'chmod +x "$CLAUDE_CODE_PREFIX/bin/claude"\n'
    )
    npm.chmod(0o755)
    npm_call = tmp_path / "npm-call"
    env = {
        **os.environ,
        "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}",
        "CLAUDE_CODE_VERSION": job["env"]["CLAUDE_CODE_VERSION"],
        "CLAUDE_CODE_PREFIX": str(prefix),
        "CLAUDE_TEMPLATE": str(template),
        "NPM_CALL": str(npm_call),
        "INSTALL_EXIT": str(install_exit),
    }
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", step["run"]],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == install_exit, result.stderr
    if cached:
        assert not npm_call.exists()
    else:
        assert npm_call.read_text().splitlines() == [
            "install", "--global", "--prefix", str(prefix),
            f"@anthropic-ai/claude-code@{env['CLAUDE_CODE_VERSION']}",
        ]
    if install_exit:
        assert not result.stdout
        assert not executable.exists()
    else:
        assert result.stdout.strip() == f"{env['CLAUDE_CODE_VERSION']} (Claude Code)"
