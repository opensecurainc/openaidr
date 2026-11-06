"""Real competing writers, with pipes fixing the order at publication boundaries."""

import errno
import json
import os
import queue
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
import tomlkit

from openaidr.core import files
from openaidr.sensor import hooks, integrations
from openaidr.sensor.config import Config


@contextmanager
def writer(script, *args):
    process = subprocess.Popen(
        [sys.executable, "-c", script, *map(str, args)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    try:
        yield process
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)


def paused(process):
    lines = queue.Queue()
    thread = threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True)
    thread.start()
    assert lines.get(timeout=10).strip() == "paused"
    thread.join(timeout=1)


def finish(process):
    stdout, stderr = process.communicate("continue\n", timeout=15)
    assert process.returncode == 0, (stdout, stderr)
    return stdout


def test_atomic_writers_never_share_a_temporary_inode(tmp_path):
    target = tmp_path / "state.json"
    # An old or unrelated temp file must not be truncated or unlinked.
    old_temp = tmp_path / "state.json.tmp"
    old_temp.write_text("untouched")
    script = '''
import sys
from openaidr.core import files
original = files.os.fdopen
def pause(fd, *args, **kwargs):
    stream = original(fd, *args, **kwargs)
    print("paused", flush=True)
    assert sys.stdin.readline().strip() == "continue"
    return stream
files.os.fdopen = pause
files.atomic_write(sys.argv[1], sys.argv[2])
'''
    first, second = json.dumps({"short": 1}), json.dumps({"long": "x" * 10000})
    with writer(script, target, first) as a, writer(script, target, second) as b:
        paused(a)
        paused(b)
        finish(b)
        assert target.read_text() == second
        finish(a)
    assert json.loads(target.read_text()) == {"short": 1}
    assert old_temp.read_text() == "untouched"
    assert list(tmp_path.glob("*.tmp")) == [old_temp]
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o600


def test_atomic_failure_keeps_destination_and_cleans_own_temporary_file(tmp_path, monkeypatch):
    target = tmp_path / "state.json"
    target.write_text('{"old": true}')

    def fail(*args):
        raise OSError("disk full")

    monkeypatch.setattr(files.os, "replace", fail)
    with pytest.raises(OSError, match="disk full"):
        files.atomic_write(target, '{"new": true}')
    assert json.loads(target.read_text()) == {"old": True}
    assert not list(tmp_path.glob("*.tmp"))


PAUSE_BOUNDARY = '''
import sys
from pathlib import Path
from openaidr.sensor import hooks, settings_files
original = settings_files.SettingsFiles.commit
paused = False
def commit(self):
    global paused
    if not paused:
        paused = True
        print("paused", flush=True)
        assert sys.stdin.readline().strip() == "continue"
    return original(self)
settings_files.SettingsFiles.commit = commit
'''

PAUSE_COMMIT = PAUSE_BOUNDARY + '''
agent, action = sys.argv[1:3]
path, trust = map(Path, sys.argv[3:5])
if agent == "codex":
    getattr(hooks, action + "_codex")(path, config_toml=trust)
else:
    getattr(hooks, action)(path)
'''


@pytest.mark.parametrize("agent", ["claude", "codex"])
@pytest.mark.parametrize("action", ["install", "uninstall"])
def test_hooks_and_telemetry_share_locks_and_cli_reports_contention(tmp_path, agent, action):
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"),
                 telemetry={"local_token": "isolated"})
    cfg.save()
    hook_path, trust = tmp_path / "hooks.json", tmp_path / "config.toml"
    target = hook_path if agent == "claude" else trust
    if agent == "claude":
        target.write_text('{"permissions": {"allow": ["Read"]}}')
    else:
        target.write_text('model = "retained"\n')
    if action == "uninstall":
        if agent == "claude":
            hooks.install(hook_path)
        else:
            hooks.install_codex(hook_path, config_toml=trust)
        integrations.install(cfg, [agent], {agent: target})
    command = [sys.executable, "-m", "openaidr.sensor.cli", "telemetry",
               "configure" if action == "install" else "remove", "--config", str(cfg.path), "--agent", agent,
               "--claude-settings" if agent == "claude" else "--codex-config", str(target)]
    with writer(PAUSE_COMMIT, agent, action, hook_path, trust) as process:
        paused(process)
        original = target.read_bytes()
        conflict = subprocess.run(command, text=True, capture_output=True, timeout=15)
        assert conflict.returncode == 1
        assert "another OpenAIDR process; retry" in conflict.stderr
        assert '"installed": true' not in conflict.stdout
        assert target.read_bytes() == original
        finish(process)
    retry = subprocess.run(command, text=True, capture_output=True, timeout=15)
    assert retry.returncode == 0, retry.stderr
    document = integrations.load(target, agent)
    if agent == "claude":
        assert document["permissions"]["allow"] == ["Read"]
    else:
        assert document["model"] == "retained"
    assert integrations.current(Config.load(cfg.path), agent, target) == (action == "install")
    installed = bool(hooks.load_settings(hook_path).get("hooks"))
    assert installed == (action == "install")
    if agent == "codex" and action == "install":
        assert hooks.codex_trusted(hook_path, trust)


@pytest.mark.parametrize("agent", ["claude", "codex"])
@pytest.mark.parametrize("action", ["install", "uninstall"])
def test_external_edits_are_reloaded_before_hook_publication(tmp_path, agent, action):
    hook_path, trust = tmp_path / "hooks.json", tmp_path / "config.toml"
    if action == "uninstall":
        if agent == "codex":
            hooks.install_codex(hook_path, config_toml=trust)
        else:
            hooks.install(hook_path)
    with writer(PAUSE_COMMIT, agent, action, hook_path, trust) as process:
        paused(process)
        document = hooks.load_settings(hook_path)
        document["permissions"] = {"deny": ["Bash(rm *)"]}
        user_hook = {"hooks": [{"type": "command", "command": "user-hook"}]}
        document.setdefault("hooks", {}).setdefault("Stop", []).append(user_hook)
        # This process acts like an editor and deliberately ignores lock files.
        hook_path.write_text(json.dumps(document))
        if agent == "codex":
            config = hooks.load_codex_config(trust)
            config["model"] = "new-choice"
            trust.write_text(tomlkit.dumps(config))
        finish(process)
    document = hooks.load_settings(hook_path)
    assert document["permissions"] == {"deny": ["Bash(rm *)"]}
    assert user_hook in document["hooks"]["Stop"]
    if agent == "codex":
        assert hooks.load_codex_config(trust)["model"] == "new-choice"
        assert hooks.codex_trusted(hook_path, trust) == (action == "install")


@pytest.mark.parametrize("action", ["install", "uninstall"])
@pytest.mark.parametrize("failure", ["conflict", "crash_before_trust", "crash_after_trust"])
def test_codex_partial_publication_recovers_positional_trust(tmp_path, monkeypatch, action, failure):
    hook_path, trust = tmp_path / "hooks.json", tmp_path / "config.toml"
    hooks.install_codex(hook_path, config_toml=trust)
    document = hooks.load_settings(hook_path)
    group = document["hooks"]["PreToolUse"][0]
    # Equal commands can have different user enablement. Hash matching alone
    # cannot recover their positional trust after removing our first handler.
    user = {"type": "command", "command": "user-hook"}
    group["hooks"].extend([user, user])
    hook_path.write_text(json.dumps(document))
    config = hooks.load_codex_config(trust)
    config["model"] = "original"
    state = hooks.codex_state(config)
    prefix = f"{hook_path}:pre_tool_use:0:"
    digest = hooks.codex_hook_hash("PreToolUse", group, user)
    for index, enabled in [(1, False), (2, True)]:
        state[prefix + str(index)] = {"trusted_hash": digest, "enabled": enabled}
    trust.write_text(tomlkit.dumps(config))
    monkeypatch.setattr(hooks, "settings_path", lambda *_: hook_path)
    script = '''
import sys
from pathlib import Path
from openaidr.sensor import hooks, settings_files
action, failure, hook, trust = sys.argv[1:]
original = settings_files.atomic_write
original_delete = settings_files.SettingsFiles.delete
def pause():
    print("paused", flush=True)
    assert sys.stdin.readline().strip() == "continue"
def write(path, text, **kwargs):
    if path == Path(trust) and failure != "crash_after_trust":
        pause()
    return original(path, text, **kwargs)
def delete(self, path):
    if path == hooks.codex_pending_path(hook) and failure == "crash_after_trust":
        pause()
    return original_delete(self, path)
settings_files.atomic_write = write
settings_files.SettingsFiles.delete = delete
try:
    getattr(hooks, action + "_codex")(hook, config_toml=trust)
except OSError as exc:
    assert "partial update" in str(exc), str(exc)
    print(str(exc))
else:
    raise AssertionError("partial publication reported success")
'''
    with writer(script, action, failure, hook_path, trust) as process:
        paused(process)
        assert hooks.load_settings(hook_path)["hooks"]["PreToolUse"][0]["hooks"] == [user, user]
        config = hooks.load_codex_config(trust)
        config["model"] = "external"
        hooks.codex_state(config)["unrelated-hook"] = {"enabled": False}
        trust.write_text(tomlkit.dumps(config))
        if failure == "conflict":
            assert "partial update" in finish(process)
    journal = hooks.codex_pending_path(hook_path)
    assert journal.exists()
    if os.name != "nt":
        assert journal.stat().st_mode & 0o777 == 0o600
    assert not hooks.codex_trusted(hook_path, trust)
    assert not hooks.current(None, "codex")
    if action == "uninstall":
        before = [path.read_bytes() for path in (hook_path, trust, journal)]
        with pytest.raises(OSError, match="retry hook uninstall"):
            hooks.install_codex(hook_path, config_toml=trust)
        assert [path.read_bytes() for path in (hook_path, trust, journal)] == before
    for _ in range(2):
        getattr(hooks, action + "_codex")(hook_path, config_toml=trust)
        assert not journal.exists()
        config = hooks.load_codex_config(trust)
        assert config["model"] == "external"
        state = hooks.codex_state(config)
        assert state["unrelated-hook"]["enabled"] is False
        assert state[prefix + "0"] == {"trusted_hash": digest, "enabled": False}
        assert state[prefix + "1"] == {"trusted_hash": digest, "enabled": True}
        assert prefix + "2" not in state
        assert hooks.codex_trusted(hook_path, trust) == (action == "install")


@pytest.mark.parametrize("change", ["hooks", "trust", "version", "target"])
def test_ambiguous_or_invalid_codex_recovery_preserves_files(tmp_path, monkeypatch, change):
    from openaidr.sensor import settings_files

    hook_path, trust = tmp_path / "hooks.json", tmp_path / "config.toml"
    original = settings_files.atomic_write

    def fail(path, text, **kwargs):
        if path == trust:
            raise OSError("injected failure")
        return original(path, text, **kwargs)

    monkeypatch.setattr(settings_files, "atomic_write", fail)
    with pytest.raises(OSError, match="injected failure"):
        hooks.install_codex(hook_path, config_toml=trust)
    monkeypatch.setattr(settings_files, "atomic_write", original)
    journal = hooks.codex_pending_path(hook_path)
    record = json.loads(journal.read_text())
    secret = "private-user-value"
    foreign = tmp_path / "foreign.toml"
    foreign.write_text('model = "untouched"\n')
    if change == "hooks":
        document = hooks.load_settings(hook_path)
        document["private"] = secret
        hook_path.write_text(json.dumps(document))
    elif change == "trust":
        config = hooks.trust_document(trust, {}, set())
        hooks.codex_state(config)[record["keys"][0]] = {"trusted_hash": secret}
        trust.write_text(tomlkit.dumps(config))
    else:
        record["version" if change == "version" else "trust_path"] = 2 if change == "version" else str(foreign)
        journal.write_text(json.dumps(record))
    paths = (hook_path, trust, journal, foreign)
    before = [files.file_content(path) for path in paths]
    for action in ("install", "uninstall"):
        with pytest.raises(OSError, match="administrator to recover") as error:
            getattr(hooks, action + "_codex")(hook_path, config_toml=trust)
        assert secret not in str(error.value)
        assert [files.file_content(path) for path in paths] == before


@pytest.mark.parametrize("agent", ["claude", "codex"])
@pytest.mark.parametrize("action", ["install", "remove", "disconnect"])
def test_external_telemetry_edits_preserve_permissions_and_accurate_undo(tmp_path, agent, action):
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"),
                 telemetry={"local_token": "isolated"})
    cfg.save()
    target = tmp_path / ("config.toml" if agent == "codex" else "settings.json")
    if action in ("remove", "disconnect"):
        integrations.install(cfg, [agent], {agent: target})
        if action == "disconnect":
            integrations.manifest_path(cfg).unlink()
    else:
        target.write_text(integrations.serialize({"model": "original"}, agent))
    script = PAUSE_BOUNDARY + '''
from openaidr.sensor import integrations
from openaidr.sensor.config import Config
agent, action, target, config = sys.argv[1:5]
if action == "disconnect":
    result = integrations.remove(Config.load(config), [agent], {agent: target}, disconnect=True)
else:
    result = getattr(integrations, action)(Config.load(config), [agent], {agent: target})
print(__import__("json").dumps(result))
'''
    with writer(script, agent, action, target, cfg.path) as process:
        paused(process)
        document = integrations.load(target, agent)
        section, field, value = (
            ("otel", "log_user_prompt", True) if agent == "codex"
            else ("env", "OTEL_LOG_USER_PROMPTS", "1")
        )
        document.setdefault(section, {})[field] = value
        document["model"] = "user-choice"
        target.write_text(integrations.serialize(document, agent))
        before_install = target.read_bytes()
        result = json.loads(finish(process))
    document = integrations.load(target, agent)
    assert document["model"] == "user-choice"
    if action == "install":
        assert integrations.backup_path(target).read_bytes() == before_install
        integrations.remove(Config.load(cfg.path), [agent], {agent: target})
        restored = integrations.load(target, agent)
        assert restored[section][field] == value
        assert restored["model"] == "user-choice"
    elif action == "remove":
        assert document[section][field] == value
        assert section + "." + field in result["agents"][0]["conflicts"]
    else:
        assert document[section][field] == value
        assert not integrations.managed_present(cfg, agent, target)
        assert result["agents"][0]["opted_out"]


def test_repeated_external_changes_fail_without_overwriting_latest_settings(tmp_path):
    target = tmp_path / "settings.json"
    script = '''
import sys
from openaidr.sensor import hooks, settings_files
original = settings_files.SettingsFiles.commit
def commit(self):
    print("paused", flush=True)
    assert sys.stdin.readline().strip() == "continue"
    return original(self)
settings_files.SettingsFiles.commit = commit
try:
    hooks.install(sys.argv[1])
except OSError as exc:
    assert "changed during setup; retry" in str(exc), str(exc)
else:
    raise AssertionError("continuous edits reported success")
'''
    with writer(script, target) as process:
        for version in range(3):
            paused(process)
            target.write_text(json.dumps({"external": version}))
            if version < 2:
                process.stdin.write("continue\n")
                process.stdin.flush()
            else:
                finish(process)
    assert json.loads(target.read_text()) == {"external": 2}
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.skipif(os.name == "nt", reason="User-created symlinks require elevated Windows privileges")
def test_codex_symlink_keeps_logical_trust_keys_and_uses_target_lock(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    hook_path, trust = alias / "hooks.json", alias / "config.toml"
    with writer(PAUSE_COMMIT, "codex", "install", hook_path, trust) as process:
        paused(process)
        # Different spellings of the same file must still contend.
        conflict = subprocess.run(
            [sys.executable, "-c",
             "from openaidr.sensor.hooks import install_codex; import sys; "
             "install_codex(sys.argv[1], config_toml=sys.argv[2])",
             str(actual / "hooks.json"), str(actual / "config.toml")],
            text=True, capture_output=True, timeout=10,
        )
        assert conflict.returncode != 0
        assert "another OpenAIDR process; retry" in conflict.stderr
        finish(process)
    assert hooks.codex_trusted(hook_path, trust)
    assert all(key.startswith(str(hook_path) + ":")
               for key in hooks.codex_state(hooks.load_codex_config(trust)))


@pytest.mark.parametrize("agent", ["claude", "codex"])
@pytest.mark.parametrize("failure", [
    "conflict", "conflict_matching_value", "crash_before_settings",
    "crash_before_unchanged", "crash_after_settings", "crash_after_edited",
])
def test_pending_telemetry_undo_recovers_through_retry_and_remove(tmp_path, agent, failure):
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"),
                 telemetry={"local_token": "isolated"})
    cfg.save()
    target = tmp_path / ("config.toml" if agent == "codex" else "settings.json")
    section, field = ("otel", "log_user_prompt") if agent == "codex" else ("env", "OTEL_LOG_USER_PROMPTS")
    original = failure in ("conflict_matching_value", "crash_after_settings", "crash_after_edited")
    original = original if agent == "codex" else ("1" if original else "0")
    newer = failure != "conflict_matching_value"
    newer = newer if agent == "codex" else ("1" if newer else "0")
    target.write_text(integrations.serialize({section: {field: original}}, agent))
    script = '''
import sys
from pathlib import Path
from openaidr.sensor import integrations, settings_files
from openaidr.sensor.config import Config
original = settings_files.atomic_write
published = False
def write(path, text, **kwargs):
    global published
    after = sys.argv[4].startswith("crash_after")
    if (path == Path(sys.argv[3]) and not after) or (published and after):
        print("paused", flush=True)
        assert sys.stdin.readline().strip() == "continue"
    result = original(path, text, **kwargs)
    published = published or path == Path(sys.argv[3])
    return result
settings_files.atomic_write = write
try:
    integrations.install(Config.load(sys.argv[1]), [sys.argv[2]], {sys.argv[2]: sys.argv[3]})
except OSError as exc:
    assert "partial update" in str(exc), str(exc)
else:
    raise AssertionError("conflicting settings reported success")
'''
    with writer(script, cfg.path, agent, target, failure) as process:
        paused(process)
        assert integrations.manifest(cfg)
        if failure not in ("crash_after_settings", "crash_before_unchanged"):
            document = integrations.load(target, agent)
            if failure != "crash_after_edited":
                document[section][field] = newer
            document["model"] = "concurrent-user-choice"
            target.write_text(integrations.serialize(document, agent))
            before_retry = target.read_bytes()
        if failure.startswith("conflict"):
            finish(process)
        else:
            process.kill()
            process.wait(timeout=10)
    if failure in ("crash_before_settings", "crash_after_edited"):
        settings_before = target.read_bytes()
        manifest_before = integrations.manifest_path(cfg).read_bytes()
        for operation in (integrations.install, integrations.remove):
            with pytest.raises(OSError, match="Cannot determine") as error:
                operation(Config.load(cfg.path), [agent], {agent: target})
            assert "isolated" not in str(error.value)
            assert "concurrent-user-choice" not in str(error.value)
            assert target.read_bytes() == settings_before
            assert integrations.manifest_path(cfg).read_bytes() == manifest_before
        # Follow the documented manual recovery only after establishing whether
        # this test's interrupted writer published the settings.
        state = integrations.manifest(cfg)
        if failure == "crash_before_settings":
            state[str(target)]["pending"]["unpublished"] = True
        else:
            del state[str(target)]["pending"]
        integrations.manifest_path(cfg).write_text(json.dumps(state))
    integrations.install(Config.load(cfg.path), [agent], {agent: target})
    assert all("pending" not in entry for entry in integrations.manifest(cfg).values())
    if failure.startswith("conflict") or failure == "crash_before_settings":
        assert integrations.backup_path(target).read_bytes() == before_retry
    result = integrations.remove(Config.load(cfg.path), [agent], {agent: target})
    assert result["agents"][0]["removed"]
    document = integrations.load(target, agent)
    assert document[section][field] == (
        original if failure in ("crash_after_settings", "crash_after_edited", "crash_before_unchanged") else newer
    )
    if failure not in ("crash_after_settings", "crash_before_unchanged"):
        assert document["model"] == "concurrent-user-choice"


@pytest.mark.parametrize("agent", ["claude", "codex"])
def test_partial_telemetry_removal_keeps_restored_values_on_retry(tmp_path, agent):
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"),
                 telemetry={"local_token": "isolated"})
    cfg.save()
    target = tmp_path / ("config.toml" if agent == "codex" else "settings.json")
    section, field, value = (("otel", "log_user_prompt", True) if agent == "codex"
                             else ("env", "OTEL_LOG_USER_PROMPTS", "1"))
    target.write_text(integrations.serialize({section: {field: value}}, agent))
    integrations.install(cfg, [agent], {agent: target})
    script = '''
import sys
from openaidr.sensor import integrations, settings_files
from openaidr.sensor.config import Config
original = settings_files.atomic_write
published = False
def write(path, text, **kwargs):
    global published
    if published:
        print("paused", flush=True)
        assert sys.stdin.readline().strip() == "continue"
    result = original(path, text, **kwargs)
    published = published or str(path) == sys.argv[3]
    return result
settings_files.atomic_write = write
integrations.remove(Config.load(sys.argv[1]), [sys.argv[2]], {sys.argv[2]: sys.argv[3]})
'''
    with writer(script, cfg.path, agent, target) as process:
        paused(process)
        assert integrations.load(target, agent)[section][field] == value
        process.kill()
        process.wait(timeout=10)
    result = integrations.remove(Config.load(cfg.path), [agent], {agent: target})["agents"][0]
    assert integrations.load(target, agent)[section][field] == value
    # An uncommitted removal cannot claim all fields were restored, but its
    # retained conflict record must not reapply or overwrite the restored value.
    assert not result["removed"]
    assert section + "." + field in result["conflicts"]
    assert result["opted_out"]


@pytest.mark.parametrize("agent", ["claude", "codex"])
def test_manifest_finalization_failure_is_visible_and_recoverable(tmp_path, agent):
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"),
                 telemetry={"local_token": "isolated"})
    cfg.save()
    target = tmp_path / ("config.toml" if agent == "codex" else "settings.json")
    section, field, value = (("otel", "log_user_prompt", True) if agent == "codex"
                             else ("env", "OTEL_LOG_USER_PROMPTS", "1"))
    target.write_text(integrations.serialize({section: {field: value}}, agent))
    script = '''
import sys
from openaidr.sensor import cli, settings_files
original = settings_files.atomic_write
published = False
def write(path, text, **kwargs):
    global published
    if published:
        raise OSError("injected manifest finalization failure")
    result = original(path, text, **kwargs)
    published = published or str(path) == sys.argv[-1]
    return result
settings_files.atomic_write = write
raise SystemExit(cli.main(sys.argv[1:]))
'''
    result = subprocess.run(
        [sys.executable, "-c", script, "telemetry", "configure", "--config", str(cfg.path),
         "--agent", agent, "--claude-settings" if agent == "claude" else "--codex-config", str(target)],
        text=True, capture_output=True, timeout=15,
    )
    assert result.returncode == 1
    assert "manifest finalization failure" in result.stderr
    assert '"installed": true' not in result.stdout
    assert integrations.manifest(cfg)[str(target)]["pending"]
    integrations.install(Config.load(cfg.path), [agent], {agent: target})
    assert integrations.remove(Config.load(cfg.path), [agent], {agent: target})["agents"][0]["removed"]
    assert integrations.load(target, agent)[section][field] == value


@pytest.mark.parametrize("outcome", ["allowed", "busy", "permission"])
def test_windows_lock_contention_is_normalized_only_at_the_lock_call(tmp_path, monkeypatch, outcome):
    from openaidr.sensor import config, settings_files

    target = tmp_path / "settings.json"
    acquired = False

    def locking(*args):
        nonlocal acquired
        if outcome == "busy":
            raise PermissionError(errno.EACCES, "locking violation")
        acquired = True

    def locked_write(fd, content):
        if not acquired:
            raise PermissionError(errno.EACCES, "write to another owner's locked byte")
        return os.write(fd, content)

    def denied(*args):
        raise PermissionError(errno.EACCES, "file access denied")

    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(LK_NBLCK=2, locking=locking))
    windows = {name: getattr(os, name) for name in (
        "open", "write", "lseek", "close", "SEEK_SET", "O_RDWR", "O_CREAT",
    )}
    windows.update(name="nt", write=locked_write)
    if outcome == "permission":
        windows["open"] = denied
    monkeypatch.setattr(config, "os", SimpleNamespace(**windows))
    update = lambda files: files.write(target, '{"kept": true}')
    if outcome == "allowed":
        settings_files.edit_settings([target], update)
        assert json.loads(target.read_text()) == {"kept": True}
    else:
        with pytest.raises(OSError) as error:
            settings_files.edit_settings([target], update)
        assert ("another OpenAIDR process; retry" in str(error.value)) == (outcome == "busy")
        assert not target.exists()


@pytest.mark.parametrize("pending", [None, {"version": 2}, {"version": 1}])
def test_invalid_telemetry_recovery_keeps_settings_and_undo(tmp_path, pending):
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"),
                 telemetry={"local_token": "isolated"})
    cfg.save()
    target = tmp_path / "settings.json"
    integrations.install(cfg, ["claude"], {"claude": target})
    state = integrations.manifest(cfg)
    state[str(target)]["pending"] = pending
    undo = integrations.manifest_path(cfg)
    undo.write_text(json.dumps(state))
    before = [path.read_bytes() for path in (target, undo)]
    for action in (integrations.install, integrations.remove):
        with pytest.raises(OSError, match="administrator to recover"):
            action(cfg, ["claude"], {"claude": target})
        assert [path.read_bytes() for path in (target, undo)] == before


def test_unrelated_backup_is_never_overwritten_during_recovery(tmp_path):
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"),
                 telemetry={"local_token": "isolated"})
    cfg.save()
    target = tmp_path / "settings.json"
    target.write_text('{"model": "before"}')
    backup = integrations.backup_path(target)
    script = '''
import sys
from openaidr.sensor import integrations, settings_files
from openaidr.sensor.config import Config
original = settings_files.atomic_write
def write(path, text, **kwargs):
    if str(path) == sys.argv[2]:
        print("paused", flush=True)
        assert sys.stdin.readline().strip() == "continue"
    return original(path, text, **kwargs)
settings_files.atomic_write = write
try:
    integrations.install(Config.load(sys.argv[1]), ["claude"], {"claude": sys.argv[2]})
except OSError as exc:
    assert "partial update" in str(exc)
else:
    raise AssertionError("conflict reported success")
'''
    with writer(script, cfg.path, target) as process:
        paused(process)
        backup.write_text("a user's separate recovery copy")
        target.write_text('{"model": "new user choice"}')
        finish(process)
    snapshots = {p: p.read_bytes() for p in (target, backup, integrations.manifest_path(cfg))}
    for operation in (integrations.install, integrations.remove):
        with pytest.raises(OSError, match="Backup changed"):
            operation(Config.load(cfg.path), ["claude"], {"claude": target})
        assert all(p.read_bytes() == content for p, content in snapshots.items())
    # Retain the separately edited backup after an administrator resolves ownership.
    state = integrations.manifest(cfg)
    state[str(target)]["pending"]["backup_created"] = False
    integrations.manifest_path(cfg).write_text(json.dumps(state))
    integrations.install(Config.load(cfg.path), ["claude"], {"claude": target})
    assert backup.read_bytes() == snapshots[backup]
    integrations.remove(Config.load(cfg.path), ["claude"], {"claude": target})
    assert json.loads(target.read_text()) == {"model": "new user choice"}
