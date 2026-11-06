"""Opt-in native agent telemetry configuration with field-level undo."""

import copy
import json
import os
import shutil
from pathlib import Path

import tomlkit

from .config import configuration_lock
from .settings_files import PartialSettingsUpdate, content_hash, edit_settings, publication_state
from .telemetry import settings
from . import hooks
from .workbuddy import config_roots

AGENTS = ("codex", "claude")
CLAUDE_GATES = (
    "OTEL_LOG_USER_PROMPTS",
    "OTEL_LOG_ASSISTANT_RESPONSES",
    "OTEL_LOG_TOOL_DETAILS",
    "OTEL_LOG_TOOL_CONTENT",
    "OTEL_LOG_RAW_API_BODIES",
)


def default_path(agent, config=None):
    """The agent's settings file, honoring CODEX_HOME and CLAUDE_CONFIG_DIR.

    With a sensor config, a directory recorded from a shell that set those
    variables is used where the variable itself is absent.
    """
    if agent == "codex":
        return hooks.codex_config_path(config)
    if agent == "claude":
        return hooks.settings_path("claude", config)
    raise ValueError("unknown agent: " + str(agent))


# GUI apps and launchd jobs start with a minimal PATH, so well-known install
# directories are searched in addition to the inherited PATH.
BINARY_DIRECTORIES = (
    "~/.local/bin",
    "~/.claude/local",
    "~/.npm-global/bin",
    "~/.bun/bin",
    "/opt/homebrew/bin",
    "/usr/local/bin",
)


def detect(home=None, directories=BINARY_DIRECTORIES, config=None):
    """Report which agents are present on this machine, without reading their settings.

    Without an explicit ``home``, each agent's directory resolves like hook
    installation: the shell variable, then the directory a CLI command
    recorded in ``config``, then the default. The desktop app and service
    never see the variable, so the recorded directory is what lets them find
    an agent whose executable is only on a shell-specific PATH.
    """
    homes = ({agent: Path(home) / ("." + agent) for agent in AGENTS} if home
             else {agent: hooks.agent_home(agent, config) for agent in AGENTS})
    home = Path(home) if home else Path.home()
    result = {}
    # WorkBuddy is detectable but deliberately absent from AGENTS: its settings
    # env interceptor runs after the native trace exporter initializes.
    for agent in (*AGENTS, "workbuddy"):
        roots = config_roots(home) if agent == "workbuddy" else (homes[agent],)
        found = bool(shutil.which(agent)) or any(root.is_dir() for root in roots)
        for directory in directories:
            if found:
                break
            base = (
                home / directory[2:] if directory.startswith("~/") else Path(directory)
            )
            path = base / agent
            found = path.is_file() and os.access(path, os.X_OK)
        result[agent + "_available"] = found
    return result


def manifest_path(config):
    return Path(config["data_dir"]) / "telemetry-integrations.json"


def manifest(config):
    path = manifest_path(config)
    return json.loads(path.read_text()) if path.exists() else {}


def load(path, agent, *, text=None):
    if text is None:
        text = path.read_text(encoding="utf-8") if path.exists() else ""
    if agent == "codex":
        return tomlkit.parse(text)
    result = json.loads(text or "{}")
    if not isinstance(result, dict):
        raise ValueError("Claude settings must be a JSON object")
    return result


def plain(value):
    return value.unwrap() if hasattr(value, "unwrap") else copy.deepcopy(value)


def expected(config, agent):
    options = settings(config)
    endpoint = "http://" + options["listen"]
    if agent == "codex":

        def exporter(signal):
            return {
                "otlp-http": {
                    "endpoint": endpoint + "/v1/" + signal,
                    "protocol": "binary",
                }
            }

        return {
            ("otel", "exporter"): exporter("logs"),
            ("otel", "metrics_exporter"): exporter("metrics"),
            ("otel", "log_user_prompt"): bool(options["capture_prompts"]),
        }
    if agent == "claude":
        env = {
            "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
            "OTEL_LOGS_EXPORTER": "otlp",
            "OTEL_METRICS_EXPORTER": "otlp",
            "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
            "OTEL_EXPORTER_OTLP_ENDPOINT": endpoint,
            "OTEL_EXPORTER_OTLP_HEADERS": "",
        }
        for signal in ("LOGS", "METRICS"):
            env["OTEL_EXPORTER_OTLP_" + signal + "_ENDPOINT"] = (
                endpoint + "/v1/" + signal.lower()
            )
            env["OTEL_EXPORTER_OTLP_" + signal + "_PROTOCOL"] = "http/protobuf"
            env["OTEL_EXPORTER_OTLP_" + signal + "_HEADERS"] = ""
        env.update({key: "0" for key in CLAUDE_GATES})
        # Claude Code emits tool_parameters/tool_input/error on tool_result
        # only when OTEL_LOG_TOOL_DETAILS=1 (docs checked 2026-09-29). Codex
        # exports tool arguments without a config gate.
        env["OTEL_LOG_TOOL_DETAILS"] = "1" if options["capture_tool_details"] else "0"
        env["OTEL_LOG_USER_PROMPTS"] = "1" if options["capture_prompts"] else "0"
        return {("env", key): value for key, value in env.items()}
    raise ValueError("unknown agent: " + str(agent))


def backup_path(path):
    return path.with_name(path.name + ".openaidr-backup")


def serialize(document, agent):
    return (
        tomlkit.dumps(document)
        if agent == "codex"
        else json.dumps(document, indent=2) + "\n"
    )


def recover_pending(state, path, files, undo_path):
    """Resolve only known publication outcomes; do not guess who changed a field."""
    key = str(path)
    entry = state.get(key)
    if not entry or "pending" not in entry:
        return False, False
    pending = entry["pending"]
    if (not isinstance(pending, dict) or pending.get("version") != 1
            or not {"before", "after", "previous", "backup_hash"} <= pending.keys()
            or pending["previous"] is not None and not isinstance(pending["previous"], dict)):
        raise OSError(f"Invalid pending telemetry record in {undo_path}; ask your administrator to recover it before retrying")
    outcome = publication_state(pending["before"], pending["after"],
                                content_hash(files.content(path)),
                                unpublished=pending.get("unpublished", False))
    owned_backup = False
    if outcome == "before":
        saved_backup = files.content(backup_path(path))
        if pending.get("backup_created") and saved_backup is not None:
            if content_hash(saved_backup) != pending["backup_hash"]:
                raise OSError(f"Backup changed during interrupted setup: {backup_path(path)}; keep it and recover {undo_path} before retrying")
            owned_backup = True
        previous = pending["previous"]
        if previous is None:
            del state[key]
        else:
            state[key] = previous
    elif outcome == "after":
        del entry["pending"]
    else:
        raise OSError(
            f"Cannot determine whether interrupted telemetry setup updated {path}; "
            f"settings were kept. Ask your administrator to recover the pending record in {undo_path} before retrying."
        )
    return True, owned_backup


def install(config, agents=AGENTS, paths=None):
    # Keep sensor preferences and the undo plan serialized for the whole call.
    # Target locks are acquired afterwards; hooks never acquire these locks
    # while holding their own settings locks.
    with configuration_lock(config.path), configuration_lock(manifest_path(config)):
        return _install(config, agents, paths)


def _install(config, agents, paths):
    paths = paths or {}
    result = []
    undo_path = manifest_path(config).expanduser().resolve()
    for agent in agents:
        path = Path(paths.get(agent) or default_path(agent, config)).expanduser().resolve()
        saved_path = backup_path(path)
        values = expected(config, agent)

        def update(files):
            state = json.loads(files.text(undo_path) or "{}")
            _, owned_backup = recover_pending(state, path, files, undo_path)
            document = load(path, agent, text=files.text(path))
            previous = copy.deepcopy(state.get(str(path)))
            create_backup = files.content(path) is not None and (owned_backup or files.content(saved_path) is None)
            discard_backup = owned_backup and files.content(path) is None
            keep_backup = create_backup or (files.content(saved_path) is not None and not discard_backup)
            backup_content = files.content(path) if create_backup else files.content(saved_path)
            entry = state.setdefault(
                str(path),
                {
                    "agent": agent,
                    "backup": str(saved_path) if keep_backup else None,
                    "fields": {},
                    "existed": files.content(path) is not None,
                },
            )
            for (section, field), value in values.items():
                entry.setdefault("sections", {}).setdefault(section, section in document)
                table = document.setdefault(section, {})
                if not isinstance(table, dict) and not hasattr(table, "unwrap"):
                    raise ValueError(f"{path}: {section} must be a table/object")
                record = entry["fields"].setdefault(
                    section + "." + field,
                    {"present": field in table, "previous": plain(table.get(field))},
                )
                record["installed"] = copy.deepcopy(value)
                table[field] = value
            replacement = serialize(document, agent)
            entry["pending"] = {
                "version": 1,
                "previous": previous,
                "before": content_hash(files.content(path)),
                "after": content_hash(replacement.encode("utf-8")),
                "backup_created": create_backup or discard_backup,
                "backup_hash": content_hash(backup_content) if create_backup or discard_backup else None,
            }
            # Publish the undo plan before touching agent configuration.
            files.write(undo_path, json.dumps(state, indent=2))
            if create_backup:
                files.write(saved_path, files.text(path))
            elif discard_backup:
                files.delete(saved_path)
            files.write(path, replacement)
            return entry["backup"]

        def complete(files, _):
            state = json.loads(files.text(undo_path))
            state[str(path)].pop("pending", None)
            files.write(undo_path, json.dumps(state, indent=2))

        try:
            saved_backup = edit_settings([undo_path, saved_path, path], update, complete=complete)
        except PartialSettingsUpdate:
            # A conditional target-write conflict proves our replacement never
            # published. Persist that fact before returning the retry error.
            def unpublished(files):
                state = json.loads(files.text(undo_path))
                state[str(path)]["pending"]["unpublished"] = True
                files.write(undo_path, json.dumps(state, indent=2))

            edit_settings([undo_path], unpublished)
            raise

        set_opt_out(config, agent, False)
        result.append(
            {"agent": agent, "path": str(path), "installed": True, "backup": saved_backup}
        )
    options = settings(config)
    return {
        "agents": result,
        "restart_required": True,
        "capture": {
            "prompts": bool(options["capture_prompts"]),
            "tool_details": bool(options["capture_tool_details"]),
            "raw_api_bodies": False,
            "secret_redaction": True,
        },
        "notice": "Restart the agents to load telemetry settings. Shell environment or managed settings may override local configuration. "
        + (
            "Tool details (commands, file paths, URLs) are exported with secret redaction; prompts are not."
            if options["capture_tool_details"] and not options["capture_prompts"]
            else "Content gates: prompts "
            + ("on" if options["capture_prompts"] else "off")
            + ", tool details "
            + ("on" if options["capture_tool_details"] else "off")
            + "."
        ),
    }


def remove(config, agents=AGENTS, paths=None, *, disconnect=False):
    """Restore managed fields; desktop uninstall also disconnects this receiver."""
    with configuration_lock(config.path), configuration_lock(manifest_path(config)):
        return _remove(config, agents, paths, disconnect=disconnect)


def _remove(config, agents, paths, *, disconnect=False):
    paths = paths or {}
    undo_path = manifest_path(config).expanduser().resolve()
    state = manifest(config)
    result = []
    for agent in agents:
        if agent not in AGENTS:
            raise ValueError("unknown agent: " + str(agent))
        # Without an explicit path, every file recorded for the agent is
        # restored, including one configured with a custom path earlier.
        targets = (
            [Path(paths[agent])]
            if paths.get(agent)
            else configured_paths(config, agent)
        )
        conflicts, touched = [], set()
        for path in targets:
            path = path.expanduser().resolve()

            def update(files):
                state = json.loads(files.text(undo_path) or "{}")
                recovered, owned_backup = recover_pending(state, path, files, undo_path)
                if owned_backup:
                    files.delete(backup_path(path))
                entry = state.get(str(path))
                if not entry:
                    if recovered:
                        files.write(undo_path, json.dumps(state, indent=2))
                    if not disconnect:
                        return state, None
                document = load(path, agent, text=files.text(path))
                conflicts = []
                for key, record in list((entry or {}).get("fields", {}).items()):
                    section, field = key.split(".", 1)
                    table = document.get(section, {})
                    if field not in table or plain(table[field]) != record["installed"]:
                        conflicts.append(key)
                        continue
                    if record["present"]:
                        table[field] = record["previous"]
                    else:
                        del table[field]
                    if not table and not entry.get("sections", {}).get(section, False):
                        document.pop(section, None)
                    del entry["fields"][key]
                remaining = receiver_fields(config, agent, document) if disconnect else []
                local_signals = []
                if remaining and agent == "claude":
                    env = document["env"]
                    local_endpoints = {field for _, field in remaining}
                    for signal in ("LOGS", "METRICS"):
                        endpoint_key = "OTEL_EXPORTER_OTLP_" + signal + "_ENDPOINT"
                        if not env.get(endpoint_key):
                            endpoint_key = "OTEL_EXPORTER_OTLP_ENDPOINT"
                        if endpoint_key in local_endpoints:
                            local_signals.append(signal)
                for section, field in remaining:
                    # Explicit uninstall removes local exporters even after an
                    # edit, a lost undo record, or restoration of an old value.
                    # Other collectors and unrelated edits remain untouched.
                    del document[section][field]
                    if not document[section] and not (entry or {}).get("sections", {}).get(section, False):
                        del document[section]
                    key = section + "." + field
                    if entry:
                        entry["fields"].pop(key, None)
                    if key in conflicts:
                        conflicts.remove(key)
                for signal in local_signals:
                    env = document.setdefault("env", {})
                    if env.get("OTEL_EXPORTER_OTLP_" + signal + "_ENDPOINT") or env.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
                        continue
                    # With no undo record, deleting endpoints alone leaves
                    # OTLP enabled against its default localhost collector.
                    key = "OTEL_" + signal + "_EXPORTER"
                    exporters = [value.strip() for value in env.get(key, "otlp").split(",")]
                    if "otlp" in exporters:
                        env[key] = ",".join(value for value in exporters if value != "otlp") or "none"
                if not entry and not remaining:
                    return state, None
                files.write(path, serialize(document, agent))
                if entry and not entry["fields"]:
                    del state[str(path)]
                files.write(undo_path, json.dumps(state, indent=2))
                return state, conflicts

            state, target_conflicts = edit_settings([undo_path, backup_path(path), path], update)
            if target_conflicts is not None:
                touched.add(str(path))
                conflicts.extend(target_conflicts)
        # The disconnect is recorded when the managed settings were removed,
        # even partially: conflicting fields the user changed stay theirs, and
        # the record keeps automatic setup from reinstalling over them. It is
        # withheld while a file still points at the receiver: a recorded file
        # this call did not touch, a file without a manifest entry, or a
        # conflicting field that still carries an exporter for the receiver.
        unresolved = sorted(
            {
                path
                for path, entry in state.items()
                if entry.get("agent") == agent and path not in touched
            }
            | {
                str(path.expanduser().resolve())
                for path in targets
                if managed_present(config, agent, path)
                and (disconnect or str(path.expanduser().resolve()) not in touched or conflicts)
            }
        )
        # The persisted record follows this outcome both ways, so an earlier
        # disconnect does not outlive an exporter that was added back by hand.
        opted_out = not unresolved
        set_opt_out(config, agent, opted_out)
        result.append(
            {
                "agent": agent,
                "removed": bool(touched) and not conflicts,
                "conflicts": conflicts,
                "unresolved": unresolved,
                "opted_out": opted_out,
            }
        )
    return {"agents": result, "restart_required": True}


def configured_paths(config, agent):
    """Settings files recorded in the manifest for this agent, else its default file.

    An agent configured through a custom `--codex-config` or
    `--claude-settings` path keeps being checked and updated at that path.
    """
    paths = [
        Path(path)
        for path, entry in manifest(config).items()
        if entry.get("agent") == agent
    ]
    paths = paths or [default_path(agent, config)]
    if agent == "codex":
        paths.extend(list(hooks.codex_paths(config).values())[1:])
    return list(dict.fromkeys(path.expanduser().resolve() for path in paths))


def current(config, agent, path=None):
    """True when the agent's settings already carry the desired telemetry values.

    The manifest only proves what was installed once; the desired listen
    address or capture gates may have changed since.
    """
    paths = [Path(path)] if path else configured_paths(config, agent)
    state = manifest(config)
    values = expected(config, agent).items()
    for target in paths:
        if "pending" in state.get(str(target.expanduser().resolve()), {}):
            return False
        try:
            document = load(target.expanduser().resolve(), agent)
        except (OSError, ValueError):
            return False
        if not all(
            plain(document.get(section, {}).get(field)) == value
            for (section, field), value in values
        ):
            return False
    return True


def managed_present(config, agent, path):
    """True when the file still points the agent at this sensor's receiver.

    Used when no manifest entry exists for the file, so the check needs no
    token and never persists one.
    """
    try:
        document = load(Path(path).expanduser().resolve(), agent)
    except (OSError, ValueError):
        return False
    return bool(receiver_fields(config, agent, document))


def receiver_fields(config, agent, document):
    """Exporter fields targeting this sensor, independent of the undo record."""
    endpoint = "http://" + settings(config)["listen"]

    # Every managed signal counts: one exporter left pointing at the receiver
    # keeps telemetry flowing even when the others were edited away. The match
    # is on the whole origin, so another collector on a longer port number
    # that merely shares the prefix is not mistaken for this receiver.
    def targets_receiver(value):
        value = str(value or "")
        return value == endpoint or value.startswith(endpoint + "/")

    if agent == "codex":
        otel = plain(document.get("otel")) or {}
        return [
            ("otel", key)
            for key in ("exporter", "trace_exporter", "metrics_exporter")
            if isinstance(otel.get(key), dict) and targets_receiver(
                ((otel.get(key) or {}).get("otlp-http") or {}).get("endpoint")
            )
        ]
    env = plain(document.get("env")) or {}
    return [
        ("env", key)
        for key in (
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
            "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
        )
        if targets_receiver(env.get(key))
    ]


def set_opt_out(config, agent, opted_out):
    """Record an explicit per-agent disconnect in the sensor config.

    `telemetry remove` is the remaining per-agent control; without this
    record automatic setup would reconnect the agent on the next refresh.
    """
    telemetry = dict(config.get("telemetry") or {})
    disabled = [
        name for name in telemetry.get("disabled_agents") or [] if name != agent
    ]
    if opted_out:
        disabled.append(agent)
    if disabled:
        telemetry["disabled_agents"] = disabled
    else:
        telemetry.pop("disabled_agents", None)
    if telemetry != (config.get("telemetry") or {}):
        config["telemetry"] = telemetry
        config.save()


def status(config):
    state = manifest(config)
    result = {}
    for agent in AGENTS:
        installed = False
        if any(entry.get("agent") == agent and "pending" in entry for entry in state.values()):
            result[agent + "_installed"] = False
            continue
        for path, entry in state.items():
            if entry.get("agent") != agent:
                continue
            try:
                document = load(Path(path), agent)
                # Keep legacy trace undo records for removal, but no longer
                # manage that setting or treat a customer's edits as drift.
                fields = {
                    key: record for key, record in entry["fields"].items()
                    if key != "otel.trace_exporter"
                }
                installed = bool(fields) and all(
                    plain(document.get(section, {}).get(field)) == record["installed"]
                    for key, record in fields.items()
                    for section, field in [key.split(".", 1)]
                )
            except (OSError, ValueError):
                installed = False
            if installed:
                break
        result[agent + "_installed"] = installed
    return result
