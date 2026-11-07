"""Desktop bridge; credentials require the explicit local-runtime sign-in action."""

import contextlib
import hashlib
import json
import logging
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import httpx
from openaidr import build_info

from openaidr.core.enrollment import parse_enrollment_link
from openaidr.core.cloud_protection import project as cloud_protection
from openaidr.core.event import now
from .config import IDENTITY_FIELDS, Config, configuration_lock
from openaidr.core.files import atomic_write
from . import desktop_edition, hooks, integrations, network_proxy, service, updates
from .runtime import NOT_ENROLLED, Client, check_reenrollment, discard_policy_cache, enroll
from .telemetry import settings, token_fingerprint
from .tls import same_origin, validate_ca_certificate

ACTIONS = {
    "simulation.status",
    "status",
    "usage.summary",
    "posture.summary",
    "posture.configure",
    "guardrails.summary",
    "guardrails.denials",
    "guardrails.check",
    "guardrails.review",
    "guardrails.configure",
    "guardrails.configuration",
    "alerts.list",
    "alerts.received",
    "alerts.acknowledge",
    "enroll",
    "enrollment.preview",
    "enrollment.connect",
    "free.connect",
    "local-runtime.check",
    "local-runtime.docker-setup",
    "local-runtime.prepare",
    "local-runtime.start",
    "local-runtime.connect",
    "local-runtime.credentials",
    "local-runtime.dashboard",
    "free.usage",
    "credits.summary",
    "api-key.connect",
    "setup",
    "desktop.update.setup",
    "desktop.remove",
    "desktop.resume",
    "desktop.purge",
    "update.check",
    "telemetry.install",
    "telemetry.remove",
    "service.install",
    "service.start",
    "service.restart",
    "proxy.status",
    "proxy.test",
    "proxy.save",
    "proxy.route",
}
PROXY_FIELDS = {"mode", "url", "bypass", "username", "password"}
# Only the desktop updater asks for a route, and only to the release server.
RELEASE_ORIGIN = "https://releases.opensecura.ai/"


def app_version():
    from .cli import app_version

    return app_version()


PRERELEASE_RANK = {
    "a": 0,
    "alpha": 0,
    "b": 1,
    "beta": 1,
    "rc": 2,
    "c": 2,
    "pre": 2,
    "preview": 2,
}
VERSION = re.compile(
    r"v?(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-._]?(?P<pre>a|alpha|b|beta|rc|c|pre|preview)[-._]?(?P<pre_n>\d*))?"
    r"(?:[-._]?post[-._]?(?P<post>\d*))?"
    r"(?:[-._]?dev[-._]?(?P<dev>\d*))?",
    re.IGNORECASE,
)


def version_key(text):
    """PEP 440 ordering key for the versions this project publishes; None if unparsable.

    dev < alpha < beta < rc < final < post, and trailing zeros in the release
    are ignored so 1.0 equals 1.0.0. Desktop alphas such as 0.1.0a2 therefore
    sort after 0.1.0a1 and before the final 0.1.0.
    """
    text = str(text).strip()
    if build_info.VERSION.fullmatch(text):
        text = text.split("+")[0]
    match = VERSION.fullmatch(text)
    if not match:
        return None
    release = [int(part) for part in match["release"].split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre = (match["pre"] or "").lower()
    if pre:
        rank = PRERELEASE_RANK[pre]
    elif match["dev"] is not None and match["post"] is None:
        rank = -1
    else:
        rank = 3
    post = int(match["post"] or 0) if match["post"] is not None else -1
    dev = (0, int(match["dev"] or 0)) if match["dev"] is not None else (1, 0)
    return (tuple(release), rank, int(match["pre_n"] or 0), post, dev)


def order_key(version, info=None):
    if not build_info.VERSION.fullmatch(version):
        return version_key(version)
    info = info or build_info.for_version(version)
    if not isinstance(info, dict) or info.get("version") != version:
        return None
    try:
        published, stamp = build_info.order(info)
        return ((10000, published, stamp), 3, 0, -1, (1, 0))
    except (ValueError, TypeError, OverflowError):
        return None


def keep_existing(existing, incoming, info=None, incoming_info=None):
    if not existing or existing == incoming:
        return False
    old, new = order_key(existing, info), order_key(incoming, incoming_info)
    if build_info.VERSION.fullmatch(existing) or build_info.VERSION.fullmatch(incoming):
        return old is None or new is None or old >= new
    return bool(old and new and old > new)


def live_status(config, *, private=False, expected_pid=None):
    """Status of the running background service, or an empty dict when unreachable."""
    try:
        return (
            hooks.private_status(config, expected_pid=expected_pid) if private
            else hooks.local_request(config, "GET", "/v1/status")
        ) or {}
    except Exception:
        return {}


def live_version(config):
    return str(live_status(config).get("version") or "")


def service_version_path(config):
    return Path(config["data_dir"]) / "service-version"


def record_service_version(config, version, info=None):
    """Remember the version the managed service last ran, for the stopped case.

    A stopped service reports nothing live, and an older bundle opened later
    has already replaced the staged executable, so this record is what keeps
    automatic setup from starting a downgraded collector.
    """
    if not version:
        return
    try:
        path = service_version_path(config)
        if not path.exists() or path.read_text().strip() != version:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            atomic_write(path, version + "\n")
        info = info or build_info.for_version(version)
        if info and info.get("version") == version:
            atomic_write(path.with_name("service-build.json"), json.dumps(info))
    except OSError:
        pass


def recorded_service_version(config):
    try:
        return service_version_path(config).read_text().strip()
    except OSError:
        return ""


def recorded_service_build(config):
    try:
        return json.loads(service_version_path(config).with_name("service-build.json").read_text())
    except (OSError, ValueError):
        return None


LIVE_SETTINGS = (
    "enabled",
    "listen",
    "max_queue_bytes",
    "capture_prompts",
    "capture_tool_details",
)


def service_state(live, options, installed):
    """How the running service relates to the installed executable and settings."""
    running = str(live.get("version") or "")
    running_key, installed_key = order_key(running, live.get("build")), order_key(installed)
    telemetry = live.get("telemetry") or {}
    newer = keep_existing(running, installed, live.get("build"))
    return {
        "service_version": running,
        # Only a newer installed executable restarts the service; an older
        # bundle opened later must never roll the collector back, so nothing
        # restarts a newer service, not even stale settings.
        "service_outdated": bool(
            running_key and installed_key and installed_key > running_key
        ),
        "service_newer": newer,
        # The receiver snapshots its settings at start; a changed listen
        # address, capture gate, queue capacity, or receiver token applies
        # only after a restart. The token itself never appears in status;
        # its fingerprint does. Stale settings on a service that must not be
        # restarted from here (newer, or started in the foreground) hold the
        # agents instead of pointing them at values the receiver rejects.
        "settings_stale": any(
            key in telemetry
            and live_setting(key, telemetry[key]) != live_setting(key, options[key])
            for key in LIVE_SETTINGS
        )
        or (
            "token_fingerprint" in telemetry
            and telemetry["token_fingerprint"]
            != token_fingerprint(options.get("local_token"))
        ),
    }


def live_setting(key, value):
    """Comparable form of a receiver setting, whatever type the YAML or status used.

    The queue clamps its capacity to 4096 bytes, so the configured value is
    compared at that same effective minimum.
    """
    if key == "max_queue_bytes":
        try:
            return max(4096, int(value))
        except (TypeError, ValueError):
            return None
    if key == "listen":
        return str(value).strip()
    return bool(value)


def proxy_action(config, action, params):
    """Network proxy settings for the desktop app. Passwords arrive only on stdin
    and go only to the credential store; responses never contain them, except
    the release-server route the updater passes straight to its HTTP client."""
    if action == "proxy.status":
        return network_proxy.public_status(config)
    if action == "proxy.route":
        url = params.get("url")
        if not isinstance(url, str) or not url.startswith(RELEASE_ORIGIN):
            raise ValueError("unsupported proxy route")
        return {"proxy": network_proxy.route(config, url)}
    settings = {key: params[key] for key in ("mode", "url", "bypass", "username") if key in params}
    password = params.get("password")
    if password is not None and not isinstance(password, str):
        raise ValueError("Enter the proxy password.")
    if action == "proxy.test":
        return network_proxy.test_connection(config, settings, password)
    with configuration_lock(config.path):
        config = Config.load(config.path)
        network_proxy.save(config, settings, password)
    # The service reads the setting at startup. Hooks fail open while it restarts.
    current = status(config)
    if current.get("running") and not current.get("foreground"):
        service.manage("restart", config, timeout=10)
    return network_proxy.public_status(Config.load(config.path))


def status(config, *, deadline=None, private=False):
    def probe_options():
        if deadline is None:
            return {}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Sensor readiness deadline expired.")
        return {"timeout": remaining}

    options = settings(config)
    telemetry = {
        "enabled": options["enabled"],
        "listen": options["listen"],
        "queue_depth": 0,
        "queue_bytes": 0,
        "forwarded": 0,
        "received": 0,
        "last_error": "",
        "capture_prompts": options["capture_prompts"],
        "capture_tool_details": options["capture_tool_details"],
        **integrations.status(config),
        **integrations.detect(config=config),
    }
    # "current" is what the window converges on: installed, still matching the
    # desired settings, backed by a running receiver, and not disconnected
    # on purpose with `telemetry remove`.
    opted_out = set(options.get("disabled_agents") or [])
    for agent in integrations.AGENTS:
        telemetry[agent + "_opted_out"] = agent in opted_out
        telemetry[agent + "_current"] = bool(
            options["enabled"]
            and agent not in opted_out
            and telemetry[agent + "_installed"]
            and integrations.current(config, agent)
        )
    queue_path = Path(config["data_dir"]) / "telemetry.sqlite3"
    if queue_path.exists():
        try:
            db = sqlite3.connect(
                queue_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=1
            )
            try:
                row = db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM exports"
                ).fetchone()
                telemetry.update(queue_depth=row[0], queue_bytes=row[1])
                error = db.execute(
                    "SELECT last_error FROM exports WHERE last_error<>'' ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                if error:
                    telemetry["last_error"] = error[0]
            finally:
                db.close()
        except sqlite3.Error:
            pass
    try:
        service_status = service.manage("status", config, **probe_options())
    except Exception:
        service_status = "unknown"
    live = None
    try:
        if private:
            identity = service.manage("identity", config, **probe_options())
            if identity["config"] != config.path.resolve():
                raise ValueError("The background service uses a different sensor config.")
            live = hooks.private_status(config, expected_pid=identity["pid"], **probe_options())
        else:
            live = hooks.local_request(config, "GET", "/v1/status", **probe_options())
        telemetry.update(live.get("telemetry") or {})
        if service_status == "running":
            record_service_version(config, str(live.get("version") or ""), live.get("build"))
    except Exception:
        pass
    recorded = recorded_service_version(config)
    hook_state = hooks.status(config=config)
    for agent in hooks.AGENTS:
        path = hooks.settings_path(agent, config)
        hook_state[agent].update(
            config_path=str(path), config_exists=path.is_file(),
            available=hook_state[agent].get("available", telemetry.get(agent + "_available", False)),
            control_events=[event for event in ("UserPromptSubmit", "PreToolUse", "PostToolUse")
                            if event in hooks.managed_events(agent) and hooks.controls(hooks.PRODUCTS[agent], event)],
        )
        hook_state[agent]["opted_out"] = hooks.opted_out(config, agent)
        hook_state[agent]["current"] = bool(
            hook_state[agent]["installed"]
            and not hook_state[agent].get("approval_pending")
            and (agent != "codex" or hook_state[agent]["trusted"])
            and hooks.current(config.path, agent, hooks.settings_path(agent, config))
        )
    hook_state["codex"]["profiles"] = hooks.codex_profiles(config)
    hook_state["codex"]["profiles"][0]["available"] |= hook_state["codex"]["available"]
    return {
        "enrolled": config.enrolled(),
        "enterprise_enrollment_required": desktop_edition.needs_organization(config),
        "connection_mode": config.get("connection_mode", "organization"),
        "sensor_id": config.get("sensor_id", ""),
        "server_url": config.get("server_url", ""),
        # The saved setting, for the connected status; never the password.
        "network_proxy": network_proxy.public_status(config, check_password=False),
        "tenant_name": (live or {}).get("tenant_name", ""),
        "cloud_protection": cloud_protection((live or {}).get("cloud_protection", (live or {}).get("cloud_credit"))),
        "service": service_status,
        "running": live is not None,
        "control_ready": bool((live or {}).get("last_heartbeat_at")),
        "heartbeat": {
            "last_success_at": live.get("last_heartbeat_at"),
            "error": live.get("heartbeat_error", ""),
        } if live is not None else None,
        "activity": {
            "queue_depth": live.get("queue_depth"),
            "last_error": (live.get("ship") or {}).get("last_error", ""),
        } if live is not None else None,
        "telemetry": telemetry,
        "hooks": hook_state,
        "config_path": str(config.path),
        "ca_cert": config.get("ca_cert", ""),
        "custom_ca": bool(config.get("ca_cert")),
        "version": app_version(),
        "build": build_info.for_version(app_version()),
        "update": update_status(config, live),
        "disabled": bool((live or {}).get("disabled")),
        # A sensor answering locally while the OS service manager does not
        # report it running was started by hand with `openaidr run`.
        "foreground": live is not None and service_status != "running",
        # A stopped service that last ran a newer version than this app must
        # not be started from the downgraded staged executable.
        "service_downgrade": service_status == "stopped"
        and keep_existing(recorded, app_version(), recorded_service_build(config)),
        "recorded_service_version": recorded,
        **service_state(live or {}, options, app_version()),
    }


def setup(config, *, require_control=False, match_version=False):
    """Converge an enrolled device: service installed and running, present agents connected.

    Desktop setup uses match_version to make its own bundled sensor authoritative.
    With require_control on Linux, agent writes wait for a verified running
    service and its first applied server response.
    """
    from .removal import marker

    if desktop_edition.needs_organization(config):
        raise ValueError(desktop_edition.MESSAGE)
    if marker(config).exists():
        raise ValueError("OpenAIDR removal was requested. Choose Install in the desktop app to resume collection.")
    if not config.enrolled():
        raise ValueError(NOT_ENROLLED)
    if require_control and service.platform.system() != "Linux":
        raise ValueError(
            "Verified setup supports Linux only. On other platforms, use "
            "telemetry configure, hook install, and install."
        )

    def manage(action):
        options = {"timeout": 10} if require_control else {}
        if match_version and action in ("install", "start", "restart"):
            options["match_version"] = True
        return service.manage(action, config, **options)

    def verify_config():
        identity = manage("identity")
        installed_config = identity["config"]
        if installed_config and installed_config != config.path.resolve():
            raise ValueError(
                f"The background service uses a different sensor config: {installed_config}. "
                "Run setup with that config, or drain its queued activity and uninstall "
                "that service before setting up this config."
            )
        return identity

    identity = verify_config() if require_control else {}
    # The service's first history import needs the shell's profile directory.
    hooks.remember_homes(config)
    # Persist the receiver token before anything reads the config, so the
    # service and the agent settings written below share one token instead of
    # each generating its own.
    options = settings(config, persist_token=True)
    installed = app_version()
    live = live_status(config, private=require_control, expected_pid=identity.get("pid") or None)
    steps = []

    def final_status():
        return status(config, **({"deadline": time.monotonic() + 5, "private": True} if require_control else {}))

    def attempt(step, action, **details):
        try:
            action()
        except Exception as exc:
            steps.append({"step": step, "ok": False, "error": str(exc), **details})
            return False
        steps.append({"step": step, "ok": True, **details})
        return True

    try:
        state = manage("status")
    except Exception as exc:
        state = "unknown"
        steps.append({"step": "service.status", "ok": False, "error": str(exc)})
    if state in ("not installed", "stopped") and live:
        # A sensor already answers locally, started with `openaidr run`;
        # a service installed beside it would fight over the same ports.
        steps.append({"step": "service.skip", "ok": True, "reason": "foreground"})
    elif state in ("not installed", "changed"):
        # A Windows task whose definition no longer matches what OpenAIDR
        # registers (another user, trigger, or command) is registered again.
        if attempt("service.install", lambda: manage("install")):
            record_service_version(config, installed)
    elif state == "stopped" and not match_version and keep_existing(
        recorded_service_version(config), installed, recorded_service_build(config),
    ):
        # The service last ran a newer version than the executable this app
        # staged; starting it now would roll the collector back.
        steps.append(
            {
                "step": "service.skip",
                "ok": True,
                "reason": "downgrade",
                "running": recorded_service_version(config),
                "installed": installed,
            }
        )
    elif state == "stopped":
        try:
            manage("start")
            steps.append({"step": "service.start", "ok": True})
            record_service_version(config, installed)
        except Exception as exc:
            # A loaded but idle launchd job rejects bootstrap; kickstart covers
            # it, and a successful fallback is a recovery, not a failure.
            if attempt(
                "service.restart",
                lambda: manage("restart"),
                after="start failed: " + str(exc),
            ):
                record_service_version(config, installed)
    elif state == "running":
        relation = service_state(live, options, installed)
        if not live:
            # Reported running but the local status endpoint does not answer,
            # for example after the listen address changed without a restart.
            attempt(
                "service.restart",
                lambda: manage("restart"),
                reason="unreachable",
            )
        elif relation["service_outdated"] or (match_version and relation["service_version"] != installed):
            # Replacing the staged executable leaves the old process running;
            # restart it so the collector matches the selected build.
            if attempt(
                "service.restart",
                lambda: manage("restart"),
                running=relation["service_version"],
                installed=installed,
            ):
                record_service_version(config, installed)
        elif relation["settings_stale"] and (match_version or not relation["service_newer"]):
            attempt(
                "service.restart",
                lambda: manage("restart"),
                reason="settings",
            )
        elif match_version or not relation["service_newer"]:
            try:
                migrate = service.needs_migration()
            except Exception as exc:
                steps.append({"step": "service.install", "ok": False, "error": str(exc)})
            else:
                if migrate and attempt("service.install", lambda: manage("install"), reason="command migration"):
                    record_service_version(config, installed)
    if require_control:
        # Installation reloads systemd and can expose previously unloaded
        # overrides. Check again before connecting any agents.
        identity = verify_config()
        # A newly started process has not learned whether the server disabled
        # it until its first heartbeat has been applied.
        live = live_status(config, private=True, expected_pid=identity["pid"])
        relation = service_state(live, options, installed)
        receiver_pending = (
            options["enabled"] and not live.get("disabled")
            and not (live.get("telemetry") or {}).get("listening")
        )
        if (
            state != "running" or not live.get("last_heartbeat_at")
            or receiver_pending or relation["service_outdated"] or relation["settings_stale"]
        ):
            return {
                "steps": steps, "restart_required": False, "agents_pending": True,
                **final_status(),
            }
    detected = integrations.detect(config=config)
    configured = integrations.status(config)
    opted_out = set(options.get("disabled_agents") or [])
    # Agents are left alone when the sensor has telemetry disabled (no
    # receiver runs), when the server disabled this sensor (exports would
    # only queue up and be rejected), and when an agent was disconnected on
    # purpose with `telemetry remove`. An agent whose settings no longer match
    # the desired values (listen address, token, capture gates) is configured
    # again at its recorded path; install keeps the original undo values.
    agents = [
        agent
        for agent in integrations.AGENTS
        if options["enabled"]
        and not live.get("disabled")
        and agent not in opted_out
        and detected[agent + "_available"]
        and not (
            configured[agent + "_installed"] and integrations.current(config, agent)
        )
    ]
    relation = service_state(live, options, installed)
    if (
        live
        and relation["settings_stale"]
        and (state != "running" or (relation["service_newer"] and not match_version))
    ):
        # The receiver still runs previous settings and must not be restarted
        # from here (started in the foreground, or newer than this app);
        # rewriting agents to the new values would point them at a receiver
        # that rejects them until the operator restarts it.
        steps.append(
            {
                "step": "telemetry.skip",
                "ok": True,
                "reason": "newer_stale" if state == "running" else "foreground_stale",
            }
        )
        agents = []
    connected, reconfigured = False, False
    for agent in agents:
        paths = [str(path) for path in integrations.configured_paths(config, agent)]
        # One agent's unreadable settings file must not block the other agent.
        done = attempt(
            "telemetry.install",
            lambda agent=agent, paths=paths: [
                integrations.install(config, [agent], {agent: path}) for path in paths
            ],
            agents=[agent],
        )
        connected = connected or done
        reconfigured = reconfigured or (done and configured[agent + "_installed"])
    # Hooks carry what native telemetry gates or omits: the prompt text, the
    # whole tool input, the tool output, and for Codex the assistant's
    # response. They are installed for every detected agent unless removed on
    # purpose with `openaidr hook uninstall --agent <name>`, and
    # reinstalled when their executable is unavailable, the file lost them,
    # their sensor config changed, or Codex no longer trusts them.
    hook_state = hooks.status(config=config)
    # Frozen hooks use a staged runtime without per-invocation extraction.
    try:
        hook_executable = service.hook_executable()
    except Exception as exc:
        steps.append({"step": "hooks.runtime", "ok": False, "error": str(exc)})
        hook_executable = service.staged_executable()
    runtime_executable = (
        os.path.normcase(hook_executable)
        if service.windows_runtime() or hook_executable != service.staged_executable() else None
    )
    # Native telemetry is still specific to Claude and Codex. The other apps
    # use hooks for both capture and decisions.
    targets = [(agent, hooks.settings_path(agent, config), hooks.codex_config_path(config), hook_state[agent])
               for agent in (*integrations.AGENTS, *hooks.APP_EVENTS) if agent != "codex"]
    codex_paths = hooks.codex_paths(config)
    profiles = hooks.codex_profiles(config, codex_paths)
    profiles[0]["available"] |= detected["codex_available"]
    targets[:0] = [("codex", path, config_toml, profile)
                   for (path, config_toml), profile in zip(codex_paths.items(), profiles)]
    for agent, path, config_toml, agent_state in targets:
        state_ok = (
            agent_state["installed"]
            and (agent != "codex" or agent_state["trusted"])
            and hooks.current(config.path, agent, path)
            and (
                runtime_executable is None
                or {os.path.normcase(path) for path in hooks.executables(
                    agent, path)} == {runtime_executable}
            )
        )
        if (
            (agent_state.get("available") if agent == "codex" or agent in hooks.APP_EVENTS else detected[agent + "_available"])
            and not live.get("disabled")
            and not hooks.opted_out(config, agent, profile=str(path) if agent == "codex" else None)
            and not agent_state.get("disabled")
            and not state_ok
        ):
            # The staged executable is referenced, never replaced here: an
            # older bundle must not overwrite a newer staged service.
            attempt(
                "hooks.install",
                lambda agent=agent, path=path, config_toml=config_toml: hooks.install(
                    path, hook_executable, agent,
                    config_path=config.path, config_toml=config_toml,
                ),
                agents=[agent],
            )
    # Settings rewritten for an agent that was already connected mean the
    # desired values changed (for example the receiver token); the running
    # receiver only picks them up after a restart.
    restarted = any(step["step"] == "service.restart" and step["ok"] for step in steps)
    if (
        reconfigured
        and state == "running"
        and live
        and not restarted
        and not service_state(live, options, installed)["service_newer"]
    ):
        attempt(
            "service.restart",
            lambda: manage("restart"),
            reason="settings",
        )
    return {
        "steps": steps,
        "restart_required": connected or any(
            step["step"] == "hooks.install" and step["ok"] for step in steps
        ),
        "agents_pending": False,
        **final_status(),
    }


def update_status(config, live):
    """Read the service's daily result without making a remote request."""
    cached = (live or {}).get("update") or updates.read_cache(config)
    current = app_version()
    latest = cached.get("latest", "") if config.enrolled() else ""
    current_key, latest_key = order_key(current), order_key(latest, cached.get("build"))
    return {
        "current": current,
        "latest": latest,
        "update_available": bool(current_key and latest_key and latest_key > current_key),
        "checked_at": cached.get("checked_at", ""),
    }


def update_check(config):
    """Compare the running sensor version with the version the server ships."""
    if not config.enrolled():
        raise ValueError(NOT_ENROLLED)
    current = app_version()
    client = Client.from_config(config, current)
    try:
        result = client.post("version", {})
        latest = str(result.get("version") or "")
    finally:
        client.close()
    if not latest:
        raise ValueError("the server did not report a version")
    current_key, latest_key = order_key(current), order_key(latest, result.get("build"))
    live = live_status(config)
    running = str(live.get("version") or "")
    running_key = order_key(running, live.get("build"))
    return {
        "current": current,
        "running": running,
        # Only a running service that ordering shows to be older gets
        # restarted by setup; the window words its notice accordingly.
        "running_outdated": bool(
            running_key and current_key and current_key > running_key
        ),
        "latest": latest,
        "update_available": bool(
            current_key and latest_key and latest_key > current_key
        ),
        "checked_at": now(),
    }


def connection_attempt(config, server, token):
    # Bind retries to this configuration, its original identity, and the exact
    # destination/link. Neither the link nor its token is persisted.
    binding = [str(config.path.resolve()), config.get("server_url"),
               config.get("tenant_id"), config.get("sensor_id"),
               config.get("auth_mode", "bearer"), server, token]
    reference = hashlib.sha256(json.dumps(binding).encode()).hexdigest()
    return Path(config["data_dir"]) / "connection-attempts" / reference


def switch_certificate_connection(config, preview, token, ca_certificate):
    from .credentials import activate, copy_config, private_directory

    if (config.get("credential_activation_pending")
            or (Path(config["data_dir"]) / "credentials" / "pending.json").exists()):
        raise ValueError("Finish the pending certificate operation before changing connections. The current connection has been kept.")
    check_reenrollment(config)
    server = preview["server_url"]
    directory = private_directory(connection_attempt(config, server, token))
    staged = Config.load(directory / "sensor.yaml")
    if not staged.path.exists():
        values = {key: value for key, value in config.items() if key not in IDENTITY_FIELDS}
        values["data_dir"] = str(directory)
        if same_origin(config.get("server_url", ""), server) and config.get("ca_cert"):
            values["server_url"], values["ca_cert"] = server, config["ca_cert"]
        staged = Config(staged.path, **values)
        staged.save()
    # A consumed enrollment link cannot be previewed again. Preserve the verified
    # preview before issuance so the original request can resume after a lost reply.
    atomic_write(directory / "preview.json", json.dumps(preview))
    if staged.enrolled() and not staged.get("credential_activation_pending"):
        if staged.get("auth_mode") == "mtls":
            activate(staged, app_version())
        else:
            client = Client.from_config(staged, app_version())
            try:
                client.post("version", {})
            finally:
                client.close()
    else:
        enroll(staged, server, token, version=app_version(),
               auth_mode=preview["auth_mode"], tenant_id=preview["tenant"]["id"],
               ca_certificate=ca_certificate)
    staged = Config.load(staged.path)
    if (not staged.enrolled() or staged.get("credential_activation_pending")
            or not same_origin(staged["server_url"], server)
            or staged.get("tenant_id") != preview["tenant"]["id"]
            or staged.get("auth_mode", "bearer") != preview["auth_mode"]):
        raise ValueError("The new connection could not be verified. The current connection has been kept.")
    # Only the active identity changes. Existing queues, collection checkpoints,
    # settings and old credentials remain in place; new keys retain durable paths.
    candidate = Config(config.path, **{key: value for key, value in config.items() if key not in IDENTITY_FIELDS})
    candidate.update({key: staged[key] for key in IDENTITY_FIELDS if key in staged})
    candidate.validate()
    candidate.save()
    copy_config(config, candidate)
    discard_policy_cache(config)
    try:
        source = directory / "server-config.json"
        atomic_write(Path(config["data_dir"]) / source.name, source.read_text() if source.exists() else "{}")
    except OSError as exc:
        logging.warning("connection saved; control-plane settings will refresh: %s", exc)
    return {"sensor_id": config["sensor_id"], "tenant": preview["tenant"]}


def preview_enrollment(config, link, ca_certificate=None):
    server, token = parse_enrollment_link(link)
    supplied_ca = validate_ca_certificate(ca_certificate) if ca_certificate is not None else None
    saved_preview = connection_attempt(config, server, token) / "preview.json"
    if config.enrolled() and saved_preview.exists():
        # This is retry metadata, not authorization. Issuance/activation still
        # verifies the token or staged device credential with the destination.
        return json.loads(saved_preview.read_text())
    inherited_ca = (config.get("ca_cert")
                    if supplied_ca is None and same_origin(config.get("server_url", ""), server)
                    else None)
    client = Client(server, version=app_version(), ca_cert=inherited_ca, ca_certificate=supplied_ca,
                    network=config.get("network"))
    try:
        result = client.post("enrollment/preview", {"enrollment_token": token})
    except httpx.HTTPStatusError as exc:
        message = ("This enrollment link is invalid, expired, revoked, or already used. Ask your administrator for a new link."
                   if exc.response.status_code in (400, 401, 403) else
                   "The server could not preview this link. Ask your administrator to check enrollment link support on the server.")
        raise ValueError(message) from None
    except httpx.RequestError:
        raise ValueError("Could not verify the enrollment server. Check your connection, set a proxy in Settings > Network proxy if your network requires one, or ask your administrator to check the server certificate.") from None
    finally:
        client.close()
    try:
        tenant = result["tenant"]
        UUID(tenant["id"])
        expires = result["expires_at"]
        if (not isinstance(tenant["name"], str) or not 0 < len(tenant["name"]) <= 256
                or result["auth_mode"] not in ("bearer", "mtls")
                or datetime.fromisoformat(expires.replace("Z", "+00:00")) <= datetime.now(timezone.utc)):
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError("The server returned an invalid or expired enrollment preview") from None
    return {"server_url": server, "tenant": {k: tenant[k] for k in ("id", "name")},
            "auth_mode": result["auth_mode"], "expires_at": expires}


def connect_enrollment(config, params):
    # Serialize desktop connection changes and reject concurrent config writes.
    with configuration_lock(config.path):
        config = Config.load(config.path)
        preview = preview_enrollment(config, params.get("link"), params.get("ca_certificate"))
        if params.get("tenant_id") != preview["tenant"]["id"]:
            raise ValueError("The organization changed. Preview the enrollment link again before connecting.")
        server, token = parse_enrollment_link(params["link"])
        resume = False
        if config.enrolled():
            state = service.manage("status", config, timeout=5)
            live = live_status(config)
            if live and state != "running":
                raise ValueError("A manually started sensor is running. Stop that process before changing the connection.")
            if state not in ("running", "stopped", "not installed"):
                raise ValueError("Cannot verify the background service. Keep the current connection and refresh.")
            running_version = (live or {}).get("version") or recorded_service_version(config)
            if keep_existing(running_version, app_version(), (live or {}).get("build") or recorded_service_build(config)):
                raise ValueError("Install the newer desktop app before changing this sensor's connection.")
            if state == "running":
                deadline = time.monotonic() + 10
                while True:
                    if (not live or live.get("sensor_id") != config["sensor_id"]
                            or not same_origin(live.get("server_url", ""), config["server_url"])
                            or not version_key(live.get("version", ""))):
                        raise ValueError("Cannot verify the running sensor. Keep the current connection and refresh.")
                    if live.get("queue_depth") == 0 and (live.get("telemetry") or {}).get("queue_depth", 0) == 0:
                        break
                    if time.monotonic() >= deadline:
                        raise ValueError("The sensor is still sending queued activity. Your current connection is unchanged. Try again after the uploads finish.")
                    time.sleep(0.2)
                    live = live_status(config)
                # launchd can unload a job before its collectors have exited.
                # Wait for the process, then enroll's existing disk-queue guard
                # checks for arrivals during shutdown before consuming the link.
                try:
                    service.stop_and_wait(config)
                except Exception as exc:
                    raise ValueError("Could not pause the background service. Keep current connection, then try again.") from exc
                resume = True
        try:
            if config.enrolled() and (config.get("auth_mode", "bearer") == "mtls" or preview["auth_mode"] == "mtls"):
                result = switch_certificate_connection(config, preview, token, params.get("ca_certificate"))
            else:
                result = enroll(config, server, token, version=app_version(),
                                auth_mode=preview["auth_mode"], tenant_id=preview["tenant"]["id"],
                                ca_certificate=params.get("ca_certificate"))
        except Exception as exc:
            if resume:
                try:
                    service.manage("start", config, timeout=15)
                except Exception:
                    raise ValueError("The connection could not be changed, and the background service could not restart. Choose Keep current connection, then Retry setup.") from exc
            raise
        response = {"sensor_id": result["sensor_id"], "tenant": result.get("tenant", {}), "enrolled": True}
        if resume:
            try:
                service.manage("start", config, timeout=15)
            except Exception:
                # Enrollment is already committed and the link consumed. Return
                # success so the UI retries setup without submitting the link again.
                response["service_error"] = "Device connected, but the background service could not start. Retry setup."
        return response


def handle(request):
    if not isinstance(request, dict) or set(request) - {
        "action",
        "config_path",
        "params",
    }:
        raise ValueError("invalid bridge request")
    action = request.get("action")
    if action not in ACTIONS:
        raise ValueError("unsupported bridge action")
    if desktop_edition.enterprise_only():
        if action == "local-runtime.dashboard":
            return {"managed": False}
        if action in ("free.connect", "api-key.connect") or action.startswith("local-runtime."):
            raise ValueError(desktop_edition.MESSAGE)
    params = request.get("params") or {}
    if not isinstance(params, dict):
        raise ValueError("params must be an object")
    allowed = {
        "posture.configure": {"automatic", "scope"},
        "usage.summary": {"days"},
        "guardrails.summary": {"days"},
        "guardrails.denials": {"days", "until", "cursor", "review_version", "decision"},
        "guardrails.check": {"id", "scope", "review_version", "decision"},
        "guardrails.review": {"id", "scope", "label", "note", "review_version", "evidence_sha256", "expected_revision", "request_id"},
        "guardrails.configure": {"agent", "enabled", "profile"},
        "guardrails.configuration": {"agent", "profile"},
        "alerts.received": {"ids", "scope"},
        "alerts.acknowledge": {"id", "scope"},
        "enrollment.preview": {"link", "ca_certificate"},
        "enrollment.connect": {"link", "tenant_id", "ca_certificate"},
        "local-runtime.connect": {"password"},
        "enroll": {
            "server_url",
            "token",
            "label",
            "host_kind",
            "ca_certificate",
            "auth_mode",
            "tenant_id",
        },
        "api-key.connect": {"api_key"},
        "proxy.test": PROXY_FIELDS,
        "proxy.save": PROXY_FIELDS,
        "proxy.route": {"url"},
        "telemetry.install": {"agents", "paths"},
        "telemetry.remove": {"agents", "paths"},
    }.get(action, set())
    if set(params) - allowed:
        raise ValueError("unknown action parameter")
    config = Config.load(request.get("config_path"))
    if action.startswith("local-runtime."):
        from . import local_runtime

        if action == "local-runtime.docker-setup":
            return local_runtime.prepare_docker(config)
        if action == "local-runtime.connect":
            return local_runtime.connect(config, params.get("password", ""))
        return getattr(local_runtime, action.split(".")[1])(config)
    if action.startswith("guardrails."):
        from .desktop_guardrails import agent_request, exchange, summary

        if action in ("guardrails.denials", "guardrails.check", "guardrails.review"):
            return exchange(config, action.split(".")[1], params)
        return summary(config, params.get("days", 1)) if action == "guardrails.summary" else agent_request(config, action, params)
    if action in ("desktop.remove", "desktop.resume", "desktop.purge"):
        from . import removal

        return {"desktop.remove": removal.remove, "desktop.resume": removal.resume, "desktop.purge": removal.purge}[action](config)
    if action.startswith("alerts."):
        from .endpoint_alerts import exchange

        return exchange(config, action, params)
    if action.startswith("proxy."):
        return proxy_action(config, action, params)
    if action == "status":
        return status(config)
    if action == "credits.summary":
        from .desktop_credits import read

        return read(config)
    if action == "free.usage":
        from .desktop_free_usage import read

        return read(config)
    if action == "posture.summary":
        from .desktop_posture import read

        return read(config)
    if action == "posture.configure":
        from .posture_assessments import configure

        scope = params.get("scope")
        if not isinstance(scope, str) or not re.fullmatch(r"[0-9a-f]{64}", scope):
            raise ValueError("Invalid Posture connection scope.")
        return configure(config, params.get("automatic"), scope)
    if action == "usage.summary":
        days = params.get("days", 30)
        if type(days) is not int or days not in (1, 7, 14, 30):
            raise ValueError("days must be 1, 7, 14, or 30")
        from .usage import overview

        try:
            return overview(config, days)
        except sqlite3.Error:
            raise ValueError("Could not read usage stored on this device. Try refreshing.") from None
    if action == "simulation.status":
        from .simulation import status as simulation_status

        return simulation_status(config)
    if action == "setup":
        return setup(config)
    if action == "desktop.update.setup":
        with configuration_lock(config.path):
            return setup(Config.load(config.path), match_version=True)
    if action == "update.check":
        return update_check(config)
    if action == "enrollment.preview":
        return preview_enrollment(config, params.get("link"), params.get("ca_certificate"))
    if action == "enrollment.connect":
        return connect_enrollment(config, params)
    if action == "api-key.connect":
        from .api_key import activate

        return activate(config, params.get("api_key"))
    if action == "free.connect":
        from .free_enrollment import activate

        return activate(config)
    if action == "enroll":
        server, token = params.get("server_url"), params.get("token")
        if (
            not isinstance(server, str)
            or not isinstance(token, str)
            or not server
            or not token
        ):
            raise ValueError("server_url and token are required")
        from urllib.parse import urlsplit

        url = urlsplit(server)
        if (
            url.scheme not in ("http", "https")
            or not url.netloc
            or url.username
            or url.password
        ):
            raise ValueError(
                "server_url must be an HTTP(S) server URL without credentials"
            )
        result = enroll(
            config,
            server,
            token,
            params.get("label", ""),
            params.get("host_kind", ""),
            app_version(),
            ca_certificate=params.get("ca_certificate"),
            auth_mode=params.get("auth_mode", "bearer"),
            tenant_id=params.get("tenant_id", ""),
        )
        return {
            "sensor_id": result["sensor_id"],
            "tenant": result.get("tenant", {}),
            "enrolled": True,
        }
    if action.startswith("telemetry."):
        agents = params.get("agents", list(integrations.AGENTS))
        paths = params.get("paths", {})
        if (
            not isinstance(agents, list)
            or not agents
            or any(a not in integrations.AGENTS for a in agents)
        ):
            raise ValueError("agents must contain codex and/or claude")
        if not isinstance(paths, dict) or any(
            k not in integrations.AGENTS or not isinstance(v, str)
            for k, v in paths.items()
        ):
            raise ValueError("invalid settings paths")
        operation = (
            integrations.install
            if action == "telemetry.install"
            else integrations.remove
        )
        return operation(config, agents, paths)
    if not config.enrolled():
        raise ValueError(NOT_ENROLLED)
    service.manage(action.split(".", 1)[1], config)
    return {"service": service.manage("status", config)}


def main():
    try:
        raw = sys.stdin.read(65537)
        if len(raw) > 65536:
            raise ValueError("bridge request too large")
        request = json.loads(raw)
        # Enrollment and service tools must not pollute the one-response protocol.
        with contextlib.redirect_stdout(sys.stderr):
            result = handle(request)
        response = {"ok": True, "data": result}
    except Exception as exc:
        response = {"ok": False, "error": str(exc)}
    print(json.dumps(response))
    return 0
