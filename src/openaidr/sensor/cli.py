import time

# Taken before the remaining imports so a hook decision's end-to-end latency
# includes this command's own startup.
STARTED_NS = time.time_ns()

import argparse
from contextlib import contextmanager
from pathlib import Path
import json
import logging
import os
import signal
import sys
import threading
from .config import Config, default_path
from openaidr.core.protocol import HOOK_TIMEOUT_SECONDS


def app_version():
    from openaidr import __version__

    return __version__


def hook_summary(live):
    state = live.get("hooks_installed") or {}
    claude_state = state.get("claude") or {}
    claude = claude_state.get("installed", live.get("hook_installed"))
    codex = state.get("codex") or {}
    # A choice made in the agent's own settings needs a different remedy
    # than missing trust, so it is reported first.
    claude_text = (
        "disabled in Claude Code settings" if claude_state.get("disabled")
        else "installed" if claude else "not installed"
    )
    codex_text = (
        "disabled in Codex /hooks"
        if codex.get("disabled")
        else "installed and trusted"
        if codex.get("trusted")
        else "installed, awaiting trust in Codex"
        if codex.get("installed")
        else "not installed"
    )
    return f"Claude Code {claude_text}; Codex {codex_text}"


def connected_agents(config):
    """Agent products that still run OpenAIDR hooks or export telemetry to it."""
    from . import hooks, integrations

    names = []
    try:
        manifest = integrations.manifest(config)
        telemetry = integrations.status(config)
    except Exception:
        manifest, telemetry = {}, {}
    for agent in hooks.AGENTS:
        exporting = telemetry.get(agent + "_installed") or any(
            isinstance(entry, dict) and entry.get("agent") == agent and "pending" in entry
            for entry in manifest.values()
        )
        if hooks.present(hooks.settings_path(agent, config), agent=agent) or exporting:
            names.append(hooks.PRODUCTS[agent])
    return names


@contextmanager
def stop_on_signals(stop, signals=(signal.SIGINT, signal.SIGTERM)):
    """Set stop on a termination signal without taking a lock in the handler.

    Python runs a handler between any two bytecodes of the main thread, even
    while that thread holds Event's non-reentrant lock inside wait() or inside
    an earlier handler's set(). systemd and the frozen launcher each send the
    service SIGTERM, so calling stop.set() in the handler can deadlock the main
    thread until the service manager kills it. The C-level handler writes to
    the wakeup socket instead, and a thread sets stop.
    """
    import socket

    reader, writer = socket.socketpair()
    with reader, writer:
        writer.setblocking(False)
        previous_fd = signal.set_wakeup_fd(writer.fileno(), warn_on_full_buffer=False)
        handlers, thread = {}, None
        try:
            for number in signals:
                handlers[number] = signal.signal(number, lambda *_: None)

            def wait():
                # Every signal with a Python handler writes its number.
                while data := reader.recv(1):
                    if data[0] in signals:
                        stop.set()
                        return

            thread = threading.Thread(target=wait, daemon=True)
            thread.start()
            yield
        finally:
            # Keep both sockets alive through shutdown, even after wait returns.
            signal.set_wakeup_fd(previous_fd)
            writer.close()  # EOF also releases the reader when no signal arrived.
            if thread is not None and thread.ident is not None:
                thread.join()
            for number, handler in handlers.items():
                signal.signal(number, handler)


def setup(config):
    from . import service
    from .bridge import setup as setup_sensor, status as sensor_status

    result = setup_sensor(config, require_control=True)
    started = any(
        step["ok"] and step["step"] in ("service.install", "service.start", "service.restart")
        for step in result["steps"]
    )
    wait_for_service = started or result["service"] == "running"
    deadline = time.monotonic() + 10

    def receiver_ready():
        return result["disabled"] or not result["telemetry"]["enabled"] or result["telemetry"].get("listening", False)

    def ready():
        return (
            result["service"] == "running" and result["running"] and result["control_ready"]
            and receiver_ready() and not result["service_outdated"] and not result["settings_stale"]
        )

    def wait_for_ready():
        while wait_for_service and not ready():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.25, remaining))
            if time.monotonic() >= deadline:
                break
            result.update(sensor_status(config, deadline=deadline, private=True))

    wait_for_ready()
    if ready() and result["agents_pending"]:
        steps = result["steps"]
        result = setup_sensor(config, require_control=True)
        restarted = any(
            step["ok"] and step["step"] in ("service.install", "service.start", "service.restart")
            for step in result["steps"]
        )
        result["steps"] = steps + result["steps"]
        if restarted:
            deadline = time.monotonic() + 10
        started = started or restarted
        wait_for_service = started or result["service"] == "running"
        wait_for_ready()
    errors = []
    for step in result["steps"]:
        label = step["step"]
        if step.get("agents"):
            label += " (" + ", ".join(step["agents"]) + ")"
        if not step["ok"]:
            errors.append(label + ": " + step["error"])
        elif not label.startswith(("service.skip", "telemetry.skip")):
            print(label + ": done")
    foreground = result["foreground"] or any(
        step["step"] == "service.skip" and step.get("reason") == "foreground"
        for step in result["steps"]
    )
    if foreground and not started:
        errors.append(
            "Stop the foreground sensor, then rerun openaidr setup to install the background service."
        )
    elif result["service_downgrade"]:
        errors.append(
            "The service needs a newer sensor executable. Install it and rerun openaidr setup."
        )
    elif result["service"] != "running":
        errors.append("The background service is not running. Check the service logs.")
    elif not result["running"]:
        errors.append("The service's private status socket is unavailable or cannot be verified. Check the service logs and data directory.")
    elif result["service_outdated"]:
        errors.append("The service still runs an older sensor version. Check its executable and restart it, then rerun setup.")
    elif result["settings_stale"]:
        errors.append(
            "The newer running sensor uses previous settings. Restart it with its newer executable, then rerun setup."
            if result["service_newer"] else
            "The running sensor has not loaded the current receiver settings. Check the service logs and rerun setup."
        )
    elif not receiver_ready():
        errors.append("The telemetry receiver is not listening. Check for an occupied port and rerun setup.")
    elif not result["control_ready"] or result["agents_pending"]:
        errors.append("Agent setup is waiting for the first server response. Check the server connection and rerun setup.")
    else:
        try:
            if service.enable_boot():
                print("Startup at boot: enabled")
        except Exception as exc:
            errors.append("Startup at boot: " + str(exc))
    if result["restart_required"] or any(
        step["step"] == "hooks.install" and step["ok"] for step in result["steps"]
    ):
        print("Restart the configured Codex and Claude Code sessions to load telemetry and hooks.")
    if errors:
        for error in errors:
            print("error: " + error, file=sys.stderr)
        print("Setup incomplete. Fix the errors and rerun openaidr setup.", file=sys.stderr)
        return 1
    print("Setup completed. The sensor service is running.")
    if result["disabled"]:
        print("Collection is disabled by the server.")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv == ["desktop-usage"]:
        from .usage import main as usage_main

        return usage_main()
    if argv in (["windows-layout-migrate"], ["windows-layout-migrate", "--check"]):
        from .windows_layout import main as migrate_windows_layout

        return migrate_windows_layout(check=len(argv) == 2)
    # Installed Windows hooks must reach the running sensor without importing
    # its collectors, policy engine, telemetry stack, or service management.
    if (os.name == "nt" and argv and argv[0] == "hook"
            and os.environ.get("OPENAIDR_HOOK_TIMEOUT_OWNER") == "agent"
            and not any(arg in ("install", "uninstall") for arg in argv[1:])):
        from .hook_client import main as hook_main

        return hook_main(argv[1:], started_ns=STARTED_NS)

    from .runtime import Sensor, enroll, NOT_ENROLLED
    from . import hooks, service
    from .tls import read_ca_certificate

    native_args = ()
    if argv and argv[0] == "managed" and "--" in argv:
        split = argv.index("--")
        native_args, argv = tuple(argv[split + 1:]), argv[:split]
    if argv and argv[0] == "desktop-bridge":
        from .bridge import main as bridge_main

        return bridge_main()
    if argv == ["simulate-devices"]:
        from .simulation import main as simulation_main

        return simulation_main()
    if argv and argv[0] == "managed-hook":
        from openaidr.guardrail.hook_bridge import MAX_MESSAGE, denied, forward_if_managed

        if len(argv) != 3 or argv[1] not in ("codex", "claude"):
            return 1
        agent, event = argv[1:]
        try:
            raw = sys.stdin.buffer.read(MAX_MESSAGE + 1)
            payload = json.loads(raw) if len(raw) <= MAX_MESSAGE else None
            if not isinstance(payload, dict):
                raise ValueError
            result = forward_if_managed(agent, event, payload, _owned=True)
        except (ValueError, OSError):
            result = denied(event)
        print(json.dumps(result if result is not None else denied(event)), flush=True)
        return 0
    if argv and argv[0] in ("--version", "-v"):
        argv[0] = "version"
    if argv and argv[0] == "help":
        argv[0] = "--help"
    parser = argparse.ArgumentParser(
        prog="openaidr", epilog="Config file: " + str(default_path())
    )
    sub = parser.add_subparsers(dest="command", required=True)
    cowork = sub.add_parser("cowork-plugin", help="package a personal Cowork hook plugin")
    cowork.add_argument("--connection-file", required=True)
    cowork.add_argument("--output", required=True)
    sub.add_parser("version")
    sub.add_parser("build-info", help="report embedded version and source metadata as JSON")
    managed = sub.add_parser("managed", help="recover retained managed-session records with --reconcile")
    managed.add_argument("client", choices=("codex", "claude"))
    managed.add_argument("--config")
    managed.add_argument("--cwd", default=os.getcwd(), help=argparse.SUPPRESS)
    managed.add_argument("--reconcile", action="store_true", help="deliver retained records without restarting native actions")
    setup_parser = sub.add_parser(
        "setup",
        help="configure detected agents and start the background service",
        description=(
            "Set up an enrolled Linux sensor and detected coding agents for the current account. "
            "Enable startup at boot, using sudo for user lingering only if needed."
        ),
    )
    setup_parser.add_argument("--config")
    credential_parser = sub.add_parser(
        "credentials",
        help="migrate, renew or recover device certificates without changing queued data",
    )
    credential_parser.add_argument("operation", choices=("migrate", "renew", "recover"))
    credential_parser.add_argument("--config")
    credential_parser.add_argument(
        "--tenant-id", help="trusted tenant UUID, required for migration"
    )
    credential_parser.add_argument(
        "--token", default="", help="administrator-issued recovery token"
    )
    inventory_parser = sub.add_parser(
        "inventory", help="scan installed software locally without enrollment"
    )
    inventory_parser.add_argument("--json", action="store_true")
    components_parser = sub.add_parser(
        "component-inventory",
        help="scan CLI tools and supported platform components locally without enrollment",
    )
    components_parser.add_argument("--json", action="store_true")
    components_parser.add_argument("--no-default-roots", action="store_true")
    for kind in ("app", "npm", "python", "skill", "plugin", "project", "bin"):
        components_parser.add_argument(f"--{kind}-root", action="append", default=[])
    components_parser.add_argument("--mcp-config", action="append", default=[])
    sub.add_parser(
        "osquery-check", help="verify bundled osquery and its OpenAIDR extension locally"
    )
    sub.add_parser(
        "desktop-bridge", help="JSON subprocess interface for the optional desktop app"
    )
    telemetry_parser = sub.add_parser(
        "telemetry", help="configure native Codex/Claude OTLP exports"
    )
    telemetry_parser.add_argument(
        "operation", choices=("install", "configure", "remove", "status", "antigravity-statusline", "sessions", "hook-estimates")
    )
    telemetry_parser.add_argument("--config")
    telemetry_parser.add_argument(
        "--agent", choices=("codex", "claude", "all"), default="all"
    )
    telemetry_parser.add_argument("--codex-config")
    telemetry_parser.add_argument("--claude-settings")
    telemetry_parser.add_argument("--json", action="store_true")
    for name in (
        "enroll",
        "run",
        "install",
        "uninstall",
        "start",
        "stop",
        "restart",
        "status",
    ):
        p = sub.add_parser(name)
        p.add_argument("--config")
        if name == "enroll":
            p.add_argument("--server", required=True)
            p.add_argument("--token", required=True)
            p.add_argument("--label", default="")
            p.add_argument("--host-kind", choices=("workstation", "server"), default="")
            p.add_argument("--force", action="store_true")
            p.add_argument("--auth-mode", choices=("bearer", "mtls"), default="bearer")
            p.add_argument(
                "--tenant-id", default="", help="trusted tenant UUID required for mTLS"
            )
            p.add_argument(
                "--ca-cert",
                help="public CA PEM for verified private HTTPS (32 KiB maximum)",
            )
        if name == "run":
            p.add_argument("--foreground", action="store_true", default=True)
        if name == "status":
            p.add_argument("--json", action="store_true")
    p = sub.add_parser("hook")
    p.add_argument("event", nargs="?", default="")
    p.add_argument("--settings")
    p.add_argument("--agent", choices=(*hooks.AGENTS, "all"), default="claude")
    p.add_argument("--config")
    args = parser.parse_args(argv)
    try:
        if args.command == "managed":
            from .launch import main as managed_main

            return managed_main(args, native_args)
        if args.command == "version":
            print("openaidr " + app_version())
            return 0
        if args.command == "build-info":
            from openaidr.build_info import current

            print(json.dumps(current()))
            return 0
        if args.command == "osquery-check":
            from .osquery_runtime import check_runtime

            print(json.dumps(check_runtime()))
            return 0
        if args.command == "cowork-plugin":
            from .cowork_plugin import build

            print(build(args.connection_file, args.output))
            return 0
        if args.command == "inventory":
            from .inventory import collect_inventory

            result = collect_inventory()
            print(json.dumps(result, indent=None if args.json else 2))
            return 0
        if args.command == "component-inventory":
            from . import component_inventory

            values = {
                f"{kind}_roots": getattr(args, f"{kind}_root")
                for kind in ("app", "npm", "python", "skill", "plugin", "project", "bin")
            }
            values["include_default_roots"] = not args.no_default_roots
            values["mcp_configs"] = args.mcp_config
            options = component_inventory.settings(
                {"inventory": {"components": values}}
            )
            result = component_inventory.collect_inventory(options)
            print(json.dumps(result, indent=None if args.json else 2))
            return 0
        if args.command == "telemetry":
            if args.operation == "hook-estimates":
                from .hook_estimates import overview
                print(json.dumps(overview(Config.load(args.config)), indent=None if args.json else 2))
                return 0
            if args.operation == "antigravity-statusline":
                from .antigravity_usage import submit
                submit(args.config, sys.stdin)
                return 0
            if args.operation == "sessions":
                from .antigravity_usage import overview
                print(json.dumps(overview(Config.load(args.config)), indent=None if args.json else 2))
                return 0
            from . import integrations
            from .bridge import status as bridge_status

            config = Config.load(args.config)
            agents = list(integrations.AGENTS) if args.agent == "all" else [args.agent]
            paths = {
                key: value
                for key, value in {
                    "codex": args.codex_config,
                    "claude": args.claude_settings,
                }.items()
                if value
            }
            if args.operation in ("install", "configure"):
                hooks.remember_homes(config)
                result = integrations.install(config, agents, paths)
            elif args.operation == "remove":
                result = integrations.remove(config, agents, paths)
            else:
                result = bridge_status(config)["telemetry"]
            print(json.dumps(result, indent=None if args.json else 2))
            return 0
        if args.command == "hook":
            agents = list(hooks.AGENTS) if args.agent == "all" else [args.agent]
            if args.event in ("install", "uninstall"):
                if args.settings and len(agents) != 1:
                    raise ValueError("--settings applies to a single --agent")
                # The same config the forwarding command reads, made absolute
                # because agents run hooks from the project directory.
                config_path = (
                    Path(
                        args.config
                        or os.environ.get("OPENAIDR_SENSOR_CONFIG")
                        or default_path()
                    )
                    .expanduser()
                    .resolve()
                )
                config = Config.load(config_path)
                # A custom CLAUDE_CONFIG_DIR or CODEX_HOME set in this shell is
                # recorded for the service and desktop app, which never see it.
                hooks.remember_homes(config)
                for agent in agents:
                    path = args.settings or hooks.settings_path(agent, config)
                    if args.event == "install":
                        # The staged service executable, as setup and the
                        # server command use: a transient app-bundle or
                        # download path can disappear after an update.
                        hooks.install(
                            path, service.hook_executable(), agent, config_path=config_path,
                            explicit=True, config_toml=hooks.codex_config_path(config),
                        )
                        hooks.set_opt_out(config, agent, False)
                        print(
                            f"Installed OpenAIDR {hooks.PRODUCTS[agent]} hooks in {path}"
                        )
                        if agent == "codex":
                            print(
                                "Recorded trust for them in "
                                + str(hooks.codex_config_path(config))
                                + "; Codex loads hooks at its next session start"
                            )
                        elif agent == "hermes":
                            print("Start hermes chat in this profile and approve the OpenAIDR hook commands")
                    else:
                        hooks.uninstall(path, agent, hooks.codex_config_path(config),
                                        config_path=config_path)
                        hooks.set_opt_out(config, agent, True)
                        print(
                            f"Removed OpenAIDR {hooks.PRODUCTS[agent]} hooks from {path}"
                        )
                return 0
            if args.agent == "all":
                raise ValueError("hook events are forwarded for one agent at a time")
            # Forwarding starts nothing meant to outlive it; on Windows, anything
            # it does start ends with it, so none holds the agent's output pipe.
            from .hook_runtime import EXIT_RESERVE_NS, contain_descendants

            contain_descendants()
            product = hooks.PRODUCTS[args.agent]
            from openaidr.guardrail.hook_bridge import ENVIRONMENT_KEY, denied, forward_if_managed

            if args.agent in ("claude", "codex") and os.environ.get(ENVIRONMENT_KEY):
                # The injected synchronous hook holds this boundary. The installed
                # observer has a short native deadline and must not duplicate it.
                # Drain without retaining or parsing native content of any size.
                try:
                    while sys.stdin.buffer.read(64 << 10):
                        pass
                    managed_reply = forward_if_managed(args.agent, args.event, {})
                except (ValueError, OSError):
                    managed_reply = denied(args.event)
                print(json.dumps(managed_reply if managed_reply is not None else denied(args.event)), flush=True)
                return 0
            try:
                config = Config.load(
                    args.config or os.environ.get("OPENAIDR_SENSOR_CONFIG")
                )
                started_ns = int(os.environ.get("OPENAIDR_HOOK_STARTED_NS", STARTED_NS))
                timeout_owner = os.environ.get("OPENAIDR_HOOK_TIMEOUT_OWNER")
                agent_timeout = timeout_owner == "agent"
                # Preserve the budgets of older immutable launchers.
                duration_ns = (HOOK_TIMEOUT_SECONDS if timeout_owner == "sensor" else 2) * 1_000_000_000
                deadline_ns = min(
                    int(os.environ.get("OPENAIDR_HOOK_DEADLINE_NS", STARTED_NS + duration_ns)),
                    STARTED_NS + duration_ns,
                )
                if not agent_timeout and os.name != "nt" and os.environ.get("OPENAIDR_HOOK_WRAPPED") == "1":
                    budget_ns = duration_ns - EXIT_RESERVE_NS if timeout_owner == "sensor" else 1_400_000_000
                    deadline_ns = min(deadline_ns, started_ns + budget_ns)
                if deadline_ns <= time.time_ns():
                    raise TimeoutError("hook deadline expired")
                payload = sys.stdin.buffer.read(4 << 20)
                from urllib.parse import urlencode

                query = {"event": args.event, "started": started_ns, "deadline": deadline_ns}
                if timeout_owner in ("agent", "sensor"):
                    query["timeout_owner"] = timeout_owner
                if args.event == "PreToolUse":
                    # The hook runs as the native agent user; the daemon can run
                    # as a different account and must not guess that user's home.
                    query["path_home"] = str(Path.home())
                if os.environ.get("OPENAIDR_HOOK_WRAPPED") == "1":
                    query["execution"] = os.environ.get("OPENAIDR_HOOK_EXECUTION_ID", "")
                if args.event == "PostToolUse" and hooks.result_capable(config, args.agent):
                    query["result_capable"] = "1"
                remaining = (deadline_ns - time.time_ns()) / 1e9 - (0 if agent_timeout else 0.05)
                if remaining <= 0:
                    raise TimeoutError("hook deadline expired")
                result = hooks.local_request(
                    config,
                    "POST",
                    hooks.ROUTES[product] + "?" + urlencode(query),
                    content=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=None if agent_timeout else remaining,
                )
                if result.get("failed") or time.time_ns() >= deadline_ns:
                    raise ValueError("hook response unavailable")
                output = result.get("output") or result.get("claude_code") or {}
                if not isinstance(output, dict):
                    raise ValueError("invalid hook response")
                # Codex treats any stdout from some hooks as model context or as
                # a failure, so it only sees output when there is a decision.
                if output:
                    print(json.dumps(output), flush=True)
            except Exception:
                # Only the native launcher sees this status. It discards failed
                # output and records the outcome when the native agent has not killed it.
                return 1 if os.environ.get("OPENAIDR_HOOK_WRAPPED") == "1" else 0
            return 0
        try:
            config = Config.load(args.config)
        except Exception:
            if args.command != "uninstall":
                raise
            # Removing the background service reads no settings, and the
            # Windows uninstaller stops when this fails: an unreadable config
            # must not leave the app impossible to uninstall.
            config = Config(args.config)
        if args.command == "setup":
            return setup(config)
        if args.command == "credentials":
            try:
                from .credentials import operate
            except ImportError as exc:
                raise ValueError(
                    "certificate operations require the openaidr[device] extra"
                ) from exc
            result = operate(
                config,
                args.operation,
                token=args.token,
                tenant_id=args.tenant_id,
                version=app_version(),
            )
            print(
                f"Device credentials {args.operation} completed for sensor {result['sensor_id']}. Config: {config.path}"
            )
        elif args.command == "enroll":
            if (
                config.enrolled()
                and not args.force
                and not (
                    args.auth_mode == "mtls"
                    and config.get("credential_activation_pending")
                )
            ):
                raise ValueError("already enrolled (use --force to re-enroll)")
            result = enroll(
                config,
                args.server,
                args.token,
                args.label,
                args.host_kind,
                app_version(),
                ca_certificate=read_ca_certificate(args.ca_cert)
                if args.ca_cert
                else None,
                auth_mode=args.auth_mode,
                tenant_id=args.tenant_id,
            )
            next_step = (
                "openaidr telemetry configure --agent all\n"
                "      openaidr hook install --agent all\n"
                "      openaidr install"
                if service.platform.system() != "Linux" else "openaidr setup"
            )
            print(
                f"Enrolled sensor {result['sensor_id']} with tenant {result.get('tenant', {}).get('name', '')!r}.\nConfig written to {config.path}\nBackend policy version {result.get('policy_version', 0)}.\nNext: {next_step}   (or: openaidr run)"
            )
        elif args.command == "run":
            logging.basicConfig(
                level={
                    "debug": logging.DEBUG,
                    "info": logging.INFO,
                    "warn": logging.WARNING,
                    "error": logging.ERROR,
                }.get(config["log_level"], logging.INFO)
            )
            stop = threading.Event()
            with stop_on_signals(stop):
                Sensor(config, app_version()).run(stop)
        elif args.command == "status":
            try:
                live = hooks.local_request(config, "GET", "/v1/status")
            except Exception as exc:
                if args.json:
                    raise ValueError("sensor not running: " + str(exc)) from exc
                live = None
            if args.json:
                print(json.dumps(live))
                return 0
            try:
                service_status = service.manage("status", config)
            except (OSError, ImportError):
                service_status = "unknown"
            print(
                f"Config:    {config.path}\nData dir:  {config['data_dir']}\nVersion:   {app_version()}\nEnrolled:  {'yes, sensor ' + config['sensor_id'] + ' at ' + config['server_url'] if config.enrolled() else 'no'}\nService:   {service_status}"
            )
            if live:
                print(
                    f"Listener:  {config['listen']}, up {live['uptime_s']}s\nCollection: {'disabled by server' if live['disabled'] else 'enabled'}"
                )
                for collector in live["collectors"]:
                    print(
                        f"  {collector['name']:<12} {collector['status']:<8} files={collector['files_watched']} events={collector['events_total']}"
                    )
                print(
                    f"Queue:     {live['queue_depth']} pending, {live['ship']['shipped']} shipped, {live['ship']['rejected']} rejected, {live['spool_dropped']} dropped\nHeartbeat: {live['last_heartbeat_at'] or 'never'}\nPolicy:    backend version {live['policy_version']}\nHooks:     {hook_summary(live)}; evaluated={live['hooks']['evaluated']} denied={live['hooks']['denied']} warned={live['hooks']['warned']}"
                )
                if live.get("heartbeat_error"):
                    print("Heartbeat error: " + live["heartbeat_error"])
                inventory = live.get("inventory", {})
                if inventory.get("enabled"):
                    print(
                        f"Inventory: {inventory.get('applications', 0)} software records; "
                        f"last scan {inventory.get('collected_at') or 'not scanned'}; "
                        f"{'pending upload' if inventory.get('pending') else 'no pending upload'}"
                    )
                    if inventory.get("last_error"):
                        print("Inventory error: " + inventory["last_error"])
                components = live.get("component_inventory", {})
                if components.get("enabled"):
                    print(
                        f"Component inventory: {components.get('components', 0)} records; "
                        f"{components.get('roots', 0)} roots; "
                        f"{'pending upload' if components.get('pending') else 'no pending upload'}"
                    )
                    if components.get("last_error"):
                        print("Component inventory error: " + components["last_error"])
                if live["ship"].get("last_error"):
                    print("Ship error: " + live["ship"]["last_error"])
            else:
                print("Listener:  not reachable at " + config["listen"])
        else:
            if args.command == "install" and not config.enrolled():
                raise ValueError(NOT_ENROLLED)
            service.manage(args.command, config)
            print("Service " + args.command + " completed.")
            if args.command == "uninstall":
                remaining = connected_agents(config)
                if remaining:
                    print(
                        "warning: OpenAIDR is still connected to "
                        + " and ".join(remaining)
                        + ". The service is removed, but those agents still run its hooks or export "
                        "telemetry to it. To remove them, run:\n"
                        "  openaidr hook uninstall --agent all\n"
                        "  openaidr telemetry remove --agent all",
                        file=sys.stderr,
                    )
        return 0
    except Exception as exc:
        print("error:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
