"""Command-line entry point for the OpenAIDR server."""

import argparse
from dataclasses import replace
import json
import logging
from pathlib import Path
import sys

from .version import __version__


def application(cfg, st):
    """The production application factory, also used by installed-image probes."""
    from .app import create_app

    return create_app(cfg, st, customer=True)


def main(argv=None):
    # Spawned policy workers import this entry point without running main.
    import psycopg
    from .auth import hash_password
    from .config import from_env
    from .store import Store, Conflict, NotFound

    parser = argparse.ArgumentParser(prog="openaidr-server")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version", help="print the version")
    serve = commands.add_parser("serve", help="run the enabled services")
    for name in ("listen", "services", "database-url", "public-url", "log-level"):
        serve.add_argument(
            "--" + name,
            help="host:port or unix:/absolute/socket/path"
            if name == "listen"
            else None,
        )
    migrate = commands.add_parser("migrate", help="apply database migrations")
    migrate.add_argument("--database-url")
    telemetry = commands.add_parser(
        "telemetry", help="maintain stored native telemetry"
    ).add_subparsers(dest="telemetry_command", required=True)
    translate = telemetry.add_parser(
        "translate", help="derive detection events from untranslated logs exports"
    )
    translate.add_argument(
        "--limit", type=int, default=0, help="exports to process (0: all pending)"
    )
    translate.add_argument("--database-url")
    costs = telemetry.add_parser("costs", help="process pending agent cost exports")
    costs.add_argument("--limit", type=int, default=0, help="exports to process (0: all pending)")
    costs.add_argument("--database-url")
    costs.add_argument("--reprice", action="store_true", help="reprice retained usage for OPENAIDR_TENANT_ID with the current quote")
    costs.add_argument("--rebuild-summaries", action="store_true", help="rebuild hourly summaries for OPENAIDR_TENANT_ID")
    billing = commands.add_parser("billing", help="collect or read provider billing reports")
    billing.add_argument("operation", choices=("sync", "report"))
    billing.add_argument("--provider", choices=("copilot", "cursor"), required=True)
    billing.add_argument("--account-scope", choices=("organization", "enterprise", "user", "team"), default="organization")
    billing.add_argument("--account")
    billing.add_argument("--month", help="calendar month YYYY-MM")
    billing.add_argument("--billing-model", choices=("ai_credit", "premium_request", "current_cycle"))
    billing.add_argument("--database-url")
    from .config import PLATFORM_AVAILABLE

    if PLATFORM_AVAILABLE:
        from openaidr.platform.cli import add_admin_commands

        add_admin_commands(commands)
    tenant = commands.add_parser(
        "tenant", help="bootstrap a self-hosted tenant"
    ).add_subparsers(dest="tenant_command", required=True)
    bootstrap = tenant.add_parser(
        "bootstrap", help="create/reuse tenant and issue an enrollment token"
    )
    bootstrap.add_argument("--name", required=True)
    bootstrap.add_argument("--slug", required=True)
    bootstrap.add_argument(
        "--max-uses", type=int, default=0, help="enrollments allowed (0: unlimited)"
    )
    bootstrap.add_argument("--label", default="bootstrap")
    bootstrap.add_argument("--database-url")
    bootstrap.add_argument("--public-url")
    bootstrap.add_argument(
        "--json", action="store_true", help="emit credentials as JSON to stdout"
    )
    if PLATFORM_AVAILABLE:
        from openaidr.platform.cli import add_readiness_command

        add_readiness_command(tenant)
    user_commands = tenant.add_parser(
        "user", help="manage users for the bound tenant"
    ).add_subparsers(dest="user_command", required=True)
    user_create = user_commands.add_parser(
        "create", help="create a tenant owner without resetting existing users"
    )
    user_create.add_argument("--email", required=True)
    user_create.add_argument("--name", required=True)
    user_create.add_argument("--password-stdin", action="store_true", required=True)
    user_create.add_argument("--database-url")
    user_create.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "version":
        print("openaidr-server", __version__ or "Not reported")
        return 0
    try:
        cfg = from_env()
    except (OSError, ValueError) as exc:
        print("error:", exc, file=sys.stderr)
        return 1
    for name in ("listen", "database_url", "public_url", "log_level"):
        if getattr(args, name, None):
            setattr(cfg, name, getattr(args, name))
    if getattr(args, "services", None):
        cfg.set_services(args.services)
    logging.basicConfig(
        level=getattr(
            logging, cfg.log_level.upper().replace("WARN", "WARNING"), logging.INFO
        )
    )
    try:
        from .service_enrollment import prepare
        enrollment = prepare(cfg)
        if enrollment is not None:
            cfg = replace(cfg, tenant_id=enrollment.connection.tenant_id)
        if args.command in ("tenant", "billing") or (args.command == "telemetry" and args.telemetry_command == "costs"):
            cfg.set_services("ingest")
        cfg.validate(
            allow_unbound=args.command == "tenant"
            and args.tenant_command == "bootstrap",
            customer=True,
        )
        listener = {}
        if args.command == "serve":
            if cfg.listen.startswith("unix:"):
                path = cfg.listen.removeprefix("unix:")
                if not Path(path).is_absolute():
                    raise ValueError("Unix listener requires an absolute socket path")
                listener = {"uds": path, "proxy_headers": False}
            else:
                host, port = cfg.listen.rsplit(":", 1)
                listener = {"host": host.strip("[]") or "0.0.0.0", "port": int(port)}
                if not 1 <= listener["port"] <= 65535:
                    raise ValueError("listener port must be between 1 and 65535")
        if (
            args.command == "tenant"
            and args.tenant_command == "user"
            and not cfg.tenant_id
        ):
            raise ValueError("OPENAIDR_TENANT_ID is required to create a tenant owner")
        st = Store(
            cfg.database_url,
            db_pool_size=cfg.db_pool_size,
            auth_pool_size=cfg.auth_pool_size,
            db_pool_timeout=cfg.db_pool_timeout,
        )
        try:
            if args.command == "migrate":
                print("migrations applied:", ", ".join(st.migrate()))
            elif args.command == "billing":
                from .agent_billing import overview

                if not cfg.tenant_id:
                    raise ValueError("OPENAIDR_TENANT_ID is required")
                st.migrate()
                if args.operation == "report":
                    result = overview(st, cfg.tenant_id, args.provider)
                elif args.provider == "copilot":
                    from .copilot_billing import sync
                    result = sync(st, cfg.tenant_id, args.account_scope, args.account, args.month, args.billing_model)
                else:
                    from .cursor_billing import sync
                    if args.month or args.account_scope != "team" or args.billing_model not in (None, "current_cycle"):
                        raise ValueError("Cursor supports --account-scope team and the current billing cycle, without --month")
                    result = sync(st, cfg.tenant_id, args.account)
                print(json.dumps(result))
                return 1 if result.get("status") == "failed" else 0
            elif args.command == "telemetry":
                st.migrate()
                if args.telemetry_command == "costs":
                    from .agent_cost_usage import process_pending, queue_repricing
                    from .agent_cost_summaries import queue_rebuild, rebuild_pending
                    from .agent_projects import pending_count, process_pending as project_sessions

                    if args.limit < 0:
                        raise ValueError("limit must be nonnegative")
                    if args.reprice:
                        queue_repricing(st, cfg.tenant_id)
                    if args.rebuild_summaries:
                        queue_rebuild(st, cfg.tenant_id)

                    done_total = {"exports": 0, "failed": 0}
                    while True:
                        remaining = args.limit - sum(done_total.values()) if args.limit else 50
                        if remaining <= 0:
                            break
                        done = process_pending(st, cfg.tenant_id or None, min(50, remaining))
                        for key in done_total:
                            done_total[key] += done[key]
                        if sum(done.values()) == 0:
                            break
                    while project_sessions(st, cfg.tenant_id or None):
                        pass
                    while rebuild_pending(st, cfg.tenant_id or None):
                        pass
                    with st.transaction() as conn:
                        done_total["pending_project_sessions"] = pending_count(conn, cfg.tenant_id or None)
                    done_total["pending_summary_hours"] = st.scalar(
                        """SELECT count(*) FROM agent_cost_dirty_hours
                           WHERE ($1::uuid IS NULL OR tenant_id=$1)""",
                        cfg.tenant_id or None,
                    )
                    print(json.dumps(done_total))
                    return 1 if done_total["failed"] or done_total["pending_summary_hours"] or done_total["pending_project_sessions"] else 0
                totals = {"exports": 0, "events": 0}
                pending = args.limit if args.limit > 0 else None
                while True:
                    step = 200 if pending is None else min(pending, 200)
                    if step <= 0:
                        break
                    done = st.translate_untranslated_exports(
                        cfg.tenant_id or None, step
                    )
                    for key in totals:
                        totals[key] += done[key]
                    if pending is not None:
                        pending -= done["exports"]
                    if done["exports"] < step:
                        break
                print(
                    f"translated {totals['exports']} exports into {totals['events']} events"
                )
            elif args.command == "tenant" and args.tenant_command == "report-readiness":
                from openaidr.platform.readiness_reporter import report_once

                try:
                    result = report_once(cfg, st, args.platform_origin, args.release_manifest, args.release_id)
                except Exception:
                    print("error: tenant readiness reporting unavailable", file=sys.stderr)
                    return 1
                print(json.dumps(result))
                return 1 if result["not_ready"] else 0
            elif args.command == "tenant" and args.tenant_command == "user":
                password = sys.stdin.read().rstrip("\r\n")
                hashed = hash_password(password)
                st.migrate()
                try:
                    user = st.create_tenant_owner(
                        cfg.tenant_id, args.email, args.name, hashed
                    )
                except Conflict:
                    raise ValueError(
                        "a user with this email already exists; no credentials were changed"
                    ) from None
                output = {key: user[key] for key in ("id", "email", "name", "role")}
                output["tenant_id"] = cfg.tenant_id
                print(
                    json.dumps(output)
                    if args.json
                    else f"created tenant owner {user['email']} ({user['id']})"
                )
            elif args.command == "tenant":
                st.migrate()
                result = st.bootstrap_tenant(
                    args.name, args.slug, cfg.tenant_id, args.label, args.max_uses
                )
                output = dict(
                    tenant_id=result["tenant"]["id"],
                    name=result["tenant"]["name"],
                    slug=result["tenant"]["slug"],
                    enrollment_token=result["enrollment_token"],
                    enrollment_token_id=result["enrollment_token_id"],
                    server_url=cfg.public_url,
                    otlp_endpoint=cfg.public_url.rstrip("/") + "/otlp",
                )
                if args.json:
                    print(json.dumps(output))
                else:
                    print(f"tenant: {output['tenant_id']} ({output['slug']})")
                    print(f"server: {output['server_url']}")
                    print(f"enrollment token: {output['enrollment_token']}")
                    print(
                        "Set OPENAIDR_TENANT_ID to this tenant id before serving the dedicated backend."
                    )
            elif args.command == "admin":
                from openaidr.platform.cli import admin

                admin(args, cfg, st)
            else:
                import uvicorn

                if cfg.auto_migrate:
                    st.migrate()
                uvicorn.run(
                    application(cfg, st),
                    timeout_keep_alive=120,
                    # Application logs use paths only; OAuth query strings contain credentials.
                    access_log=False,
                    **listener,
                )
        finally:
            st.close()
    except (
        ValueError,
        RuntimeError,
        OSError,
        psycopg.Error,
        Conflict,
        NotFound,
    ) as exc:
        print("error:", exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
