#!/usr/bin/env python3
"""Create the local workspace for compose.yaml: one tenant and its owner account.

Runs inside the server image before the server starts. The first run creates
the tenant and records its id where the server reads OPENAIDR_TENANT_ID_FILE.
Later runs reuse that tenant and leave existing users and passwords unchanged.
"""

import argparse
import os
from pathlib import Path
import sys


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--email", required=True, help="owner account email")
    parser.add_argument("--name", default="Administrator", help="owner display name")
    parser.add_argument("--tenant-name", default=os.environ.get("OPENAIDR_TENANT_NAME") or "Local workspace")
    parser.add_argument("--tenant-slug", default="local")
    parser.add_argument("--tenant-file", type=Path,
                        default=Path(os.environ.get("OPENAIDR_LOCAL_TENANT_FILE") or "/run/openaidr-tenant/tenant_id"),
                        help="where the tenant id is recorded for the server")
    args = parser.parse_args(argv)
    password = os.environ.get("OPENAIDR_ADMIN_PASSWORD", "")
    if len(password) < 12:
        print("error: OPENAIDR_ADMIN_PASSWORD must be at least 12 characters", file=sys.stderr)
        return 1

    from openaidr.server.auth import hash_password
    from openaidr.server.config import from_env
    from openaidr.server.service_enrollment import prepare
    from openaidr.server.store import Conflict, Store

    cfg = from_env()
    cfg.set_services("ingest")
    enrollment = prepare(cfg)
    if enrollment is not None:
        cfg.tenant_id = enrollment.connection.tenant_id
    cfg.validate(allow_unbound=True, customer=True)
    store = Store(cfg.database_url, db_pool_size=cfg.db_pool_size,
                  auth_pool_size=cfg.auth_pool_size, db_pool_timeout=cfg.db_pool_timeout)
    try:
        store.migrate()
        tenant_id = args.tenant_file.read_text().strip() if args.tenant_file.is_file() else ""
        if tenant_id and cfg.tenant_id and tenant_id != cfg.tenant_id:
            raise ValueError("Configured Intelligence identity does not match the existing local workspace")
        if tenant_id:
            print(f"tenant {tenant_id} already bound")
        else:
            result = store.bootstrap_tenant(args.tenant_name, args.tenant_slug, cfg.tenant_id, "local", 0)
            tenant_id = result["tenant"]["id"]
            args.tenant_file.parent.mkdir(parents=True, exist_ok=True)
            staged = args.tenant_file.with_name(args.tenant_file.name + ".tmp")
            staged.write_text(tenant_id + "\n")
            os.replace(staged, args.tenant_file)
            print(f"tenant {tenant_id} created")
        try:
            user = store.create_tenant_owner(tenant_id, args.email, args.name, hash_password(password))
            print(f"created owner {user['email']}")
        except Conflict:
            print(f"owner {args.email} already exists; credentials unchanged")
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
