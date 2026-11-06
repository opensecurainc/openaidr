"""Shared Guardrail settings reads and bounded database transactions."""

from contextlib import contextmanager
import time
import os

from psycopg.conninfo import conninfo_to_dict, make_conninfo

DB_STATEMENT_TIMEOUT_MS = 5_000
DB_LOCK_TIMEOUT_MS = 3_000


def get_settings(st, tenant_id, conn=None):
    rows = st.many(
        "SELECT version,enabled,ask_threshold,block_threshold,timeout_ms,updated_at,"
        "approvals_enabled,approval_wait_seconds,approval_use_seconds,"
        "context_enabled,context_required,context_failure_action "
        "FROM tenant_guardrail_settings WHERE tenant_id=$1",
        tenant_id,
        conn=conn,
    )
    return (
        rows[0]
        if rows
        else {
            "version": 0,
            "enabled": False,
            "ask_threshold": None,
            "block_threshold": None,
            "timeout_ms": None,
            "approvals_enabled": False,
            "approval_wait_seconds": None,
            "approval_use_seconds": None,
            "context_enabled": False,
            "context_required": False,
            "context_failure_action": "ask",
            "updated_at": None,
        }
    )


@contextmanager
def _bounded_transaction(st, deadline, *, wait_for_capacity=False):
    """Bound pool waits and each SQL statement without abandoning a thread."""
    def remaining_ms():
        remaining = int((deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise TimeoutError("inline database deadline")
        return remaining

    with st.pools["data"].connection(timeout=(remaining_ms() / 1000 if wait_for_capacity else min(0.005, remaining_ms() / 1000))) as connection:
        with connection.transaction():
            class DeadlineConnection:
                def transaction(self):
                    return connection.transaction()

                def execute(self, query, params=None):
                    remaining = remaining_ms()
                    lock_timeout = remaining if wait_for_capacity else min(25, remaining)
                    connection.execute(f"SET LOCAL statement_timeout={remaining}; SET LOCAL lock_timeout={lock_timeout}")
                    return connection.execute(query, params)

            yield DeadlineConnection()


def risk_store(original, *, db_pool_size=1):
    from ..store import Store

    options = conninfo_to_dict(original.url).get("options", os.environ.get("PGOPTIONS", ""))
    return Store(make_conninfo(
        original.url,
        connect_timeout=5,
        keepalives=1, keepalives_idle=5, keepalives_interval=2, keepalives_count=2,
        tcp_user_timeout=10_000,
        options=(options + f" -c statement_timeout={DB_STATEMENT_TIMEOUT_MS}"
                 + f" -c lock_timeout={DB_LOCK_TIMEOUT_MS}"),
    ), db_pool_size=db_pool_size, auth_pool_size=1, query_sources=original.query_sources)
