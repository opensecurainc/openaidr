"""PostgreSQL persistence. Tenant scope is explicit on every tenant operation."""

from __future__ import annotations
import base64
from collections import Counter
import hashlib
import json
import logging
import math
import re
import secrets
import time
import uuid
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool, PoolTimeout, TooManyRequests
from openaidr.core.event import validate_evidence
from . import _sql as sql
from .config import PLATFORM_AVAILABLE
from .model import finish, SEVERITIES
from .permissions import LEGACY_ROLES, normalize_roles
from .telemetry_events import translate_export
from .query_sources import QuerySources, SourceCursor
from .config import PLATFORM_AVAILABLE

if PLATFORM_AVAILABLE:
    from openaidr.platform.storage import PlatformStore
else:
    PlatformStore = object

if PLATFORM_AVAILABLE:
    from openaidr.platform.storage import PlatformStore
else:
    PlatformStore = object

log = logging.getLogger(__name__)


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


class Busy(Exception):
    pass


class TokenRevoked(Exception):
    pass


class TokenExpired(Exception):
    pass


class TokenExhausted(Exception):
    pass


PREFIX_ENROLLMENT = "oaet_"
PREFIX_SENSOR = "oast_"
PREFIX_INVITE = "oaiv_"
PREFIX_SESSION = "oass_"
SESSION_TTL = timedelta(days=30)


def now():
    return datetime.now(timezone.utc)


# The built-in credential-read rule's original glob. Policy globs have no
# brace groups, so it never matched. Migration 0037, a reconciliation at every
# startup, every save, and every read split a built-in copy into one rule per
# directory.
LEGACY_CREDENTIAL_GLOB = "**/.{aws,ssh,kube}/*"
CREDENTIAL_DIRECTORIES = ("aws", "ssh", "kube")
CREDENTIAL_GLOBS = tuple(f"**/.{d}/**" for d in CREDENTIAL_DIRECTORIES)
CREDENTIAL_SPLIT = Path(__file__).with_name("migrations") / "0037_split_credential_read_rule.sql"
STRICT_ACTIONS = ("deny", "ask")


def _builtin_glob(rule, globs):
    match = rule.get("match") if isinstance(rule, dict) else None
    return (
        isinstance(match, dict)
        and rule.get("source") == "builtin"
        and match.get("path_glob") in globs
    )


def legacy_credential_rules(rules):
    """How many built-in copies of the legacy credential-read rule a list has."""
    return sum(1 for r in rules if _builtin_glob(r, (LEGACY_CREDENTIAL_GLOB,)))


def split_credential_rule(rules):
    """Rules with each built-in copy of the legacy credential-read rule
    replaced by one rule per directory. The copies' ids derive from the
    original's (``<id>-aws`` and so on), as migration 0037 derives them; an
    id another rule already has, or one without an original id, is replaced
    by a new one so every id still names one rule.

    Policies use the first matching rule, and the legacy rule never matched,
    so built-in credential rules set to warn or allow go last: they must not
    come before a rule that did, such as a tenant's own deny or ask for the
    same files, including one appended later. Those set to deny or ask keep
    their place, so a later allow cannot overtake them."""
    out, fallback, copied = [], [], []
    for rule in rules:
        if not _builtin_glob(rule, (LEGACY_CREDENTIAL_GLOB,)):
            lenient = (
                _builtin_glob(rule, CREDENTIAL_GLOBS)
                and rule.get("action") not in STRICT_ACTIONS
            )
            (fallback if lenient else out).append(rule)
            continue
        base = rule.get("id")
        copies = [
            dict(
                rule,
                id=f"{base}-{directory}" if base else None,
                name=f"{rule.get('name', '')} (.{directory})",
                match=dict(rule["match"], path_glob=f"**/.{directory}/**"),
            )
            for directory in CREDENTIAL_DIRECTORIES
        ]
        (out if rule.get("action") in STRICT_ACTIONS else fallback).extend(copies)
        copied.extend(copies)
    counts = Counter(r.get("id") for r in out + fallback)
    for copy in copied:
        if not copy["id"] or counts[copy["id"]] > 1:
            copy["id"] = new_id()
    return out + fallback


def new_id():
    # UUIDv7: millisecond timestamp followed by cryptographically random bits.
    value = (
        (int(time.time() * 1000) << 80)
        | (7 << 76)
        | (secrets.randbits(12) << 64)
        | (2 << 62)
        | secrets.randbits(62)
    )
    return str(uuid.UUID(int=value))


def hash_token(plain):
    return hashlib.sha256(plain.encode()).hexdigest()


def new_token(prefix):
    plain = prefix + secrets.token_urlsafe(32)
    return plain, hash_token(plain)


def valid_uuid(value):
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, TypeError, AttributeError):
        return False


def valid_slug(value):
    return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?", value))


def timestamp(value):
    return (
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        if isinstance(value, str)
        else value
    )


@dataclass
class Cursor:
    time: datetime | None = None
    id: str = ""

    def encode(self):
        if not self.id:
            return ""
        return (
            base64.urlsafe_b64encode(
                (self.time.isoformat().replace("+00:00", "Z") + "|" + self.id).encode()
            )
            .decode()
            .rstrip("=")
        )


def decode_cursor(value):
    if not value:
        return Cursor()
    try:
        t, id = (
            base64.b64decode(
                value + "=" * ((-len(value)) % 4), altchars=b"-_", validate=True
            )
            .decode()
            .split("|", 1)
        )
        t = timestamp(t)
        if not valid_uuid(id) or t.tzinfo is None:
            raise ValueError()
        return Cursor(t, id)
    except Exception as exc:
        raise ValueError("invalid cursor") from exc


@dataclass
class LiveCursor:
    """A live feed position plus the transactions still in progress when it was read."""

    position: Cursor
    pending: tuple = ()

    def encode(self):
        tail = ",".join(str(int(x)) for x in self.pending)
        return (
            self.position.encode()
            + "."
            + base64.urlsafe_b64encode(tail.encode()).decode().rstrip("=")
        )


MAX_PENDING = 1000


def decode_live_cursor(value):
    """Decode a live cursor; a plain event cursor has nothing pending."""
    head, _, tail = (value or "").partition(".")
    position = decode_cursor(head)
    if not position.id:
        raise ValueError("invalid cursor")
    if not tail:
        return LiveCursor(position)
    try:
        text = base64.b64decode(
            tail + "=" * ((-len(tail)) % 4), altchars=b"-_", validate=True
        ).decode()
        pending = tuple(int(x) for x in text.split(",")) if text else ()
    except Exception as exc:
        raise ValueError("invalid cursor") from exc
    if len(pending) > MAX_PENDING or any(x <= 0 for x in pending):
        raise ValueError("invalid cursor")
    return LiveCursor(position, pending)


@dataclass
class Page:
    limit: int = 50
    cursor: Cursor | str | None = None

    def norm(self):
        return Page(
            min(self.limit, 500) if self.limit > 0 else 50,
            decode_cursor(self.cursor)
            if isinstance(self.cursor, str)
            else self.cursor or Cursor(),
        )


def page_of(page):
    return (Page(**page) if isinstance(page, dict) else page or Page()).norm()


def bound(cursor, asc=False):
    return (
        (cursor.time, cursor.id)
        if cursor and cursor.id
        else (
            datetime(1 if asc else 9999, 1, 1, tzinfo=timezone.utc),
            "00000000-0000-0000-0000-000000000000"
            if asc
            else "ffffffff-ffff-ffff-ffff-ffffffffffff",
        )
    )


def clean(value):
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v) for v in value]
    return value


class Store(PlatformStore):
    def __init__(self, url, *, db_pool_size=16, auth_pool_size=4, db_pool_timeout=5, query_sources=None):
        self.url = url
        self.query_sources = query_sources if query_sources is not None else QuerySources()
        self.pools = {}
        # Policy versions found free of the legacy credential rule, by tenant.
        self.clean_policy_versions = {}
        if not math.isfinite(db_pool_timeout) or db_pool_timeout <= 0:
            raise ValueError("db_pool_timeout must be finite and positive")
        for size in (db_pool_size, auth_pool_size):
            if type(size) is not int or size <= 0:
                raise ValueError("database pool sizes must be positive integers")
        try:
            for name, size in (("data", db_pool_size), ("auth", auth_pool_size)):
                pool = ConnectionPool(
                    url,
                    kwargs={
                        "row_factory": dict_row,
                        "cursor_factory": partial(SourceCursor, collector=self.query_sources),
                        "connect_timeout": math.ceil(db_pool_timeout),
                    },
                    name=name,
                    min_size=1,
                    max_size=size,
                    timeout=db_pool_timeout,
                    max_waiting=64,
                    open=False,
                )
                self.pools[name] = pool
                pool.open(wait=True, timeout=db_pool_timeout)
        except BaseException:
            self.close()
            raise

    @classmethod
    def open(cls, url):
        return cls(url)

    def close(self):
        for pool in self.pools.values():
            pool.close()

    @contextmanager
    def transaction(self, *, auth=False):
        try:
            with self.pools["auth" if auth else "data"].connection() as connection:
                yield connection
        except (PoolTimeout, TooManyRequests) as exc:
            raise Busy("database connection capacity exhausted") from exc
        except psycopg.errors.UniqueViolation as exc:
            raise Conflict("conflict") from exc

    def _run(self, query, args=(), mode="many", conn=None, auth=False):
        # Numbered placeholders allow faithful reuse of the existing SQL.
        params = []

        def replace(match):
            params.append(args[int(match[1]) - 1])
            return "%s"

        query = re.sub(r"\$(\d+)", replace, query.replace("%", "%%"))
        if conn is None:
            with self.transaction(auth=auth) as connection:
                return self._execute(connection, query, params, mode)
        return self._execute(conn, query, params, mode)

    def _execute(self, conn, query, args, mode):
        cur = conn.execute(query, args)
        if mode == "exec":
            return cur.rowcount
        if mode == "many":
            return clean(cur.fetchall())
        row = cur.fetchone()
        if row is None:
            raise NotFound("not found")
        return clean(next(iter(row.values())) if mode == "scalar" else row)

    def one(self, q, *args, conn=None, auth=False):
        return self._run(q, args, "one", conn, auth)

    def many(self, q, *args, conn=None, auth=False):
        return self._run(q, args, "many", conn, auth)

    def execute(self, q, *args, conn=None, auth=False):
        return self._run(q, args, "exec", conn, auth)

    def scalar(self, q, *args, conn=None, auth=False):
        return self._run(q, args, "scalar", conn, auth)

    def ping(self):
        start = time.monotonic()
        self.scalar("SELECT 1")
        return time.monotonic() - start

    def database_health(self, tenant):
        pools = []
        for name, pool in self.pools.items():
            stats = pool.get_stats()
            pools.append(dict(
                name=name,
                size=stats["pool_size"],
                available=stats["pool_available"],
                maximum=stats["pool_max"],
                waiting=stats["requests_waiting"],
            ))
        result = dict(ok=False, latency_ms=None, pools=[], activity=None)
        start = time.monotonic()
        try:
            # A full data pool must not hide its own overload. Borrow the
            # reserved pool briefly; never scan application tables here.
            pool = self.pools["auth"]
            with pool.connection(timeout=min(1, pool.timeout)) as conn:
                conn.execute("SET TRANSACTION READ ONLY")
                conn.execute("SET LOCAL statement_timeout = '1s'")
                shared = self.scalar(
                    "SELECT EXISTS (SELECT 1 FROM tenants WHERE id<>$1)", tenant, conn=conn
                )
                if shared:
                    return dict(status="disabled", message="Database diagnostics require a database dedicated to one tenant.")
                result["pools"] = pools
                activity = self.one(
                    """SELECT
                    count(*) FILTER (WHERE state='active') AS active_queries,
                    count(*) FILTER (WHERE state='active'
                        AND query_start < statement_timestamp() - interval '30 seconds')
                        AS long_running_queries,
                    count(*) FILTER (WHERE state='active' AND wait_event_type='Lock')
                        AS lock_waits,
                    count(*) FILTER (WHERE state IN
                        ('idle in transaction','idle in transaction (aborted)'))
                        AS idle_transactions,
                    COALESCE(max(GREATEST(0, extract(epoch FROM
                        statement_timestamp()-query_start))) FILTER (WHERE state='active'),0)::float8
                        AS oldest_query_seconds,
                    COALESCE(max(GREATEST(0, extract(epoch FROM
                        statement_timestamp()-xact_start))),0)::float8
                        AS oldest_transaction_seconds,
                    count(*) FILTER (WHERE state IS NULL OR state='disabled')
                        AS untracked_sessions
                    FROM pg_catalog.pg_stat_activity
                    WHERE datname=current_database() AND usename=current_user
                        AND backend_type='client backend' AND pid<>pg_backend_pid()""",
                    conn=conn,
                )
            result.update(
                ok=True,
                latency_ms=round((time.monotonic() - start) * 1000),
                activity=activity,
            )
        except psycopg.Error:
            # Pool statistics remain useful when the database check fails.
            pass
        result["checked_at"] = now().isoformat()
        return result

    def migrate(self):
        applied = []
        with self.transaction() as conn:
            # Keep other migrators out while releasing each file's DDL locks.
            conn.execute("SELECT pg_advisory_lock(684021559)")
            conn.commit()
            try:
                with conn.transaction():
                    conn.execute(
                        "CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())"
                    )
                    versions = {
                        row["version"]
                        for row in conn.execute("SELECT version FROM schema_migrations")
                    }
                for path in sorted(Path(__file__).with_name("migrations").glob("*.sql")):
                    version = int(path.name.split("_")[0])
                    if version in versions:
                        continue
                    with conn.transaction():
                        conn.execute(path.read_text())
                        self.execute(
                            "INSERT INTO schema_migrations(version,name) VALUES($1,$2)",
                            version,
                            path.name,
                            conn=conn,
                        )
                    applied.append(path.name)
                    versions.add(version)
                # A server rolled back past migration 0037 can write the
                # legacy credential rule again; split it on every start so a
                # re-upgrade fixes it without waiting for a policy save.
                with conn.transaction():
                    self._split_stored_credential_rules(conn)
            finally:
                conn.execute("SELECT pg_advisory_unlock(684021559)")
                conn.commit()
        return applied

    def _required(self, n):
        if n == 0:
            raise NotFound("not found")

    def _page(
        self, columns, source, conditions, args, page, time_col, kind=None, asc=False
    ):
        page = page_of(page)
        t, id = bound(page.cursor, asc)
        args = list(args)
        args.extend((t, id, page.limit + 1))
        n = len(args)
        idcol = time_col.rsplit(".", 1)[0] + ".id" if "." in time_col else "id"
        conditions = list(conditions) + [
            f"({time_col}, {idcol}) {'>' if asc else '<'} (${n - 2}, ${n - 1}::uuid)"
        ]
        direction = "" if asc else "DESC"
        rows = self.many(
            f"SELECT {columns} FROM {source} WHERE "
            + " AND ".join(conditions)
            + f" ORDER BY {time_col} {direction}, {idcol} {direction} LIMIT ${n}",
            *args,
        )
        more = len(rows) > page.limit
        rows = rows[: page.limit]
        cursor = (
            Cursor(rows[-1][time_col.split(".")[-1]], rows[-1]["id"]).encode()
            if more
            else ""
        )
        return ([finish(r, kind) for r in rows] if kind else rows), cursor

    def create_tenant(self, name, slug, plan="", default_rules=None):
        id = new_id()
        with self.transaction() as conn:
            self.execute(
                "INSERT INTO tenants(id,name,slug,plan) VALUES($1,$2,$3,$4)",
                id,
                name,
                slug.lower(),
                plan or "trial",
                conn=conn,
            )
            self.execute(
                "INSERT INTO policies(tenant_id,version,rules) VALUES($1,1,$2)",
                id,
                Jsonb(default_rules or []),
                conn=conn,
            )
        return self.get_tenant(id)

    def bootstrap_cloud_tenant(
        self, tenant_id, name, slug, owner_email, owner_name, approved_domains, bootstrap_id
    ):
        from openaidr.platform.cloud_identity import bootstrap_cloud_tenant

        return bootstrap_cloud_tenant(
            self, tenant_id, name, slug, owner_email, owner_name,
            approved_domains, bootstrap_id,
        )

    def get_tenant(self, id):
        return self.one(
            "SELECT " + sql.tenantColumns + " FROM tenants t WHERE t.id=$1", id
        )

    def get_tenant_brief(self, id):
        return self.one(
            "SELECT id,name,slug,status,plan,created_at FROM tenants WHERE id=$1",
            id,
            auth=True,
        )

    def list_tenants(self, q="", status="", page=None):
        return self._page(
            sql.tenantColumns,
            "tenants t",
            [
                "($1='' OR t.name ILIKE '%'||$1||'%' OR t.slug ILIKE '%'||$1||'%')",
                "($2='' OR t.status=$2)",
            ],
            [q, status],
            page,
            "t.created_at",
        )

    def update_tenant(self, id, name="", plan="", status=""):
        self._required(
            self.execute(
                "UPDATE tenants SET name=CASE WHEN $2<>'' THEN $2 ELSE name END, plan=CASE WHEN $3<>'' THEN $3 ELSE plan END, status=CASE WHEN $4<>'' THEN $4 ELSE status END,updated_at=now() WHERE id=$1",
                id,
                name,
                plan,
                status,
            )
        )
        return self.get_tenant(id)

    def active_tenant_ids(self):
        return [
            r["id"]
            for r in self.many(
                "SELECT id FROM tenants WHERE status='active' ORDER BY created_at"
            )
        ]

    def create_user(self, tenant_id, email, name, password_hash, role):
        id = new_id()
        roles = normalize_roles(LEGACY_ROLES.get(role, []) if isinstance(role, str) else role)
        self.execute(
            "INSERT INTO tenant_users(id,tenant_id,email,name,password_hash,roles) VALUES($1,$2,$3,$4,$5,$6)",
            id,
            tenant_id,
            email.strip().lower(),
            name,
            password_hash,
            roles,
        )
        return self.get_user(tenant_id, id)

    def get_user(self, tenant_id, id, *, conn=None):
        return self.one(
            "SELECT "
            + sql.userColumns
            + " FROM tenant_users WHERE tenant_id=$1 AND id=$2",
            tenant_id,
            id,
            conn=conn,
            auth=True,
        )

    def get_user_by_email(self, email):
        return self.one(
            "SELECT "
            + sql.userColumns
            + " FROM tenant_users WHERE lower(email)=lower($1)",
            email.strip(),
            auth=True,
        )

    def list_users(self, tenant_id):
        return self.many(
            "SELECT "
            + sql.userColumns
            + " FROM tenant_users WHERE tenant_id=$1 ORDER BY created_at,id",
            tenant_id,
        )

    def update_user(self, tenant_id, id, role="", status="", *, roles=None, conn=None):
        if roles is not None or role:
            roles = normalize_roles(roles if roles is not None else LEGACY_ROLES.get(role, []))
        self._required(
            self.execute(
                "UPDATE tenant_users SET roles=COALESCE($3::text[],roles),"
                "status=CASE WHEN $4<>'' THEN $4 ELSE status END WHERE tenant_id=$1 AND id=$2",
                tenant_id, id, roles, status, conn=conn,
            )
        )
        return self.get_user(tenant_id, id, conn=conn)

    def delete_user(self, tenant_id, id, *, conn=None):
        with nullcontext(conn) if conn is not None else self.transaction() as conn:
            user = self.one(
                "SELECT email,oidc_issuer,oidc_subject FROM tenant_users WHERE tenant_id=$1 AND id=$2",
                tenant_id,
                id,
                conn=conn,
            )
            if user["oidc_issuer"]:
                self.lock_identity(tenant_id, user["oidc_issuer"], user["oidc_subject"], conn)
            self.lock_membership(tenant_id, user["email"], conn)
            user = self.one(
                "DELETE FROM tenant_users WHERE tenant_id=$1 AND id=$2 AND email=$3 "
                "AND oidc_issuer IS NOT DISTINCT FROM $4 AND oidc_subject IS NOT DISTINCT FROM $5 "
                "RETURNING email,oidc_issuer,oidc_subject",
                tenant_id, id, user["email"], user["oidc_issuer"], user["oidc_subject"], conn=conn,
            )
            if user["oidc_issuer"]:
                # Capture the cutoff after DELETE's row-lock wait, never at transaction start.
                self.execute(
                    "INSERT INTO tenant_identity_revocations(tenant_id,issuer,subject,removed_at) "
                    "VALUES($1,$2,$3,clock_timestamp()) ON CONFLICT(tenant_id,issuer,subject) "
                    "DO UPDATE SET removed_at=GREATEST(tenant_identity_revocations.removed_at,EXCLUDED.removed_at)",
                    tenant_id, user["oidc_issuer"], user["oidc_subject"], conn=conn,
                )
            self.clear_pending_invites(tenant_id, user["email"], conn)

    def lock_identity(self, tenant_id, issuer, subject, conn):
        # Subject precedes email and row locks, including after a Google email rename.
        self.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            "tenant-identity:" + tenant_id + ":" + issuer + ":" + subject,
            conn=conn,
        )

    def lock_membership(self, tenant_id, email, conn):
        # Take this before invitation, proof, or user row locks.
        self.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            "tenant-membership:" + tenant_id + ":" + email.strip().lower(),
            conn=conn,
        )

    def clear_pending_invites(self, tenant_id, email, conn):
        self.execute(
            "DELETE FROM invites WHERE tenant_id=$1 AND lower(email)=lower($2) AND accepted_at IS NULL",
            tenant_id, email, conn=conn,
        )
        self.execute(
            "DELETE FROM oidc_pending_memberships WHERE tenant_id=$1 AND email=lower($2)",
            tenant_id, email, conn=conn,
        )

    def active_user_counts(self, tenant_id, *, conn=None):
        return self.one(
            "SELECT count(*) AS users,count(*) FILTER (WHERE 'it_admin'=ANY(roles)) AS it_admins "
            "FROM tenant_users WHERE tenant_id=$1 AND status='active'",
            tenant_id,
            conn=conn,
        )

    def touch_login(self, id):
        self.execute(
            "UPDATE tenant_users SET last_login_at=now() WHERE id=$1", id, auth=True
        )

    def create_invite(
        self,
        tenant_id,
        email,
        role,
        created_by_type="",
        created_by_id="",
        ttl=timedelta(days=7),
        *,
        require_absent=False,
    ):
        email = email.strip().lower()
        roles = normalize_roles(LEGACY_ROLES.get(role, []) if isinstance(role, str) else role)
        plain, hashed = new_token(PREFIX_INVITE)
        id = new_id()
        if isinstance(ttl, (int, float)):
            ttl = timedelta(seconds=ttl)
        with self.transaction() as conn:
            self.lock_membership(tenant_id, email, conn)
            if require_absent and self.scalar(
                "SELECT EXISTS(SELECT 1 FROM tenant_users WHERE lower(email)=lower($1))",
                email, conn=conn,
            ):
                raise Conflict("a user with this email already exists")
            self.execute(
                "INSERT INTO invites(id,tenant_id,token_hash,email,roles,expires_at,created_by_type,created_by_id,created_at) "
                "VALUES($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp())",
                id,
                tenant_id,
                hashed,
                email,
                roles,
                now() + ttl,
                created_by_type,
                created_by_id,
                conn=conn,
            )
            return {**self.one(
                "SELECT " + sql.inviteColumns + " FROM invites WHERE id=$1", id, conn=conn,
            ), "token": plain}

    def get_invite_by_token(self, token):
        return self.one(
            "SELECT " + sql.inviteColumns + " FROM invites WHERE token_hash=$1",
            hash_token(token),
            auth=True,
        )

    def list_invites(self, tenant_id):
        return self.many(
            "SELECT "
            + sql.inviteColumns
            + " FROM invites WHERE tenant_id=$1 AND accepted_at IS NULL ORDER BY created_at DESC,id",
            tenant_id,
        )

    def delete_invite(self, tenant_id, id):
        with self.transaction() as conn:
            invite = self.one(
                "SELECT email FROM invites WHERE tenant_id=$1 AND id=$2",
                tenant_id, id, conn=conn,
            )
            self.lock_membership(tenant_id, invite["email"], conn)
            self._required(self.execute(
                "DELETE FROM invites WHERE tenant_id=$1 AND id=$2", tenant_id, id, conn=conn,
            ))

    def accept_invite(self, invite, name, password_hash):
        id = new_id()
        with self.transaction(auth=True) as conn:
            self.lock_membership(invite["tenant_id"], invite["email"], conn)
            self.one("SELECT id FROM invites WHERE id=$1 FOR UPDATE", invite["id"], conn=conn)
            inv = self.one(
                "UPDATE invites SET accepted_at=clock_timestamp() WHERE id=$1 AND accepted_at IS NULL "
                "AND expires_at>clock_timestamp() RETURNING tenant_id,email,roles",
                invite["id"],
                conn=conn,
            )
            self.execute(
                "INSERT INTO tenant_users(id,tenant_id,email,name,password_hash,roles) VALUES($1,$2,$3,$4,$5,$6)",
                id,
                inv["tenant_id"],
                inv["email"],
                name,
                password_hash,
                inv["roles"],
                conn=conn,
            )
            self.clear_pending_invites(inv["tenant_id"], inv["email"], conn)
            # Roll back membership as well if subsequent writes outlasted the grant.
            self.one(
                "SELECT id FROM invites WHERE id=$1 AND expires_at>clock_timestamp()",
                invite["id"], conn=conn,
            )
        return self.get_user(inv["tenant_id"], id)

    def create_session(self, user_id, tenant_id):
        plain, hashed = new_token(PREFIX_SESSION)
        self.execute(
            "INSERT INTO auth_sessions(id,token_hash,user_id,tenant_id,expires_at) VALUES($1,$2,$3,$4,$5)",
            new_id(),
            hashed,
            user_id,
            tenant_id,
            now() + SESSION_TTL,
            auth=True,
        )
        return plain

    def _session(self, table, token):
        row = self.one(
            f"SELECT * FROM {table} WHERE token_hash=$1 AND expires_at>now()",
            hash_token(token),
            auth=True,
        )
        if not row.get("oidc_issuer") and now() - row["last_seen_at"] > timedelta(hours=1):
            self.execute(
                f"UPDATE {table} SET last_seen_at=now(),expires_at=$2 WHERE id=$1",
                row["id"],
                now() + SESSION_TTL,
                auth=True,
            )
        return row

    def get_session(self, token):
        row = self._session("auth_sessions", token)
        return {
            "session_id": row["id"],
            "oidc_issuer": row.get("oidc_issuer"),
            "verified_at": row.get("verified_at"),
            "user": self.get_user(row["tenant_id"], row["user_id"]),
            "tenant": self.get_tenant_brief(row["tenant_id"]),
        }

    def delete_session(self, token):
        self.execute(
            "DELETE FROM auth_sessions WHERE token_hash=$1",
            hash_token(token),
            auth=True,
        )

    def create_enrollment_token(self, tenant_id, label="", expires_in=0, max_uses=0):
        if isinstance(expires_in, (int, float)):
            expires_in = timedelta(seconds=expires_in)
        plain, hashed = new_token(PREFIX_ENROLLMENT)
        id = new_id()
        self.execute(
            "INSERT INTO enrollment_tokens(id,tenant_id,token_hash,label,expires_at,max_uses) VALUES($1,$2,$3,$4,$5,$6)",
            id,
            tenant_id,
            hashed,
            label,
            now() + expires_in if expires_in > timedelta(0) else None,
            max(0, max_uses),
        )
        return {
            **self.one(
                "SELECT "
                + sql.enrollmentColumns
                + " FROM enrollment_tokens WHERE id=$1",
                id,
            ),
            "token": plain,
        }

    def list_enrollment_tokens(self, tenant_id):
        return self.many(
            "SELECT "
            + sql.enrollmentColumns
            + " FROM enrollment_tokens WHERE tenant_id=$1 ORDER BY created_at DESC,id",
            tenant_id,
        )

    def revoke_enrollment_token(self, tenant_id, id):
        self._required(
            self.execute(
                "UPDATE enrollment_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE tenant_id=$1 AND id=$2",
                tenant_id,
                id,
            )
        )

    def enroll_sensor(self, req, tenant_id=""):
        from . import device_identity

        device = device_identity.validate(req)
        plain, hashed = new_token(PREFIX_SENSOR)
        id = new_id()
        with self.transaction() as conn:
            tok = self.one(
                "SELECT * FROM enrollment_tokens WHERE token_hash=$1 FOR UPDATE",
                hash_token(req["enrollment_token"]),
                conn=conn,
            )
            if tenant_id and tok["tenant_id"] != tenant_id:
                raise NotFound("invalid enrollment token")
            if tok["revoked_at"]:
                raise TokenRevoked("enrollment token revoked")
            if tok["expires_at"] and tok["expires_at"] < now():
                raise TokenExpired("enrollment token expired")
            if tok["max_uses"] > 0 and tok["uses"] >= tok["max_uses"]:
                raise TokenExhausted("enrollment token has no uses left")
            tenant = self.one(
                "SELECT id,name,slug,status,plan,created_at FROM tenants WHERE id=$1",
                tok["tenant_id"],
                conn=conn,
            )
            if tenant["status"] != "active":
                raise TokenRevoked("enrollment token revoked")
            self.execute(
                """INSERT INTO sensors(id,tenant_id,token_hash,label,hostname,os,arch,username,host_kind,
                       serial_number,hardware_uuid,machine_id,device_id_source)
                   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)""",
                id,
                tenant["id"],
                hashed,
                req.get("label", ""),
                req.get("hostname", ""),
                req.get("os", ""),
                req.get("arch", ""),
                req.get("user", ""),
                req.get("host_kind") or "workstation",
                *device_identity.values(device),
                conn=conn,
            )
            self.execute(
                "INSERT INTO sensor_activity(sensor_id,version,last_heartbeat_at) VALUES($1,$2,now())",
                id,
                req.get("sensor_version", ""),
                conn=conn,
            )
            self.execute(
                "UPDATE enrollment_tokens SET uses=uses+1 WHERE id=$1",
                tok["id"],
                conn=conn,
            )
        return self.get_sensor(tenant["id"], id), plain, tenant

    def preview_enrollment(self, plain, tenant_id=""):
        """Read an expiring invitation with uses remaining without consuming it."""
        row = self.one(
            "SELECT e.expires_at,e.uses,e.max_uses,e.revoked_at,"
            "t.id,t.name,t.status FROM enrollment_tokens e "
            "JOIN tenants t ON t.id=e.tenant_id WHERE e.token_hash=$1",
            hash_token(plain),
        )
        if tenant_id and row["id"] != tenant_id:
            raise NotFound("invalid enrollment link")
        if row["revoked_at"] or row["status"] != "active":
            raise TokenRevoked("enrollment link revoked")
        if not row["expires_at"] or row["expires_at"] <= now():
            raise TokenExpired("enrollment link expired")
        if row["max_uses"] <= 0 or row["uses"] >= row["max_uses"]:
            raise TokenExhausted("enrollment link must have unused enrollments within a finite limit")
        return {"tenant": {k: row[k] for k in ("id", "name")}, "expires_at": row["expires_at"]}

    def get_sensor(self, tenant_id, id):
        row = finish(
            self.one(
                "SELECT "
                + sql.sensorColumns
                + " FROM "
                + sql.sensorFrom
                + " WHERE s.tenant_id=$1 AND s.id=$2 AND s.deleted_at IS NULL",
                tenant_id,
                id,
            ),
            "sensor",
        )
        row["same_hardware"] = self.same_hardware(tenant_id, id).get(str(row["id"]), [])
        return row

    def get_sensor_by_token(self, token):
        # Authentication reads only stable identity and credential state.
        return self.one(
            "SELECT "
            + sql.sensorIdentityColumns
            + " FROM sensors WHERE token_hash=$1 AND deleted_at IS NULL",
            hash_token(token),
            auth=True,
        )

    def get_sensor_identity(self, tenant_id, id, *, conn=None):
        return self.one(
            "SELECT "
            + sql.sensorIdentityColumns
            + " FROM sensors WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL",
            tenant_id,
            id,
            conn=conn,
            auth=True,
        )

    def list_all_sensors(self, tenant_id):
        matches = self.same_hardware(tenant_id)
        rows = [
            finish(r, "sensor")
            for r in self.many(
                "SELECT "
                + sql.sensorColumns
                + """, (SELECT max(r.memory_rss_bytes) FROM sensor_resource_samples r
                        WHERE r.sensor_id=s.id
                          AND r.sampled_at >= now()-interval '24 hours'
                          AND r.sampled_at <= now()) AS max_memory_rss_bytes_24h"""
                + " FROM "
                + sql.sensorFrom
                + " WHERE s.tenant_id=$1 AND s.deleted_at IS NULL ORDER BY s.enrolled_at DESC,s.id DESC",
                tenant_id,
            )
        ]
        for row in rows:
            row["same_hardware"] = matches.get(str(row["id"]), [])
        return rows

    def same_hardware(self, tenant_id, sensor_id=None):
        """Other live enrollments reporting the same serial number or hardware
        UUID, keyed by sensor id. A reinstalled or re-enrolled machine keeps its
        earlier sensor rows until an admin removes them; this lets the dashboard
        show that they are one device. Empty identifiers never match."""
        from .model import sensor_status

        rows = self.many(
            """SELECT s.id, m.id AS match_id, m.label, m.hostname, m.enrolled_at, m.disabled, a.last_heartbeat_at
               FROM sensors s
               JOIN sensors m ON m.tenant_id=s.tenant_id AND m.id<>s.id AND m.deleted_at IS NULL
                 AND ((s.serial_number<>'' AND m.serial_number=s.serial_number)
                   OR (s.hardware_uuid<>'' AND m.hardware_uuid=s.hardware_uuid))
               JOIN sensor_activity a ON a.sensor_id=m.id
               WHERE s.tenant_id=$1 AND s.deleted_at IS NULL AND ($2::uuid IS NULL OR s.id=$2)
               ORDER BY m.enrolled_at DESC, m.id""",
            tenant_id,
            sensor_id,
        )
        result = {}
        for row in rows:
            result.setdefault(str(row["id"]), []).append({
                "id": row["match_id"],
                "label": row["label"],
                "hostname": row["hostname"],
                "enrolled_at": row["enrolled_at"],
                "status": sensor_status(row),
            })
        return result

    def list_sensors(self, tenant_id, f=None, page=None):
        f = f or {}
        conditions = ["tenant_id=$1", "deleted_at IS NULL"]
        args = [tenant_id]
        if f.get("host_kind"):
            args.append(f["host_kind"])
            conditions.append(f"host_kind=${len(args)}")
        if f.get("q"):
            args.append("%" + f["q"] + "%")
            n = len(args)
            conditions.append(
                f"(label ILIKE ${n} OR hostname ILIKE ${n} OR username ILIKE ${n})"
            )
        if f.get("status") == "disabled":
            conditions.append("disabled")
        if f.get("status") == "online":
            conditions.append(
                "NOT disabled AND last_heartbeat_at>now()-interval '90 seconds'"
            )
        if f.get("status") == "offline":
            conditions.append(
                "NOT disabled AND (last_heartbeat_at IS NULL OR last_heartbeat_at<=now()-interval '90 seconds')"
            )
        return self._page(
            sql.sensorColumns,
            sql.sensorFrom,
            conditions,
            args,
            page,
            "s.enrolled_at",
            "sensor",
        )

    def update_sensor(self, tenant_id, id, label=None, host_kind=None, disabled=None):
        self._required(
            self.execute(
                "UPDATE sensors SET label=COALESCE($3,label),host_kind=COALESCE($4,host_kind),disabled=COALESCE($5,disabled) WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL",
                tenant_id,
                id,
                label,
                host_kind,
                disabled,
            )
        )
        return self.get_sensor(tenant_id, id)

    def delete_sensor(self, tenant_id, id):
        self._required(
            self.execute(
                "UPDATE sensors SET deleted_at=now(),token_hash=NULL WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL",
                tenant_id,
                id,
            )
        )

    def record_heartbeat(self, sensor_id, hb):
        from . import device_identity, signed_in_user
        from .sensor_health import validate_report

        device = device_identity.validate(hb)
        report = validate_report(hb.get("health_report"))
        login = signed_in_user.parse(hb.get("signed_in_user"))
        self.execute(
            """WITH heartbeat AS (
                UPDATE sensor_activity SET last_heartbeat_at=now(),
                    version=CASE WHEN $2<>'' THEN $2 ELSE version END,
                    uptime_s=$3,collectors=$4,queue_depth=$5,policy_version=$6,
                    hook_installed=$7,telemetry_queue_depth=$8,
                    cpu_percent=$9,memory_rss_bytes=$10,
                    policy_delivery=$12,policy_delivery_reported_at=now(),
                    health_report=$13,health_reported_at=CASE WHEN $13::jsonb IS NOT NULL THEN now() END,
                    latest_signed_in_user=CASE WHEN $15::timestamptz IS NOT NULL AND
                        (latest_signed_in_at IS NULL OR $15>latest_signed_in_at)
                        THEN $14 ELSE latest_signed_in_user END,
                    latest_signed_in_at=CASE WHEN $15::timestamptz IS NOT NULL AND
                        (latest_signed_in_at IS NULL OR $15>latest_signed_in_at)
                        THEN $15 ELSE latest_signed_in_at END
                WHERE sensor_id=$1
                RETURNING sensor_id,last_heartbeat_at,cpu_percent,memory_rss_bytes
            )
            INSERT INTO sensor_resource_samples(sensor_id,sampled_at,cpu_percent,memory_rss_bytes)
            SELECT sensor_id,date_trunc('minute',last_heartbeat_at),cpu_percent,memory_rss_bytes
            FROM heartbeat WHERE $11
            ON CONFLICT(sensor_id,sampled_at) DO UPDATE
                SET cpu_percent=EXCLUDED.cpu_percent,memory_rss_bytes=EXCLUDED.memory_rss_bytes""",
            sensor_id,
            hb.get("sensor_version", ""),
            hb.get("uptime_s", 0),
            Jsonb(hb.get("collectors") or []),
            hb.get("queue_depth", 0),
            hb.get("policy_version", 0),
            hb.get("hook_installed", False),
            hb.get("telemetry_queue_depth"),
            hb.get("cpu_percent"),
            hb.get("memory_rss_bytes"),
            "cpu_percent" in hb or "memory_rss_bytes" in hb,
            "backend" if hb.get("policy_delivery") == "backend" else None,
            Jsonb(report) if report is not None else None,
            login[0] if login else "",
            login[1] if login else None,
        )
        if device is not None:
            # Reported identifiers only ever fill in or replace a value. An
            # empty field keeps the stored value, so a collection failure on
            # one heartbeat does not erase a serial recorded earlier.
            self.execute(
                """UPDATE sensors SET
                    serial_number=CASE WHEN $2<>'' THEN $2 ELSE serial_number END,
                    hardware_uuid=CASE WHEN $3<>'' THEN $3 ELSE hardware_uuid END,
                    machine_id=CASE WHEN $4<>'' THEN $4 ELSE machine_id END,
                    device_id_source=CASE WHEN $5<>'' THEN $5 ELSE device_id_source END
                   WHERE id=$1""",
                sensor_id,
                *device_identity.values(device),
            )

    def queue_command(self, tenant_id, sensor_id, typ, params=None, action_id=""):
        self.get_sensor(tenant_id, sensor_id)
        id = new_id()
        self.execute(
            "INSERT INTO sensor_commands(id,tenant_id,sensor_id,type,params,action_id) VALUES($1,$2,$3,$4,$5,$6)",
            id,
            tenant_id,
            sensor_id,
            typ,
            Jsonb(params or {}),
            action_id or None,
        )
        return id

    def list_commands(self, tenant_id, sensor_id, limit=50):
        """Recent commands for one sensor, newest first, with their outcomes."""
        self.get_sensor(tenant_id, sensor_id)
        return self.many(
            "SELECT id,type,params,status,message,created_at,delivered_at,acked_at FROM sensor_commands"
            " WHERE tenant_id=$1 AND sensor_id=$2 ORDER BY created_at DESC, id DESC LIMIT $3",
            tenant_id,
            sensor_id,
            limit,
        )

    def get_command(self, tenant_id, sensor_id, command_id):
        row = self.one(
            "SELECT id,type,params,status,message,created_at,delivered_at,acked_at FROM sensor_commands"
            " WHERE tenant_id=$1 AND sensor_id=$2 AND id=$3",
            tenant_id,
            sensor_id,
            command_id,
        )
        if row is None:
            raise NotFound("command")
        return row

    def pending_commands(self, sensor_id):
        # Delivered in queue order: the sensor applies them sequentially, and
        # opposite hook commands queued before one heartbeat must not swap.
        return self.many(
            "WITH delivered AS (UPDATE sensor_commands SET status='delivered',delivered_at=COALESCE(delivered_at,now())"
            " WHERE sensor_id=$1 AND status IN ('pending','delivered') RETURNING id,type,params,created_at)"
            " SELECT id,type,params,created_at FROM delivered ORDER BY created_at, id",
            sensor_id,
        )

    def ack_command(self, sensor_id, command_id, ack):
        status = "failed" if ack.get("status") == "failed" else "applied"
        with self.transaction() as conn:
            aid = self.scalar(
                "UPDATE sensor_commands SET status=$3,acked_at=now(),message=$4 WHERE id=$1 AND sensor_id=$2 RETURNING action_id",
                command_id,
                sensor_id,
                status,
                ack.get("message", ""),
                conn=conn,
            )
            if aid:
                self.execute(
                    "UPDATE response_actions SET status=$2,applied_at=CASE WHEN $2='applied' THEN now() ELSE applied_at END,message=$3 WHERE id=$1",
                    aid,
                    status,
                    ack.get("message", ""),
                    conn=conn,
                )

    def ingest_batch(self, sensor, events, conn=None):
        """Persist normalized events, upserting inventory rows and counters.

        Runs inside ``conn`` when given so callers can make the events atomic
        with other writes; otherwise it opens its own transaction.
        """
        if conn is None:
            with self.transaction() as connection:
                return self.ingest_batch(sensor, events, connection)
        from .session_ownership import (
            RegistrationRejected, lock_sensor_sessions, validate_event_registration,
        )

        self.execute("SELECT ensure_telemetry_partitions($1)", sensor["tenant_id"], conn=conn)
        lock_sensor_sessions(self, sensor, conn)
        result = {"accepted": 0, "duplicates": 0}
        for index, event in enumerate(events):
            aid = sid = None
            e = event
            agent = e.get("agent") or {}
            host = e.get("host") or {}
            session = e.get("session") or {}
            t = timestamp(e["time"])
            # Lock the ID to keep retries from creating phantom inventory or counts.
            self.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                e["id"],
                conn=conn,
            )
            if self.scalar(
                "SELECT EXISTS(SELECT 1 FROM event_keys WHERE id=$1)",
                e["id"],
                conn=conn,
            ):
                result["duplicates"] += 1
                continue
            session_evidence = "evidence" in e and not validate_evidence(e["evidence"])
            registration = None
            if session.get("id"):
                try:
                    if session.get("registration_id") and e["kind"] == "sensor" and not session_evidence:
                        raise RegistrationRejected("registered sensor events require evidence metadata")
                    registration = validate_event_registration(self, sensor, e, conn)
                except RegistrationRejected as exc:
                    result.setdefault("rejected", []).append(
                        {"index": index, "id": e["id"], "reason": str(exc)}
                    )
                    continue
            if session.get("id") and (e["kind"] != "sensor" or session_evidence):
                native_activity = e["kind"] != "sensor"
                aid = self.scalar(
                    """INSERT INTO agents(id,tenant_id,sensor_id,product,version,hostname,os,arch,username,models,first_seen,last_seen)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)
                ON CONFLICT(tenant_id,sensor_id,product,username) DO UPDATE SET
                version=CASE WHEN EXCLUDED.version<>'' THEN EXCLUDED.version ELSE agents.version END,
                hostname=CASE WHEN EXCLUDED.hostname<>'' THEN EXCLUDED.hostname ELSE agents.hostname END,
                os=CASE WHEN EXCLUDED.os<>'' THEN EXCLUDED.os ELSE agents.os END,
                arch=CASE WHEN EXCLUDED.arch<>'' THEN EXCLUDED.arch ELSE agents.arch END,
                models=COALESCE((SELECT array_agg(DISTINCT m ORDER BY m) FROM unnest(agents.models||EXCLUDED.models) AS m),'{}') RETURNING id""",
                    new_id(),
                    sensor["tenant_id"],
                    sensor["id"],
                    agent.get("product", ""),
                    agent.get("version", ""),
                    host.get("hostname") or sensor["hostname"],
                    host.get("os") or sensor["os"],
                    host.get("arch") or sensor["arch"],
                    registration["agent_username"]
                    if registration and registration["session_id"] else host.get("user", ""),
                    [agent["model"]] if agent.get("model") else [],
                    t,
                    conn=conn,
                )
                # Gap-only rows use provisional timestamps until native activity arrives.
                # Later gap metadata must not reopen or extend native session activity.
                sr = self.one(
                    """INSERT INTO agent_sessions(id,tenant_id,agent_id,sensor_id,external_id,product,cwd,git_branch,started_at,last_event_at,registration_id)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$11) ON CONFLICT(tenant_id,agent_id,external_id) DO UPDATE SET
                cwd=CASE WHEN EXCLUDED.cwd<>'' THEN EXCLUDED.cwd ELSE agent_sessions.cwd END,
                git_branch=CASE WHEN EXCLUDED.git_branch<>'' THEN EXCLUDED.git_branch ELSE agent_sessions.git_branch END,
                started_at=CASE WHEN NOT $10 THEN agent_sessions.started_at WHEN agent_sessions.has_native_activity THEN LEAST(agent_sessions.started_at,EXCLUDED.started_at) ELSE EXCLUDED.started_at END,
                last_event_at=CASE WHEN NOT $10 THEN agent_sessions.last_event_at WHEN agent_sessions.has_native_activity THEN GREATEST(agent_sessions.last_event_at,EXCLUDED.last_event_at) ELSE EXCLUDED.last_event_at END
                RETURNING id,(xmax=0) AS inserted""",
                    new_id(),
                    sensor["tenant_id"],
                    aid,
                    sensor["id"],
                    session["id"],
                    agent.get("product", ""),
                    session.get("cwd", ""),
                    session.get("git_branch", ""),
                    t,
                    native_activity,
                    registration["id"] if registration else None,
                    conn=conn,
                )
                sid = sr["id"]
                from .agent_projects import observe

                observe(conn, sensor["tenant_id"], sensor["id"], agent.get("product"),
                        session, "event:" + str(e["id"]), t)
                self.execute(
                    """UPDATE agents SET events_total=events_total+1,sessions_total=sessions_total+$2,
                    first_seen=CASE WHEN NOT $3 THEN first_seen WHEN has_native_activity THEN LEAST(first_seen,$4) ELSE $4 END,
                    last_seen=CASE WHEN NOT $3 THEN last_seen WHEN has_native_activity THEN GREATEST(last_seen,$4) ELSE $4 END
                    WHERE id=$1""",
                    aid,
                    int(sr["inserted"]),
                    native_activity,
                    t,
                    conn=conn,
                )
                self.execute(
                    """UPDATE agent_sessions SET events_total=events_total+1,tool_calls=tool_calls+$2,commands=commands+$3,
                ended_at=CASE WHEN $4::timestamptz IS NOT NULL THEN $4 WHEN ended_at IS NOT NULL AND $5>ended_at THEN NULL ELSE ended_at END WHERE id=$1""",
                    sid,
                    int(
                        e["kind"]
                        in (
                            "command",
                            "tool.call",
                            "file.read",
                            "file.write",
                            "network",
                        )
                    ),
                    int(e["kind"] == "command"),
                    t if e["kind"] == "session.end" else None,
                    t if native_activity else None,
                    conn=conn,
                )
            export = e.get("export") if isinstance(e.get("export"), dict) else {}
            export_id = export.get("id") if valid_uuid(export.get("id")) else None
            from .hook_policy import captured_assessment

            hook_risk = captured_assessment(self, sensor, e, conn)
            self.execute(
                """INSERT INTO events(id,tenant_id,sensor_id,agent_id,session_id,time,observed_at,kind,product,command_text,file_path,network_host,tool_name,body,export_id,export_record,risk)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)""",
                e["id"],
                sensor["tenant_id"],
                sensor["id"],
                aid,
                sid,
                t,
                timestamp(e.get("observed_at")) if e.get("observed_at") else None,
                e["kind"],
                agent.get("product", ""),
                (e.get("command") or {}).get("text") or None,
                (e.get("file") or {}).get("path") or None,
                (e.get("network") or {}).get("host") or None,
                (e.get("tool") or {}).get("name") or None,
                Jsonb(e),
                export_id,
                export.get("record")
                if export_id and isinstance(export.get("record"), int)
                else None,
                Jsonb(hook_risk) if hook_risk else None,
                conn=conn,
            )
            if hook_risk:
                self.record_risk_detection({
                    "id": e["id"], "tenant_id": sensor["tenant_id"], "sensor_id": sensor["id"],
                    "agent_id": aid, "session_id": sid, "kind": e["kind"],
                    "product": agent.get("product", ""), "time": t, "body": e,
                }, hook_risk, conn)
            result["accepted"] += 1
        self.execute(
            "UPDATE sensor_activity SET events_total=events_total+$2,agents_total=(SELECT count(*) FROM agents WHERE sensor_id=$1) WHERE sensor_id=$1",
            sensor["id"],
            result["accepted"],
            conn=conn,
        )
        return result

    def _filters(self, tenant_id, f, fields, prefix="", time_col="time"):
        conditions = [prefix + "tenant_id=$1"]
        args = [tenant_id]
        for key in fields:
            if (f or {}).get(key):
                args.append(f[key])
                conditions.append(f"{prefix}{key}=${len(args)}")
        for key, op in (("since", ">="), ("until", "<=")):
            if (f or {}).get(key):
                args.append(timestamp(f[key]))
                conditions.append(f"{prefix}{time_col}{op}${len(args)}")
        return conditions, args

    @staticmethod
    def _source_condition(f, where):
        """`source=otlp` selects events derived from stored exports; `collector` the rest."""
        source = (f or {}).get("source")
        if source == "otlp":
            where.append("export_id IS NOT NULL")
        elif source == "collector":
            where.append("export_id IS NULL")
        elif source:
            raise ValueError("source must be otlp or collector")

    def list_events(self, tenant_id, f=None, page=None):
        where, args = self._filters(
            tenant_id, f, ("kind", "agent_id", "sensor_id", "session_id")
        )
        self._source_condition(f, where)
        for key, field in (("username", "user"), ("hostname", "hostname")):
            if (f or {}).get(key):
                args.append(f[key])
                where.append(f"strpos(lower(body #>> '{{host,{field}}}'), lower(${len(args)})) > 0")
        if (f or {}).get("session"):
            args.append(f["session"])
            n = len(args)
            where.append(f"(strpos(body #>> '{{session,id}}', ${n}) > 0 OR strpos(session_id::text, ${n}) > 0)")
        if (f or {}).get("before"):
            args.append(timestamp(f["before"]))
            where.append(f"time < ${len(args)}")
        if (f or {}).get("q"):
            args.append("%" + f["q"] + "%")
            n = len(args)
            where.append(
                f"(command_text ILIKE ${n} OR file_path ILIKE ${n} OR network_host ILIKE ${n} OR tool_name ILIKE ${n})"
            )
        return self._page(sql.eventColumns, "events", where, args, page, "time")

    def list_session_events(self, tenant_id, session_id, kind="", page=None):
        return self._page(
            sql.eventColumns,
            "events",
            ["tenant_id=$1", "session_id=$2", "($3='' OR kind=$3)"],
            [tenant_id, session_id, kind],
            page,
            "time",
            asc=True,
        )

    def get_event(self, tenant_id, id):
        return self.one(
            "SELECT " + sql.eventColumns + " FROM events WHERE tenant_id=$1 AND id=$2",
            tenant_id,
            id,
        )

    def list_session_evidence(self, tenant_id, session_id, limit=50, cursor="", *, owner_user_id=None):
        from .session_evidence import read_page

        return read_page(self, tenant_id, session_id, limit, cursor, owner_user_id=owner_user_id)

    def get_events(self, tenant_id, ids):
        return self.many(
            "SELECT "
            + sql.eventColumns
            + " FROM events WHERE tenant_id=$1 AND id=ANY($2::uuid[]) ORDER BY time,id",
            tenant_id,
            ids,
        )

    def event_risks(self, tenant_id, ids):
        return self.many(
            "SELECT id,risk FROM events WHERE tenant_id=$1 AND id=ANY($2::uuid[])",
            tenant_id, ids,
        )

    def expire_risk_events(self, tenant_id=None, *, retry_legacy=False):
        from .guardrail.inline import KINDS

        # Validate event references before casting, keeping the hook UUID indexes
        # usable. Lock only a bounded batch so concurrent cleanup can make progress.
        self.execute(
            """UPDATE events e SET risk=COALESCE((
                   SELECT CASE WHEN c.status='evaluated' AND c.assessment->>'status'='scored' THEN c.assessment
                       ELSE jsonb_build_object('status','error','reason',
                           CASE WHEN c.status='pending' THEN 'timeout' ELSE c.failure_reason END) END
                       ||jsonb_build_object('hook_check_id',c.id)
                   FROM ordinary_hook_checks c WHERE c.tenant_id=e.tenant_id AND c.sensor_id=e.sensor_id
                     AND (c.request_id=CASE WHEN e.body->'source'->>'hook_request_id'
                              ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
                              THEN (e.body->'source'->>'hook_request_id')::uuid END
                          OR c.id=CASE WHEN e.risk->>'hook_check_id'
                              ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
                              THEN (e.risk->>'hook_check_id')::uuid END) LIMIT 1),
                   '{"status":"error","reason":"backend_unavailable"}'::jsonb)
               WHERE ($1::uuid IS NULL OR e.tenant_id=$1) AND e.id=ANY(ARRAY(
                   SELECT id FROM events WHERE ($1::uuid IS NULL OR tenant_id=$1)
                     AND risk->>'status'='pending'
                     AND (body->'source'->>'hook_request_id' IS NOT NULL OR risk ? 'hook_check_id')
                     AND received_at<statement_timestamp()-interval '2 seconds'
                   LIMIT 100 FOR UPDATE SKIP LOCKED
               ))""", tenant_id,
        )
        # Oversized bodies never enter the scoring queue or dispatch model calls.
        # Drain their metadata in bounded batches, including without Jev enabled.
        self.execute(
            """UPDATE events e SET risk=CASE WHEN t.status='active' AND e.kind=ANY($2)
                   AND e.received_at>=now()-interval '24 hours'
                   THEN '{"status":"unscored","category":"unknown",
                       "score":null,"level":null,"reason":"evidence_too_large"}'::jsonb
                   ELSE e.risk END,
                   risk_next_attempt_at='infinity'::timestamptz
               FROM tenants t WHERE t.id=e.tenant_id AND e.id IN (
                   SELECT id FROM events WHERE ($1::uuid IS NULL OR tenant_id=$1)
                   AND risk_body_omitted AND risk IS NULL
                   AND risk_next_attempt_at<'infinity'::timestamptz
                   AND NOT EXISTS (SELECT 1 FROM agent_sessions s
                       JOIN session_registrations r ON r.id=s.registration_id AND r.tenant_id=s.tenant_id
                       WHERE s.id=events.session_id AND s.tenant_id=events.tenant_id
                         AND r.assessment_mode='inline')
                   LIMIT 100 FOR UPDATE SKIP LOCKED
               )""",
            tenant_id, list(KINDS),
        )
        # Retired background claims leave pending once their lease expires.
        # Hook-linked copies remain in the bounded reconciliation queue above.
        return self.execute(
            """UPDATE events SET risk=jsonb_build_object('status','error','reason',
                   CASE WHEN risk_retry_attempts>=3 THEN 'attempts_exhausted' ELSE 'assessment_expired' END),
                   risk_next_attempt_at='infinity'::timestamptz
               WHERE ($1::uuid IS NULL OR tenant_id=$1)
               AND body->'source'->>'hook_request_id' IS NULL
               AND NOT COALESCE(risk ? 'hook_check_id',false)
               AND (NOT $2::boolean OR risk_retry_attempts>=3 OR received_at<now()-interval '24 hours')
               AND NOT EXISTS (SELECT 1 FROM agent_sessions s
                   JOIN session_registrations r ON r.id=s.registration_id AND r.tenant_id=s.tenant_id
                   WHERE s.id=events.session_id AND s.tenant_id=events.tenant_id
                     AND r.assessment_mode='inline')
               AND risk->>'status'='pending' AND risk_next_attempt_at<=now()""",
            tenant_id, retry_legacy,
        )

    def claim_risk_event(self, tenant_id=None, *, require_tenant_key=False, excluded_tenants=()):
        from .guardrail.scoring import KINDS

        self.expire_risk_events(tenant_id, retry_legacy=True)
        with self.transaction() as conn:
            window = self.scalar(
                "SELECT to_timestamp(floor(extract(epoch FROM clock_timestamp())/3600)*3600)",
                conn=conn,
            )
            rows = self.many(
                """UPDATE events SET risk='{"status":"pending"}'::jsonb,
                       risk_attempts=risk_attempts+1, risk_retry_attempts=risk_retry_attempts+1,
                       risk_next_attempt_at=clock_timestamp()+interval '60 seconds'
                   WHERE id=(
                       SELECT e.id FROM events e JOIN tenants t ON t.id=e.tenant_id
                       LEFT JOIN risk_assessment_usage su ON su.tenant_id=e.tenant_id
                           AND su.sensor_id=e.sensor_id AND su.window_start=$3::timestamptz
                       LEFT JOIN (
                           SELECT tenant_id,sum(attempts) AS attempts FROM risk_assessment_usage
                           WHERE window_start=$3::timestamptz GROUP BY tenant_id
                       ) tu ON tu.tenant_id=e.tenant_id
                       WHERE ($1::uuid IS NULL OR e.tenant_id=$1) AND t.status='active'
                       AND (NOT $4::boolean OR EXISTS (
                           SELECT 1 FROM tenant_model_keys mk
                           WHERE mk.tenant_id=e.tenant_id AND mk.kind='guardrail'
                       ))
                       AND e.tenant_id <> ALL($5::uuid[])
                       AND NOT EXISTS (
                           SELECT 1 FROM risk_provider_backoff
                           WHERE provider='jev' AND retry_at>now()
                       )
                       AND e.kind=ANY($2) AND e.received_at>=now()-interval '24 hours'
                       AND e.body->'source'->>'hook_request_id' IS NULL
                       AND NOT COALESCE(e.risk ? 'hook_check_id',false)
                       AND NOT EXISTS (SELECT 1 FROM agent_sessions s
                           JOIN session_registrations r ON r.id=s.registration_id AND r.tenant_id=s.tenant_id
                           WHERE s.id=e.session_id AND s.tenant_id=e.tenant_id
                             AND r.assessment_mode='inline')
                       AND NOT e.risk_body_omitted
                       AND e.risk_retry_attempts<3
                       AND e.risk_next_attempt_at<=now()
                       AND (e.risk IS NULL OR e.risk->>'status' IN ('pending','error'))
                       ORDER BY COALESCE(tu.attempts,0),COALESCE(su.attempts,0),e.received_at,e.id
                       FOR UPDATE OF e SKIP LOCKED LIMIT 1
                   ) RETURNING """ + sql.riskEventColumns + ",risk_attempts,risk_retry_attempts",
                tenant_id, list(KINDS), window, require_tenant_key, list(excluded_tenants), conn=conn,
            )
            if not rows:
                return None
            row = rows[0]
            self.execute(
                """INSERT INTO risk_assessment_usage(tenant_id,sensor_id,window_start,attempts)
                   VALUES($1,$2,$3::timestamptz,1)
                   ON CONFLICT(tenant_id,sensor_id) DO UPDATE SET
                       window_start=EXCLUDED.window_start,
                       attempts=CASE WHEN risk_assessment_usage.window_start=EXCLUDED.window_start
                           THEN risk_assessment_usage.attempts+1 ELSE 1 END""",
                row["tenant_id"], row["sensor_id"], window, conn=conn,
            )
            return row

    def risk_context(self, row):
        if not row.get("session_id"):
            return [], None
        args = (row["tenant_id"], row["session_id"], row["time"], row["id"])
        where = "tenant_id=$1 AND session_id=$2 AND (time,id)<($3,$4::uuid)"
        context = self.many(
            "SELECT " + sql.riskEventColumns + " FROM events WHERE " + where
            + " AND kind IN ('prompt','response','command','tool.call','tool.result','file.read','file.write','network','hook.decision')"
            # Sensors record every policy check; one no rule matched says
            # nothing about the session and would crowd out real context.
            + " AND NOT (kind='hook.decision' AND COALESCE(body->'source'->>'collector','')='hook'"
            + " AND body->'hook'->>'decision'='allow'"
            + " AND COALESCE(body->'hook'->>'rule_id','')='')"
            + " ORDER BY time DESC,id DESC LIMIT 12", *args,
        )
        prompts = self.many(
            "SELECT " + sql.riskEventColumns + " FROM events WHERE " + where
            + " AND kind='prompt' ORDER BY time DESC,id DESC LIMIT 1", *args,
        )
        return list(reversed(context)), prompts[0] if prompts else None

    def risk_knowledge(self, row):
        from .knowledge_retrieval import retrieve
        from .guardrail.evidence import event_evidence

        return retrieve(self, row["tenant_id"], event_evidence(row))

    def start_model_call(
        self, row, model, *, purpose="detection", provider="typesafe",
        guardrail_check_id=None, conn=None,
    ):
        from .model_costs import PRICE_DATE, RATES

        rates = RATES.get((provider, model), (None, None))
        calls = self.many(
            """INSERT INTO model_usage
                (id,tenant_id,sensor_id,event_id,attempt,purpose,provider,model,
                 input_rate_usd,output_rate_usd,price_date,guardrail_check_id)
               VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
               ON CONFLICT (tenant_id,purpose,event_id,attempt) DO NOTHING
               RETURNING id""",
            new_id(), row["tenant_id"], row["sensor_id"], row["id"], row["risk_attempts"],
            purpose, provider, model, *rates, PRICE_DATE if rates[0] is not None else None,
            guardrail_check_id, conn=conn,
        )
        return calls[0]["id"] if calls else None

    def finish_model_call(self, tenant_id, call_id, usage, *, failed=False, conn=None):
        usage = usage or {}
        # Billing belongs to the provider attempt, even if its event lease expired.
        # Finalizing the same attempt twice must not overwrite its first result.
        # Keep the requested model identity. An unexpected response model cannot
        # change which provider attempt occurred or be priced using its quote.
        return self.execute(
            """UPDATE model_usage SET completed_at=clock_timestamp(), status=$6,
                   input_tokens=$4, output_tokens=$5,
                   cost_usd=CASE WHEN model=$3 AND $4::bigint IS NOT NULL AND $5::bigint IS NOT NULL
                       THEN ($4::numeric*input_rate_usd+$5::numeric*output_rate_usd)/1000000 END,
                   input_rate_usd=CASE WHEN model=$3 THEN input_rate_usd END,
                   output_rate_usd=CASE WHEN model=$3 THEN output_rate_usd END,
                   price_date=CASE WHEN model=$3 THEN price_date END
               WHERE tenant_id=$1 AND id=$2 AND completed_at IS NULL""",
            tenant_id, call_id, usage.get("model"), usage.get("input_tokens"),
            usage.get("output_tokens"), "error" if failed else "completed",
            conn=conn,
        )

    def finish_risk_event(self, row, result, retry=False, provider_delay=0):
        delay = 30 * row["risk_retry_attempts"] if retry is True else retry
        with self.transaction() as conn:
            updated = self.execute(
                """UPDATE events SET risk=$4,
                       risk_retry_attempts=CASE WHEN $6 THEN GREATEST(0,risk_retry_attempts-1) ELSE risk_retry_attempts END,
                       risk_next_attempt_at=CASE WHEN $5>0 THEN now()+interval '1 second' * $5 ELSE 'infinity'::timestamptz END
                   WHERE tenant_id=$1 AND id=$2 AND risk_attempts=$3 AND risk->>'status'='pending'
                   AND NOT EXISTS (SELECT 1 FROM agent_sessions s
                       JOIN session_registrations r ON r.id=s.registration_id AND r.tenant_id=s.tenant_id
                       WHERE s.id=events.session_id AND s.tenant_id=events.tenant_id
                         AND r.assessment_mode='inline')""",
                row["tenant_id"], row["id"], row["risk_attempts"], Jsonb(result), float(delay),
                result.get("reason") == "authentication_failed",
                conn=conn,
            )
            if updated and provider_delay > 0:
                self.execute(
                    """INSERT INTO risk_provider_backoff(provider,retry_at)
                       VALUES('jev',now()+interval '1 second' * $1)
                       ON CONFLICT(provider) DO UPDATE
                       SET retry_at=GREATEST(risk_provider_backoff.retry_at,EXCLUDED.retry_at)""",
                    float(provider_delay), conn=conn,
                )
            if updated:
                self.record_risk_detection(row, result, conn)
            return updated

    def record_risk_detection(self, row, result, conn=None):
        """Persist model and link findings with their assessed evidence event."""
        from .guardrail.findings import detection_finding
        from .malicious_links import detection_finding as link_finding

        findings = [finding for finding in (detection_finding(row, result), link_finding(row, result))
                    if finding is not None]
        if not findings:
            return False
        disabled = self.disabled_rules(row["tenant_id"], conn=conn)
        inserted = False
        for finding in findings:
            if not disabled.get(finding["rule_id"]):
                inserted = self.insert_finding(finding, conn=conn) or inserted
        return inserted

    def events_after(self, tenant_id, after, limit=500):
        if isinstance(after, str):
            after = decode_cursor(after)
        if isinstance(after, dict):
            after = Cursor(after.get("time"), after.get("id", ""))
        t, id = bound(after, True)
        return self.many(
            "SELECT "
            + sql.eventColumns
            + " FROM events WHERE tenant_id=$1 AND (received_at,id)>($2,$3::uuid) ORDER BY received_at,id LIMIT $4",
            tenant_id,
            t,
            id,
            limit,
        )

    def live_events(self, tenant_id, after=None, f=None, limit=100):
        """Events in arrival order for live views.

        Without a cursor the newest `limit` events are returned newest first.
        With a cursor, events that arrived after its position are returned
        oldest first, and `more` says whether further arrivals are already
        waiting beyond `limit`. Arrival order is `received_at`, not the
        agent's own event time.

        `received_at` is stamped at insert, so a transaction can commit after
        a later-stamped one, and a position alone would skip its rows. Each
        read therefore runs in one snapshot that also lists the transactions
        still in progress; the cursor carries that list, and the next read
        first returns every row those transactions inserted up to the
        position (`events.txid`, the top-level transaction, also for rows
        written under a savepoint). Rows are returned once: a pending
        transaction's rows were invisible when the list was taken.
        """
        limit = max(1, min(int(limit or 100), 500))
        f = f or {}
        where, args = self._filters(
            tenant_id, f, ("kind", "product", "agent_id", "sensor_id", "session_id")
        )
        self._source_condition(f, where)
        if isinstance(after, str):
            after = decode_live_cursor(after)
        select = "SELECT " + sql.eventColumns + " FROM events WHERE " + " AND ".join(where)
        n = len(args)
        with self.transaction() as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            pending = tuple(
                self.scalar(
                    "SELECT COALESCE(array_agg(x::text::bigint ORDER BY x), '{}')"
                    " FROM pg_snapshot_xip(pg_current_snapshot()) x",
                    conn=conn,
                )
                or ()
            )[:MAX_PENDING]
            if not (after and after.position.id):
                rows = self.many(
                    select + f" ORDER BY received_at DESC,id DESC LIMIT ${n + 1}",
                    *args,
                    limit,
                    conn=conn,
                )
                if not rows:
                    return rows, "", False
                position = Cursor(rows[0]["received_at"], rows[0]["id"])
                return rows, LiveCursor(position, pending).encode(), False
            position = after.position
            late = (
                self.many(
                    select
                    + f" AND txid=ANY(${n + 1}::bigint[]) AND (received_at,id)<=(${n + 2},${n + 3}::uuid)"
                    + " ORDER BY received_at,id",
                    *args,
                    list(after.pending),
                    position.time,
                    position.id,
                    conn=conn,
                )
                if after.pending
                else []
            )
            rows = self.many(
                select
                + f" AND (received_at,id)>(${n + 1},${n + 2}::uuid)"
                + f" ORDER BY received_at,id LIMIT ${n + 3}",
                *args,
                position.time,
                position.id,
                limit + 1,
                conn=conn,
            )
        more = len(rows) > limit
        rows = rows[:limit]
        if rows:
            position = Cursor(rows[-1]["received_at"], rows[-1]["id"])
        return late + rows, LiveCursor(position, pending).encode(), more

    def list_agents(self, tenant_id, f=None, page=None):
        f = f or {}
        where, args = self._filters(tenant_id, f, ("product", "sensor_id"), "a.")
        if f.get("status") in ("active", "idle"):
            where.append(
                "a.last_seen "
                + (">" if f["status"] == "active" else "<=")
                + " now()-interval '24 hours'"
            )
        if f.get("q"):
            args.append("%" + f["q"] + "%")
            n = len(args)
            where.append(
                f"(a.hostname ILIKE ${n} OR a.username ILIKE ${n} OR a.product ILIKE ${n}"
                f" OR replace(lower(a.product), 'jev', 'guardrail') ILIKE ${n})"
            )
        return self._page(
            sql.agentColumns, "agents a", where, args, page, "a.last_seen", "agent"
        )

    def get_agent(self, tenant_id, id):
        return finish(
            self.one(
                "SELECT "
                + sql.agentColumns
                + " FROM agents a WHERE a.tenant_id=$1 AND a.id=$2",
                tenant_id,
                id,
            ),
            "agent",
        )

    def agents_for_sensor(self, tenant_id, sensor_id):
        return [
            finish(r, "agent")
            for r in self.many(
                "SELECT "
                + sql.agentColumns
                + " FROM agents a WHERE a.tenant_id=$1 AND a.sensor_id=$2 ORDER BY a.last_seen DESC,a.id DESC",
                tenant_id,
                sensor_id,
            )
        ]

    def list_agent_sessions(self, tenant_id, agent_id, page=None):
        return self._page(
            sql.sessionColumns,
            "agent_sessions s",
            ["s.tenant_id=$1", "s.agent_id=$2"],
            [tenant_id, agent_id],
            page,
            "s.last_event_at",
        )

    def get_session_row(self, tenant_id, id):
        return self.one(
            "SELECT "
            + sql.sessionColumns
            + " FROM agent_sessions s WHERE s.tenant_id=$1 AND s.id=$2",
            tenant_id,
            id,
        )

    def insert_finding(self, f, conn=None):
        host = f.get("host") or {}
        return (
            self.execute(
                """INSERT INTO findings(id,tenant_id,rule_id,category,severity,title,summary,agent_id,session_id,sensor_id,hostname,os,arch,username,product,event_ids,primary_event_id,first_event_at,account)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::uuid[],$17,$18,$19) ON CONFLICT DO NOTHING""",
                new_id(),
                f["tenant_id"],
                f["rule_id"],
                f["category"],
                f["severity"],
                f["title"],
                f.get("summary", ""),
                f.get("agent_id"),
                f.get("session_id"),
                f["sensor_id"],
                host.get("hostname", ""),
                host.get("os", ""),
                host.get("arch", ""),
                host.get("user", ""),
                f.get("product", ""),
                f.get("event_ids") or [],
                f["primary_event_id"],
                timestamp(f["first_event_at"]),
                f.get("account", ""),
                conn=conn,
            )
            > 0
        )

    def user_risk(self, tenant_id, group="username"):
        """Findings totals grouped by OS username, or by reported identity.

        ``group="username"`` keeps the original contract: one row per exact OS
        username, which older dashboards link by username alone.
        ``group="identity"`` keys rows by the agent's reported account, which
        identifies a person across devices; findings without an account fall back
        to the OS username scoped to the reporting sensor, so the same local name
        on two unrelated devices stays two rows.
        """
        if group not in ("username", "identity"):
            raise ValueError("group must be username or identity")
        counts = ", ".join(
            f"count(*) FILTER (WHERE status IN ('open','triaged') AND severity='{severity}') AS {severity}"
            for severity in SEVERITIES
        )
        order = ", ".join(f"{severity} DESC" for severity in SEVERITIES)
        if group == "identity":
            key = """CASE WHEN account <> '' THEN 'account' ELSE 'os_user' END AS kind,
                CASE WHEN account <> '' THEN account ELSE username END COLLATE "C" AS "user",
                CASE WHEN account <> '' THEN NULL ELSE sensor_id END AS sensor_id,
                count(*) AS total, {counts},
                COALESCE(array_agg(DISTINCT username COLLATE "C" ORDER BY username COLLATE "C")
                    FILTER (WHERE username <> ''), '{{}}') AS users,"""
            grouping = "GROUP BY 1, 2, 3 ORDER BY {order}, total DESC, 2, 3"
        else:
            key = 'username COLLATE "C" AS "user", count(*) AS total, {counts},'
            grouping = 'GROUP BY username COLLATE "C" ORDER BY {order}, total DESC, username COLLATE "C"'
        rows = self.many(
            f"""SELECT {key.format(counts=counts)}
                COALESCE(array_agg(DISTINCT account COLLATE "C" ORDER BY account COLLATE "C")
                    FILTER (WHERE account <> ''), '{{}}') AS accounts,
                COALESCE(array_agg(DISTINCT hostname COLLATE "C" ORDER BY hostname COLLATE "C")
                    FILTER (WHERE hostname <> ''), '{{}}') AS hosts
                FROM findings WHERE tenant_id=$1 {grouping.format(order=order)}
            """,
            tenant_id,
        )
        for row in rows:
            row["open"] = {severity: row.pop(severity) for severity in SEVERITIES}
            row["openTotal"] = sum(row["open"].values())
        return {"items": rows, "total_findings": sum(row["total"] for row in rows)}

    def list_findings(self, tenant_id, f=None, page=None):
        filters = dict(f or {})
        active = filters.get("status") == "active"
        if active:
            del filters["status"]
        where, args = self._filters(
            tenant_id,
            filters,
            (
                "status",
                "severity",
                "category",
                "agent_id",
                "sensor_id",
                "session_id",
                "assignee_id",
            ),
            "f.",
            "created_at",
        )
        if active:
            where.append("f.status IN ('open','triaged')")
        for key in ("username", "account"):
            if key in filters:
                args.append(filters[key])
                where.append(f"COALESCE(f.{key},'')=${len(args)}")
        source = filters.get("source")
        if source == "incident":
            where.append("f.investigation_job_id IS NOT NULL")
        elif source == "policy":
            where.append("f.investigation_job_id IS NULL")
        elif source:
            raise ValueError("source must be incident or policy")
        return self._page(
            sql.findingColumns,
            sql.findingFrom.strip()[5:],
            where,
            args,
            page,
            "f.created_at",
            "finding",
        )

    def get_finding(self, tenant_id, id, *, conn=None):
        return finish(
            self.one(
                "SELECT "
                + sql.findingColumns
                + sql.findingFrom
                + " WHERE f.tenant_id=$1 AND f.id=$2",
                tenant_id,
                id,
                conn=conn,
            ),
            "finding",
        )

    def update_finding(self, tenant_id, id, u, *, conn=None):
        if u.get("assignee_id"):
            self.get_user(tenant_id, u["assignee_id"], conn=conn)
        self._required(
            self.execute(
                """UPDATE findings SET status=COALESCE($3,status),assignee_id=CASE WHEN $5 THEN NULL WHEN $4::uuid IS NOT NULL THEN $4::uuid ELSE assignee_id END,resolution=COALESCE($6,resolution),updated_at=now() WHERE tenant_id=$1 AND id=$2""",
                tenant_id,
                id,
                u.get("status"),
                u.get("assignee_id") or None,
                u.get("assignee_id") == "",
                u.get("resolution"),
                conn=conn,
            )
        )
        return self.get_finding(tenant_id, id, conn=conn)

    def rule_finding_counts(self, tenant_id):
        return {
            r["rule_id"]: r["count"]
            for r in self.many(
                "SELECT rule_id,count(*) FROM findings WHERE tenant_id=$1 AND created_at>now()-interval '30 days' GROUP BY rule_id",
                tenant_id,
            )
        }

    def add_note(self, tenant_id, finding_id, author_id, body, *, conn=None):
        id = new_id()
        self._required(
            self.execute(
                "INSERT INTO finding_notes(id,tenant_id,finding_id,author_id,body) SELECT $1,$2,$3,$4,$5 WHERE EXISTS(SELECT 1 FROM findings WHERE tenant_id=$2 AND id=$3)",
                id,
                tenant_id,
                finding_id,
                author_id,
                body,
                conn=conn,
            )
        )
        return finish(
            self.one(
                "SELECT "
                + sql.noteColumns
                + " FROM finding_notes n LEFT JOIN tenant_users u ON u.id=n.author_id WHERE n.id=$1",
                id,
                conn=conn,
            ),
            "note",
        )

    def list_notes(self, tenant_id, finding_id):
        return [
            finish(r, "note")
            for r in self.many(
                "SELECT "
                + sql.noteColumns
                + " FROM finding_notes n LEFT JOIN tenant_users u ON u.id=n.author_id WHERE n.tenant_id=$1 AND n.finding_id=$2 ORDER BY n.created_at,n.id",
                tenant_id,
                finding_id,
            )
        ]

    def create_action(
        self, tenant_id, finding_id, typ, params, status, created_by, applied=False
    ):
        if finding_id:
            self.get_finding(tenant_id, finding_id)
        id = new_id()
        self.execute(
            "INSERT INTO response_actions(id,tenant_id,finding_id,type,params,status,created_by,applied_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            id,
            tenant_id,
            finding_id,
            typ,
            Jsonb(params or {}),
            status,
            created_by,
            now() if applied else None,
        )
        return self.get_action(tenant_id, id)

    def get_action(self, tenant_id, id):
        return finish(
            self.one(
                "SELECT "
                + sql.actionColumns
                + sql.actionFrom
                + " WHERE a.tenant_id=$1 AND a.id=$2",
                tenant_id,
                id,
            ),
            "action",
        )

    def list_actions(self, tenant_id, f=None, page=None):
        where, args = self._filters(
            tenant_id, f, ("finding_id", "type", "status"), "a."
        )
        return self._page(
            sql.actionColumns,
            sql.actionFrom.strip()[5:],
            where,
            args,
            page,
            "a.created_at",
            "action",
        )

    def actions_for_finding(self, tenant_id, finding_id):
        return [
            finish(r, "action")
            for r in self.many(
                "SELECT "
                + sql.actionColumns
                + sql.actionFrom
                + " WHERE a.tenant_id=$1 AND a.finding_id=$2 ORDER BY a.created_at,a.id",
                tenant_id,
                finding_id,
            )
        ]

    def set_action_status(self, tenant_id, id, status, message=""):
        self.execute(
            "UPDATE response_actions SET status=$3,message=$4,applied_at=CASE WHEN $3='applied' THEN now() ELSE applied_at END WHERE tenant_id=$1 AND id=$2",
            tenant_id,
            id,
            status,
            message,
        )

    def disabled_rules(self, tenant_id, conn=None):
        return {
            r["rule_id"]: True
            for r in self.many(
                "SELECT rule_id FROM detection_rules WHERE tenant_id=$1 AND NOT enabled",
                tenant_id,
                conn=conn,
            )
        }

    def set_rule_enabled(self, tenant_id, rule_id, enabled):
        self.execute(
            "INSERT INTO detection_rules(tenant_id,rule_id,enabled) VALUES($1,$2,$3) ON CONFLICT(tenant_id,rule_id) DO UPDATE SET enabled=EXCLUDED.enabled",
            tenant_id,
            rule_id,
            enabled,
        )

    def get_detect_cursor(self, tenant_id):
        try:
            row = self.one(
                "SELECT last_received_at,last_event_id FROM detect_cursors WHERE tenant_id=$1",
                tenant_id,
            )
            return Cursor(
                row["last_received_at"],
                row["last_event_id"]
                if row["last_event_id"] != "00000000-0000-0000-0000-000000000000"
                else "",
            )
        except NotFound:
            return Cursor()

    def set_detect_cursor(self, tenant_id, c):
        if isinstance(c, dict):
            c = Cursor(c.get("time"), c.get("id", ""))
        self.execute(
            "INSERT INTO detect_cursors(tenant_id,last_received_at,last_event_id,updated_at) VALUES($1,$2,$3,now()) ON CONFLICT(tenant_id) DO UPDATE SET last_received_at=EXCLUDED.last_received_at,last_event_id=EXCLUDED.last_event_id,updated_at=now()",
            tenant_id,
            c.time,
            c.id,
        )

    def detect_lag(self, tenant_id):
        t, id = bound(self.get_detect_cursor(tenant_id), True)
        return self.scalar(
            "SELECT count(*) FROM events WHERE tenant_id=$1 AND (received_at,id)>($2,$3::uuid)",
            tenant_id,
            t,
            id,
        )

    def _split_stored_credential_rules(self, conn=None):
        """Run migration 0037 again: split stored legacy credential rules and
        bump those policies' versions so sensors fetch the result."""
        self.execute(CREDENTIAL_SPLIT.read_text(), conn=conn)

    def get_policy(self, tenant_id, conn=None):
        query = "SELECT version,rules,updated_at,ask_rule_ids FROM policies WHERE tenant_id=$1"
        try:
            policy = self.one(query, tenant_id, conn=conn)
            # A legacy credential rule written by a server without this
            # change, such as an older instance during a rolling deploy, is
            # split in storage with a new version, so sensors that hold the
            # old version fetch it. The split and the reread share one
            # transaction, so no other write can land between them.
            if legacy_credential_rules(policy.get("rules") or []):
                with nullcontext(conn) if conn else self.transaction() as tx:
                    self._split_stored_credential_rules(tx)
                    policy = self.one(query, tenant_id, conn=tx)
        except NotFound:
            return {"version": 0, "rules": []}
        rules = policy.get("rules") or []
        # A deny is restored to ask only when its id names one rule, so an
        # explicit deny that shares an id with an ask rule stays a deny.
        counts = Counter(r.get("id") for r in rules)
        asks = {i for i in policy.pop("ask_rule_ids") or [] if counts[i] == 1}
        policy["rules"] = [
            dict(r, action="ask")
            if r.get("action") == "deny" and r.get("id") in asks
            else r
            for r in rules
        ]
        return policy

    def save_policy(self, tenant_id, rules, *, conn=None):
        # Ask rules are stored as denies, so a server rolled back to a
        # version without ask serves a deny that older sensors enforce;
        # ask_rule_ids (migration 0026) records which ones are ask rules.
        rules = split_credential_rule(rules or [])
        counts = Counter(r.get("id") for r in rules)
        # An ask rule without a unique id cannot be told apart from a deny, so
        # it is stored as one.
        asks = [
            r["id"] for r in rules
            if r.get("action") == "ask" and r.get("id") and counts[r["id"]] == 1
        ]
        stored = [dict(r, action="deny") if r.get("action") == "ask" else r for r in rules]
        self.execute(
            "INSERT INTO policies(tenant_id,version,rules,ask_rule_ids,updated_at) VALUES($1,1,$2,$3,now()) ON CONFLICT(tenant_id) DO UPDATE SET version=policies.version+1,rules=EXCLUDED.rules,ask_rule_ids=EXCLUDED.ask_rule_ids,updated_at=now()",
            tenant_id,
            Jsonb(stored),
            asks,
            conn=conn,
        )
        return self.get_policy(tenant_id, conn=conn)

    def policy_version(self, tenant_id):
        query = "SELECT version, rules @> $2 AS legacy FROM policies WHERE tenant_id=$1"
        legacy = Jsonb([{"source": "builtin", "match": {"path_glob": LEGACY_CREDENTIAL_GLOB}}])
        try:
            version = self.scalar("SELECT version FROM policies WHERE tenant_id=$1", tenant_id)
            # Every save bumps the version, including an older server's, so
            # the rules are scanned once per version rather than on every
            # heartbeat.
            if self.clean_policy_versions.get(tenant_id) == version:
                return version
            row = self.one(query, tenant_id, legacy)
            # As in get_policy: a stored legacy rule gets a new version.
            if row["legacy"]:
                with self.transaction() as tx:
                    self._split_stored_credential_rules(tx)
                    row = self.one(query, tenant_id, legacy, conn=tx)
            if not row["legacy"]:
                self.clean_policy_versions[tenant_id] = row["version"]
            return row["version"]
        except NotFound:
            return 0

    def audit(
        self, tenant_id, actor, action, target_type="", target_id="", details=None
    ):
        self.execute(
            "INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            new_id(),
            tenant_id or None,
            actor.get("type", "system"),
            actor.get("id", ""),
            actor.get("name", ""),
            action,
            target_type,
            target_id,
            Jsonb(details or {}),
        )

    def list_audit(self, tenant_id, page=None, *, category="all"):
        conditions = ["tenant_id=$1"]
        if category == "page_views":
            conditions.append("action='dashboard.page.view'")
        elif category == "actions":
            conditions.append("action<>'dashboard.page.view'")
        return self._page(
            "id,at,actor_type,actor_id,actor_name,action,target_type,target_id,details",
            "audit_log",
            conditions,
            [tenant_id],
            page,
            "at",
            "audit",
        )

    def service_heartbeat(self, service, instance, details=None):
        self.execute(
            "INSERT INTO service_heartbeats(service,instance,last_seen_at,details) VALUES($1,$2,now(),$3) ON CONFLICT(service,instance) DO UPDATE SET last_seen_at=now(),details=EXCLUDED.details",
            service,
            instance,
            Jsonb(details or {}),
        )

    def list_service_heartbeats(self):
        return self.many(
            "SELECT DISTINCT ON(service) service AS name,instance,last_seen_at,details FROM service_heartbeats ORDER BY service,last_seen_at DESC"
        )

    def events_last_hour(self, tenant_id):
        return self.scalar(
            "SELECT count(*) FROM events WHERE tenant_id=$1 AND received_at>now()-interval '1 hour'",
            tenant_id,
        )

    def sensors_online(self, tenant_id):
        return self.scalar(
            "SELECT count(*) FROM "
            + sql.sensorFrom
            + " WHERE s.tenant_id=$1 AND s.deleted_at IS NULL AND NOT s.disabled AND a.last_heartbeat_at>now()-interval '90 seconds'",
            tenant_id,
        )

    def get_overview(self, tenant_id, rng="24h", *, risk_only=False, include_evidence=True):
        if rng not in ("24h", "7d", "30d"):
            rng = "24h"
        since = now() - timedelta(days={"24h": 1, "7d": 7, "30d": 30}[rng])
        trunc = "hour" if rng == "24h" else "day"
        step = "1 " + trunc
        count = lambda table, extra="": self.scalar(
            "SELECT count(*) FROM " + table + " WHERE tenant_id=$1 " + extra,
            tenant_id,
            since,
        )
        sensors = {
            "total": count("sensors", "AND deleted_at IS NULL"),
            "online": self.sensors_online(tenant_id),
            "disabled": count("sensors", "AND deleted_at IS NULL AND disabled"),
        }
        sensors["offline"] = sensors["total"] - sensors["online"] - sensors["disabled"]
        findings = dict.fromkeys(SEVERITIES, 0)
        findings.update(
            {
                r["severity"]: r["count"]
                for r in self.many(
                    "SELECT severity,count(*) FROM findings WHERE tenant_id=$1 AND status IN ('open','triaged') GROUP BY severity",
                    tenant_id,
                )
            }
        )
        event_counts = "" if risk_only else """(SELECT count(*) FROM events e
          WHERE e.tenant_id=$1 AND e.received_at>=b AND e.received_at<b+$4::interval) AS events,"""
        result = {
            "range": rng,
            "agents": {
                "total": count("agents"),
                "active": count("agents", "AND last_seen>=$2"),
            },
            "sessions": count("agent_sessions", "AND last_event_at>=$2"),
            "sensors": sensors,
            "findings_open": findings,
            "by_category": self.many(
                "SELECT category,count(*) FROM findings WHERE tenant_id=$1 AND created_at>=$2 GROUP BY category ORDER BY count(*) DESC,category",
                tenant_id,
                since,
            ),
            "timeline": self.many(
                f"""WITH buckets AS (SELECT generate_series(date_trunc($3,$2::timestamptz),date_trunc($3,now()),$4::interval) AS b)
          SELECT b AS bucket,{event_counts}
          (SELECT count(*) FROM findings f WHERE f.tenant_id=$1 AND f.created_at>=b AND f.created_at<b+$4::interval) AS findings FROM buckets ORDER BY b""",
                tenant_id,
                since,
                trunc,
                step,
            ),
            "recent_findings": self.list_findings(tenant_id, page={"limit": 5})[0] if include_evidence else [],
        }
        if not risk_only:
            result.update({
                "events": count("events", "AND received_at>=$2"),
                "by_product": self.many(
                    "SELECT a.product,count(*) AS agents,(SELECT count(*) FROM events e WHERE e.tenant_id=$1 AND e.product=a.product AND e.received_at>=$2) AS events FROM agents a WHERE a.tenant_id=$1 GROUP BY a.product ORDER BY count(*) DESC,a.product",
                    tenant_id,
                    since,
                ),
                "top_agents": self.many(
                    'SELECT a.id AS agent_id,a.product,a.hostname,a.username AS "user",count(e.id) AS events FROM events e JOIN agents a ON a.id=e.agent_id WHERE e.tenant_id=$1 AND e.received_at>=$2 GROUP BY a.id ORDER BY events DESC LIMIT 5',
                    tenant_id,
                    since,
                ) if include_evidence else [],
            })
        return result

    def bootstrap_tenant(self, name, slug, tenant_id="", label="bootstrap", max_uses=0):
        """Idempotently establish a tenant and issue a fresh enrollment credential."""
        if not name.strip() or not valid_slug(slug):
            raise ValueError("name and a valid lowercase slug are required")
        if max_uses < 0:
            raise ValueError("max_uses must not be negative")
        plain, hashed = new_token(PREFIX_ENROLLMENT)
        token_id = new_id()
        with self.transaction() as conn:
            # Serialize concurrent bootstrap calls for the same human-readable slug.
            self.execute(
                "SELECT pg_advisory_xact_lock(hashtext($1))",
                "openaidr-bootstrap:" + slug,
                conn=conn,
            )
            existing = self.many(
                "SELECT id,name,slug,status FROM tenants WHERE slug=$1", slug, conn=conn
            )
            if existing:
                tenant = existing[0]
                if tenant_id and tenant_id != tenant["id"]:
                    raise ValueError(
                        "configured tenant id does not match the requested slug"
                    )
                if tenant["status"] != "active":
                    raise ValueError("tenant is not active")
            else:
                tenant = dict(
                    id=tenant_id or new_id(),
                    name=name.strip(),
                    slug=slug,
                    status="active",
                )
                self.execute(
                    "INSERT INTO tenants(id,name,slug,plan) VALUES($1,$2,$3,'self-hosted')",
                    tenant["id"],
                    tenant["name"],
                    slug,
                    conn=conn,
                )
                self.execute(
                    "INSERT INTO policies(tenant_id,version,rules) VALUES($1,1,'[]'::jsonb)",
                    tenant["id"],
                    conn=conn,
                )
            self.execute(
                "INSERT INTO enrollment_tokens(id,tenant_id,token_hash,label,max_uses) VALUES($1,$2,$3,$4,$5)",
                token_id,
                tenant["id"],
                hashed,
                label,
                max_uses,
                conn=conn,
            )
        return dict(tenant=tenant, enrollment_token=plain, enrollment_token_id=token_id)

    def get_telemetry_export(self, tenant_id, id):
        """One stored export with its canonical payload, for investigation."""
        return self.one(
            """SELECT e.id,e.batch_id,e.sensor_id,COALESCE(s.hostname,'') AS hostname,
                      e.signal,e.record_count,e.record_count AS total_record_count,
                      e.service_names,e.payload_sha256,e.first_event_unix_nano,
                      e.last_event_unix_nano,e.received_at,e.payload,
                      EXISTS (SELECT 1 FROM jsonb_array_elements(e.payload -> CASE e.signal
                                WHEN 'logs' THEN 'resourceLogs' WHEN 'metrics' THEN 'resourceMetrics'
                                ELSE 'resourceSpans' END) r(value)) AND NOT EXISTS (
                        SELECT 1 FROM jsonb_array_elements(e.payload -> CASE e.signal
                                WHEN 'logs' THEN 'resourceLogs' WHEN 'metrics' THEN 'resourceMetrics'
                                ELSE 'resourceSpans' END) r(value)
                        WHERE NOT EXISTS (
                            SELECT 1 FROM jsonb_array_elements(COALESCE(r.value #> '{resource,attributes}','[]'::jsonb)) a
                            WHERE a->>'key'='openaidr.demo' AND a #> '{value,boolValue}'='true'::jsonb)) AS demo
               FROM telemetry_exports e LEFT JOIN sensors s ON s.id=e.sensor_id AND s.tenant_id=$1
               WHERE e.tenant_id=$1 AND e.id=$2""",
            tenant_id,
            id,
        )

    def ingest_telemetry(self, sensor, signal, batch_id, payload, record_count, *, conn=None):
        """Persist one canonical export. Retries are atomic across processes/restarts."""
        from . import ingest_evidence

        reason = ingest_evidence.storage_issue(payload)
        canonical = ingest_evidence.encode(payload) if reason else json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
        digest = hashlib.sha256(canonical).hexdigest()
        services, times = set(), []
        resource_key = {
            "logs": "resourceLogs",
            "metrics": "resourceMetrics",
            "traces": "resourceSpans",
        }[signal]
        for resource in payload.get(resource_key, []):
            for attribute in resource.get("resource", {}).get("attributes", []):
                if attribute.get("key") == "service.name":
                    value = attribute.get("value", {}).get("stringValue")
                    if isinstance(value, str):
                        services.add(value)

        def collect_times(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in (
                        "timeUnixNano",
                        "startTimeUnixNano",
                        "endTimeUnixNano",
                        "observedTimeUnixNano",
                    ):
                        try:
                            number = int(item)
                            if 0 < number <= 18446744073709551615:
                                times.append(number)
                        except (ValueError, TypeError):
                            pass
                    else:
                        collect_times(item)
            elif isinstance(value, list):
                for item in value:
                    collect_times(item)

        collect_times(payload)
        with nullcontext(conn) if conn is not None else self.transaction() as conn:
            self.execute("SELECT ensure_telemetry_partitions($1)", sensor["tenant_id"], conn=conn)
            self.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                f"export:{sensor['tenant_id']}:{sensor['id']}:{signal}:{uuid.UUID(str(batch_id))}",
                conn=conn,
            )
            previous = self.many(
                "SELECT payload_sha256 FROM telemetry_export_keys WHERE tenant_id=$1 AND sensor_id=$2 AND signal=$3 AND batch_id=$4",
                sensor["tenant_id"], sensor["id"], signal, batch_id, conn=conn,
            )
            if previous:
                if previous[0]["payload_sha256"] != digest:
                    raise Conflict("batch id was already used for a different payload")
                return False
            retained = self.many(
                """SELECT payload_sha256 FROM retained_ingest_evidence
                   WHERE tenant_id=$1 AND sensor_id=$2 AND source=$3 AND record_key=$4""",
                sensor["tenant_id"], sensor["id"], "otlp-" + signal,
                str(uuid.UUID(str(batch_id))), conn=conn,
            )
            if retained:
                if retained[0]["payload_sha256"] != hashlib.sha256(ingest_evidence.encode(payload)).hexdigest():
                    raise Conflict("batch id was already used for a different payload")
                return False
            if reason:
                ingest_evidence.retain(self, sensor, "otlp-" + signal, str(uuid.UUID(str(batch_id))),
                                       payload, reason, conn=conn)
                return True
            try:
                with conn.transaction():
                    inserted = self.many(
                        "INSERT INTO telemetry_exports(id,tenant_id,sensor_id,signal,batch_id,payload_sha256,record_count,service_names,first_event_unix_nano,last_event_unix_nano,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id,received_at",
                        new_id(),
                        sensor["tenant_id"],
                        sensor["id"],
                        signal,
                        batch_id,
                        digest,
                        record_count,
                        sorted(services),
                        min(times) if times else None,
                        max(times) if times else None,
                        Jsonb(payload),
                        conn=conn,
                    )
                    # Events derive from the export inside the same transaction, so
                    # an export and its events commit together. A translation bug
                    # keeps the export and leaves it pending for the backfill.
                    self._translate_export(
                        conn, inserted[0]["id"], sensor, signal, payload,
                        inserted[0]["received_at"],
                    )
            except (psycopg.DataError, psycopg.errors.ProgramLimitExceeded):
                # The whole export is the OTLP retry unit. Keep its canonical
                # payload durable without inventing a modified successful export.
                ingest_evidence.retain(self, sensor, "otlp-" + signal, str(uuid.UUID(str(batch_id))),
                                       payload, "database_data_error", conn=conn)
            return True

    def _translate_export(self, conn, export_id, sensor, signal, payload, received):
        """Derive and persist events for one export; returns the accepted count."""
        accepted = 0
        try:
            with conn.transaction():
                events = translate_export(export_id, sensor, signal, payload, received)
                if events:
                    accepted = self.ingest_batch(sensor, events, conn)["accepted"]
                self.execute(
                    "UPDATE telemetry_exports SET translated_at=now() WHERE id=$1",
                    export_id,
                    conn=conn,
                )
        except Exception:
            log.exception("translating telemetry export %s failed", export_id)
            return 0
        return accepted

    def translate_untranslated_exports(self, tenant_id=None, limit=200):
        """Backfill events for stored logs exports that were never translated.

        Bounded by ``limit`` exports per call. Each export is processed in its
        own transaction under a row lock, so an ingest or a second backfill
        running at the same time skips it. Returns ``{"exports", "events"}``.
        """
        pending = self.many(
            "SELECT id FROM telemetry_exports WHERE signal='logs' AND translated_at IS NULL AND ($1::uuid IS NULL OR tenant_id=$1) ORDER BY received_at,id LIMIT $2",
            tenant_id or None,
            max(1, int(limit)),
        )
        result = {"exports": 0, "events": 0}
        for row in pending:
            with self.transaction() as conn:
                locked = self.many(
                    """SELECT e.id,e.signal,e.payload,e.received_at,e.tenant_id,e.sensor_id,
                              COALESCE(s.hostname,'') AS hostname,COALESCE(s.os,'') AS os,COALESCE(s.arch,'') AS arch,COALESCE(s.username,'') AS username
                       FROM telemetry_exports e LEFT JOIN sensors s ON s.id=e.sensor_id
                       WHERE e.id=$1 AND e.translated_at IS NULL FOR UPDATE OF e SKIP LOCKED""",
                    row["id"],
                    conn=conn,
                )
                if not locked:
                    continue
                export = locked[0]
                sensor = {
                    key: export[key]
                    for key in ("id", "tenant_id", "hostname", "os", "arch", "username")
                }
                sensor["id"] = export["sensor_id"]
                result["events"] += self._translate_export(
                    conn,
                    export["id"],
                    sensor,
                    export["signal"],
                    export["payload"],
                    export["received_at"],
                )
                result["exports"] += 1
        return result

    def create_tenant_owner(self, tenant_id, email, name, password_hash):
        """Create, never reset, the initial owner for an explicitly bound tenant."""
        if not valid_uuid(tenant_id):
            raise ValueError("a valid OPENAIDR_TENANT_ID is required")
        email, name = email.strip().lower(), name.strip()
        if "@" not in email or not name:
            raise ValueError("a valid email and nonempty name are required")
        user_id = new_id()
        with self.transaction() as conn:
            tenant = self.one(
                "SELECT status FROM tenants WHERE id=$1 FOR SHARE", tenant_id, conn=conn
            )
            if tenant["status"] != "active":
                raise ValueError("tenant must be active")
            self.execute(
                "INSERT INTO tenant_users(id,tenant_id,email,name,password_hash,role) VALUES($1,$2,$3,$4,$5,'owner')",
                user_id,
                tenant_id,
                email,
                name,
                password_hash,
                conn=conn,
            )
            self.execute(
                "INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details) VALUES($1,$2,'system','','tenant CLI','user.create','user',$3,$4)",
                new_id(),
                tenant_id,
                user_id,
                Jsonb({"email": email, "role": "owner"}),
                conn=conn,
            )
        return self.get_user(tenant_id, user_id)
