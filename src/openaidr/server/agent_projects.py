"""Project attribution from timestamped session and hook metadata."""

from bisect import bisect_right
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import logging

from . import agent_costs
from .agent_costs import UNKNOWN

log = logging.getLogger(__name__)
SERVICES = {
    "codex-cli": ("codex-cli", "codex-app-server", "codex"),
    "claude-code": ("claude-code", "claude_code"),
    "cowork": ("cowork",),
    "github-copilot": ("github-copilot",),
    "cursor": ("cursor",),
    "hermes-agent": ("hermes-agent",),
    "opencode": ("opencode",),
    "workbuddy": ("workbuddy",),
}
SCOPE = "tenant_id=%s AND sensor_id=%s AND product=%s AND session_id=%s"


def pending_count(conn, tenant):
    return conn.execute(
        """SELECT count(*) AS count FROM (
             SELECT sensor_id,product,session_id FROM agent_project_sessions
             WHERE (%s::uuid IS NULL OR tenant_id=%s) AND pending
             UNION SELECT sensor_id,product,session_id FROM agent_project_evidence
             WHERE (%s::uuid IS NULL OR tenant_id=%s) AND pending
           ) pending""", (tenant, tenant, tenant, tenant),
    ).fetchone()["count"]


def session_keys(sensor, product, session_id):
    return [hashlib.sha256(json.dumps((str(sensor), service, session_id)).encode()).hexdigest()
            for service in SERVICES[product]]


def register(conn, tenant, sensor, product, session_id, keys=()):
    conn.execute(
        """INSERT INTO agent_project_sessions
           (tenant_id,sensor_id,product,session_id,session_keys)
           VALUES (%s,%s,%s,%s,%s)
           ON CONFLICT (tenant_id,sensor_id,product,session_id) DO UPDATE SET
             session_keys=ARRAY(SELECT DISTINCT unnest(agent_project_sessions.session_keys||excluded.session_keys)),
             pending=true,retry_at=NULL,updated_at=clock_timestamp()""",
        (tenant, sensor, product, session_id, list(keys)),
    )


def observe(conn, tenant, sensor, product, session, event_key, when):
    if product not in SERVICES or not isinstance(session, dict):
        return
    sid = session.get("id")
    if not isinstance(sid, str) or not 0 < len(sid) <= 1024:
        return
    directory = agent_costs.project({"cwd": session.get("cwd")})
    parent = session.get("parent_id")
    if not isinstance(parent, str) or not 0 < len(parent) <= 1024 or parent == sid:
        parent = ""
    if not directory and not parent:
        return
    # Append only: hook ingestion never waits for a worker's session queue lock.
    conn.execute(
        """INSERT INTO agent_project_evidence
           (tenant_id,sensor_id,product,session_id,event_key,observed_at,project,parent_id)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
        (tenant, sensor, product, sid, event_key, when, directory, parent),
    )


def exchange_metadata(st, sensor, report):
    """Repair only this device's observed sessions through its heartbeat."""
    if not isinstance(report, dict) or report.get("version") != 1 or sensor["disabled"]:
        return None
    observations = report.get("observations", [])
    if not isinstance(observations, list) or len(observations) > 128:
        return None
    with st.transaction() as conn:
        conn.execute("SET LOCAL statement_timeout='2s'")
        for item in observations:
            if not isinstance(item, dict):
                continue
            product, sid = item.get("product"), item.get("session_id")
            if product not in ("codex-cli", "claude-code") or not isinstance(sid, str) or not 0 < len(sid) <= 256 or not sid.isprintable():
                continue
            try:
                when = datetime.fromisoformat(item["time"].replace("Z", "+00:00"))
                if when.tzinfo is None or when > datetime.now(timezone.utc):
                    continue
            except (KeyError, TypeError, ValueError, AttributeError):
                continue
            session = {"id": sid}
            for field in ("cwd", "parent_id"):
                value = item.get(field, "")
                if isinstance(value, str) and (not value or value.isprintable()) and len(value) <= (4096 if field == "cwd" else 256):
                    session[field] = value
            if "cwd" in item and item["cwd"] is None:
                # A redacted or oversized directory ends the previous assignment.
                session["cwd"] = UNKNOWN
            scope = (sensor["tenant_id"], sensor["id"], product, sid)
            if not conn.execute(
                f"SELECT 1 FROM agent_project_sessions WHERE {SCOPE}", scope,
            ).fetchone():
                continue
            # Managed captures must retain their registration and capture contract.
            if conn.execute(
                """SELECT 1 FROM agent_sessions WHERE tenant_id=%s AND sensor_id=%s
                   AND product=%s AND external_id IN (%s,%s) AND registration_id IS NOT NULL""",
                (*scope, session.get("parent_id", "")),
            ).fetchone():
                continue
            ident = hashlib.sha256(json.dumps([product, session, when.isoformat()], sort_keys=True).encode()).hexdigest()
            observe(conn, *scope[:3], session, "metadata:" + ident, when)
        requests = []
        if report.get("ready") is True:
            after = report.get("after")
            if not (isinstance(after, list) and len(after) == 2
                    and all(isinstance(value, str) and len(value) <= 256 for value in after)):
                after = ["", ""]
            requests = conn.execute(
                """WITH usage AS (
                     SELECT session_key FROM agent_cost_records
                     WHERE tenant_id=%s AND sensor_id=%s AND is_usage
                       AND happened_at>=now()-interval '30 days'
                       AND (project=%s OR happened_at>=now()-interval '1 hour')
                     GROUP BY session_key
                   )
                   SELECT p.product,p.session_id FROM agent_project_sessions p
                   WHERE p.tenant_id=%s AND p.sensor_id=%s
                     AND p.product IN ('codex-cli','claude-code')
                     AND p.session_id ~ '^[A-Za-z0-9_-]+$' AND length(p.session_id)<=256
                     AND (p.product,p.session_id)>(%s,%s)
                     AND EXISTS (SELECT 1 FROM usage u WHERE u.session_key=ANY(p.session_keys))
                     AND NOT EXISTS (SELECT 1 FROM agent_sessions s
                         WHERE s.tenant_id=p.tenant_id AND s.sensor_id=p.sensor_id
                           AND s.product=p.product AND s.external_id=p.session_id
                           AND s.registration_id IS NOT NULL)
                   ORDER BY p.product,p.session_id LIMIT 4""",
                (sensor["tenant_id"], sensor["id"], UNKNOWN, sensor["tenant_id"], sensor["id"], *after),
            ).fetchall()
    return {"version": 1, "requests": requests}


def backfill(conn, scope):
    tenant, sensor, product, sid = scope
    rows = conn.execute(
        """SELECT e.id,e.time,e.body->'session' AS session FROM events e
           JOIN agent_sessions s ON s.id=e.session_id AND s.tenant_id=e.tenant_id
           WHERE s.tenant_id=%s AND s.sensor_id=%s AND s.product=%s AND s.external_id=%s
             AND (coalesce(e.body#>>'{session,cwd}','')<>''
                  OR coalesce(e.body#>>'{session,parent_id}','')<>'')""", scope,
    ).fetchall()
    for row in rows:
        observe(conn, tenant, sensor, product, row["session"], "event:" + str(row["id"]), row["time"])
    rows = conn.execute(
        """SELECT id,created_at,actions FROM ordinary_hook_checks
           WHERE tenant_id=%s AND sensor_id=%s AND product=%s AND session_id=%s
           ORDER BY created_at""", scope,
    ).fetchall()
    for row in rows:
        for index, action in enumerate(row["actions"]):
            observe(conn, tenant, sensor, product, action.get("session"),
                    f"hook:{row['id']}:{index}", row["created_at"])
    # Use the session snapshot only when timestamped directory evidence is gone.
    # Late ingestion can leave this snapshot older than retained observations.
    for row in conn.execute(
        """SELECT id,cwd,last_event_at FROM agent_sessions
           WHERE tenant_id=%s AND sensor_id=%s AND product=%s AND external_id=%s AND cwd<>''
             AND NOT EXISTS (SELECT 1 FROM agent_project_evidence
                             WHERE tenant_id=%s AND sensor_id=%s AND product=%s AND session_id=%s AND project<>'')""",
        (*scope, *scope),
    ):
        observe(conn, tenant, sensor, product, {"id": sid, "cwd": row["cwd"]},
                "session:" + str(row["id"]), row["last_event_at"])


def resolve(conn, scope, keys):
    tenant, sensor, product, sid = scope
    keys = sorted(set(keys) | set(session_keys(sensor, product, sid)))
    for key in keys:
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                     (f"agent-cost:{tenant}:{key}",))
    rows = conn.execute(
        """WITH RECURSIVE ancestors(session_id,path) AS (
             SELECT %s::text,ARRAY[%s::text]
             UNION ALL
             SELECT DISTINCT e.parent_id,a.path||e.parent_id
             FROM ancestors a JOIN agent_project_evidence e ON e.session_id=a.session_id
             WHERE e.tenant_id=%s AND e.sensor_id=%s AND e.product=%s
               AND e.parent_id<>'' AND NOT e.parent_id=ANY(a.path) AND cardinality(a.path)<16
           )
           SELECT DISTINCT e.session_id,e.observed_at,e.project,e.parent_id
           FROM agent_project_evidence e JOIN ancestors a USING(session_id)
           WHERE e.tenant_id=%s AND e.sensor_id=%s AND e.product=%s
           ORDER BY e.observed_at""",
        (sid, sid, tenant, sensor, product, tenant, sensor, product),
    ).fetchall()
    directories, parents = defaultdict(dict), defaultdict(dict)
    for row in rows:
        for field, target in (("project", directories), ("parent_id", parents)):
            if row[field]:
                target[row["session_id"]].setdefault(row["observed_at"], set()).add(row[field])

    def timeline(values):
        return {session: (sorted(points), points) for session, points in values.items()}

    directories, parents = timeline(directories), timeline(parents)

    def at(values, session, when):
        times, points = values.get(session, ([], {}))
        index = bisect_right(times, when) - 1
        if index < 0:
            return set()
        return points[times[index]]

    def directory(session, when, visited=()):
        if session in visited or len(visited) >= 16:
            return ""
        choices = at(directories, session, when)
        if choices:
            return next(iter(choices)) if len(choices) == 1 else ""
        related = at(parents, session, when)
        if len(related) == 1:
            return directory(next(iter(related)), when, (*visited, session))
        return ""

    updates, contexts = [], set()
    for row in conn.execute(
        """SELECT event_key,happened_at,session_project,context_key FROM agent_cost_records
           WHERE tenant_id=%s AND session_key=ANY(%s) AND is_usage""", (tenant, keys),
    ):
        value = directory(sid, row["happened_at"])
        if value != row["session_project"]:
            updates.append((row["event_key"], value))
            if row["context_key"]:
                contexts.add(row["context_key"])
    for start in range(0, len(updates), 1000):
        batch = updates[start:start + 1000]
        placeholders = ",".join(["(%s::text,%s::text)"] * len(batch))
        conn.execute(
            f"""UPDATE agent_cost_records e
                SET session_project=p.project,project=coalesce(nullif(e.direct_project,''),nullif(p.project,''),%s)
                FROM (VALUES {placeholders}) p(event_key,project)
                WHERE e.tenant_id=%s AND e.event_key=p.event_key""",
            (UNKNOWN, *(value for row in batch for value in row), tenant),
        )
    from .agent_cost_usage import resolve_contexts

    resolve_contexts(conn, tenant, contexts)


def process_pending(st, tenant_id=None, limit=50):
    # Transfer append-only observations into the queue in a separate transaction.
    # Session locks and cost writes are never held by hook requests.
    with st.transaction() as conn:
        conn.execute("SET LOCAL statement_timeout='30s'")
        rows = conn.execute(
            """SELECT * FROM agent_project_evidence WHERE pending
               AND (%s::uuid IS NULL OR tenant_id=%s)
               ORDER BY observed_at LIMIT %s FOR UPDATE SKIP LOCKED""",
            (tenant_id, tenant_id, limit * 20),
        ).fetchall()
        groups = defaultdict(list)
        for row in rows:
            scope = tuple(row[name] for name in ("tenant_id", "sensor_id", "product", "session_id"))
            groups[scope].append(row["event_key"])
        scopes = set(groups)
        for scope in groups:
            for child in conn.execute(
                """WITH RECURSIVE children(session_id) AS (
                     SELECT %s::text UNION
                     SELECT e.session_id FROM agent_project_evidence e JOIN children c ON e.parent_id=c.session_id
                     WHERE e.tenant_id=%s AND e.sensor_id=%s AND e.product=%s
                   ) SELECT session_id FROM children""",
                (scope[3], *scope[:3]),
            ):
                scopes.add((*scope[:3], child["session_id"]))
        for scope in sorted(scopes):
            register(conn, *scope)
        for scope, event_keys in groups.items():
            conn.execute(f"UPDATE agent_project_evidence SET pending=false WHERE {SCOPE} AND event_key=ANY(%s)",
                         (*scope, event_keys))
    completed = 0
    for _ in range(limit):
        with st.transaction() as conn:
            conn.execute("SET LOCAL statement_timeout='30s'")
            conn.execute("SET LOCAL lock_timeout='5s'")
            row = conn.execute(
                """SELECT * FROM agent_project_sessions WHERE pending
                   AND (retry_at IS NULL OR retry_at<=now()) AND (%s::uuid IS NULL OR tenant_id=%s)
                   ORDER BY updated_at LIMIT 1 FOR UPDATE SKIP LOCKED""", (tenant_id, tenant_id),
            ).fetchone()
            if not row:
                break
            scope = tuple(row[name] for name in ("tenant_id", "sensor_id", "product", "session_id"))
            try:
                with conn.transaction():
                    if row["backfill"]:
                        backfill(conn, scope)
                    resolve(conn, scope, row["session_keys"])
                    conn.execute(f"UPDATE agent_project_sessions SET pending=false,backfill=false,retry_at=NULL WHERE {SCOPE}", scope)
                completed += 1
            except Exception:
                log.exception("Project attribution failed for a %s session", row["product"])
                conn.execute(f"UPDATE agent_project_sessions SET retry_at=now()+interval '1 minute' WHERE {SCOPE}", scope)
    return completed + len(rows)
