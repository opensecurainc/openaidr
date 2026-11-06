"""Organization app approvals and usage from attributed activity, not installs."""

import hashlib
from datetime import timedelta

from psycopg.types.json import Jsonb

from openaidr.core.event import PRODUCTS
from openaidr.core.ai_software import (
    APP_NAMES as APP_NAMES, APP_IDENTIFIERS as APP_IDENTIFIERS,
    PACKAGE_PRODUCTS as PACKAGE_PRODUCTS, application_product as application_product,
)
from . import ai_software, app_inventory
from .httpx import require
from .store import new_id, now

# Exact product aliases keep helpers and unrelated applications distinct.
PRODUCT_NAMES = {
    "chatgpt": "ChatGPT",
    "claude": "Claude",
    "claude-code": "Claude Code",
    "codex": "Codex",
    "codex-cli": "Codex CLI",
    "cursor": "Cursor",
    "antigravity": "Antigravity",
    "opencode": "OpenCode",
    "hermes-agent": "Hermes Agent",
    "github-copilot": "GitHub Copilot",
    "copilot-cli": "GitHub Copilot CLI",
    "gemini-cli": "Gemini CLI",
    "aider": "Aider",
    "gpt4all": "GPT4All",
    "lm-studio": "LM Studio",
    "ollama": "Ollama",
    "perplexity": "Perplexity",
    "windsurf": "Windsurf",
    "workbuddy": "WorkBuddy",
}
EVENT_PRODUCTS = {product: product for product in PRODUCTS if product != "unknown"}
EVENT_PRODUCTS["codex_cli_rs"] = "codex-cli"
EVENT_PRODUCTS = {alias: "codex" if product == "codex-cli" else product
                  for alias, product in EVENT_PRODUCTS.items()}


def approval_product(st, tenant, product):
    if product in {"codex-cli", "app-" + hashlib.sha256(b"com.openai.codex").hexdigest()}:
        return "codex"
    # Retain old product URLs after consolidating approvals. ChatGPT is shared
    # by the old name fallback and must keep its own independent approval.
    if product != "chatgpt" and st.scalar(
        """SELECT EXISTS(SELECT 1 FROM ai_application_approvals
        WHERE tenant_id=$1 AND product_id='codex'
            AND previous_decisions @> $2::jsonb)""",
        tenant, Jsonb([{"product_id": product}]),
    ):
        return "codex"
    return product


def approval_records(st, tenant, *, conn=None):
    rows = {row["product_id"]: row for row in st.many(
        "SELECT * FROM ai_application_approvals WHERE tenant_id=$1", tenant, conn=conn,
    )}
    canonical = rows.get("codex")
    if canonical and canonical["approval_conflict"]:
        canonical["approved"] = False
    aliases = {"codex-cli", "app-" + hashlib.sha256(b"com.openai.codex").hexdigest()}
    if canonical:
        aliases.update(entry["product_id"] for entry in canonical["previous_decisions"]
                       if entry["product_id"] not in ("codex", "chatgpt"))
    # An old worker may finish a variant decision during rollout. Keep newer
    # decisions visible, with denial taking precedence, until the whole-product
    # decision is confirmed again. Future ChatGPT choices remain independent.
    pending = [row for product, row in rows.items() if product in aliases
               and (canonical is None or row["updated_at"] > canonical["updated_at"])]
    if pending:
        decisions = ([canonical] if canonical else []) + pending
        previous = {entry["product_id"]: entry for entry in canonical["previous_decisions"]} if canonical else {}
        previous.update({row["product_id"]: {key: row[key] for key in ("product_id", "name", "approved")}
                         | {"updated_at": row["updated_at"].isoformat()}
                         for row in decisions})
        rows["codex"] = {
            "product_id": "codex", "name": "Codex",
            "approved": all(row["approved"] for row in decisions),
            "updated_at": max(row["updated_at"] for row in decisions),
            "approval_conflict": any(row["approval_conflict"] for row in decisions)
                or len({row["approved"] for row in decisions}) > 1,
            "previous_decisions": list(previous.values()),
        }
    return rows


def _installed(st, tenant):
    conditions, args, category = app_inventory._filters(
        tenant, {"include_helpers": "false"}
    )
    records = st.many(
        f"""{app_inventory.APPLICATION_RECORDS}
        SELECT a.identifier,a.name,a.source,max(a.last_seen_at) AS last_seen_at
        FROM applications a JOIN sensors s ON s.id=a.sensor_id
        WHERE {" AND ".join(conditions)} AND ({category})='ai'
        GROUP BY a.identifier,a.name,a.source ORDER BY a.identifier,a.name""",
        *args,
    )
    products = {}
    for row in records:
        identifier = row["identifier"].lower()
        product = application_product(identifier, row["name"], row["source"])
        if product is None:
            # Preserve AI vendor apps absent from the product alias catalog.
            product = "app-" + hashlib.sha256(identifier.encode()).hexdigest()
        previous = products.get(product)
        if previous is None or row["last_seen_at"] > previous["last_installed_at"]:
            products[product] = {
                "name": PRODUCT_NAMES.get(product, row["name"]),
                "last_installed_at": row["last_seen_at"],
            }
    for ecosystem, aliases in PACKAGE_PRODUCTS.items():
        rows = st.many(
            """SELECT c.identifier,max(c.last_seen_at) AS last_seen_at
            FROM inventory_components c
            JOIN sensors s ON s.id=c.sensor_id AND s.tenant_id=c.tenant_id
            WHERE c.tenant_id=$1 AND s.deleted_at IS NULL AND c.kind='package'
                AND c.evidence='installed' AND c.ecosystem=$2 AND c.identifier=ANY($3::text[])
            GROUP BY c.identifier""",
            tenant,
            ecosystem,
            list(aliases),
        )
        for row in rows:
            product = aliases[row["identifier"]]
            previous = products.get(product)
            if previous is None or row["last_seen_at"] > previous["last_installed_at"]:
                products[product] = {
                    "name": PRODUCT_NAMES[product],
                    "last_installed_at": row["last_seen_at"],
                }
    return products


def overview(st, tenant, days="1"):
    require(str(days) in ("1", "7", "30"), "days must be 1, 7, or 30")
    days = int(days)
    end = now()
    start = end - timedelta(days=days)
    products = _installed(st, tenant)
    # Count each user before product totals to keep full event bodies out of sorts.
    activity = st.many(
        """WITH aliases AS (
            SELECT * FROM unnest($4::text[],$5::text[]) AS a(alias,product_id)
        ), activity AS (
            SELECT a.product_id,e.time,e.sensor_id,s.hostname,
                NULLIF(btrim(jsonb_path_query_first(e.body,
                    'strict $.host.user ? (@.type() == "string")',
                    silent => true) #>> '{}'),'') AS username
            FROM events e JOIN aliases a ON a.alias=e.product
            JOIN sensors s ON s.id=e.sensor_id AND s.tenant_id=e.tenant_id
            WHERE e.tenant_id=$1 AND s.deleted_at IS NULL
                AND e.time >= $2 AND e.time <= $3 AND e.kind<>'sensor'
        ), users AS (
            SELECT product_id,username,count(*) AS activity_events,
                max(time) AS last_activity_at,
                jsonb_agg(DISTINCT jsonb_build_object('id',sensor_id,'name',hostname)) AS devices
            FROM activity GROUP BY product_id,username
        )
        SELECT product_id,count(username) AS observed_users,
            sum(activity_events)::bigint AS activity_events,
            COALESCE(sum(activity_events) FILTER (WHERE username IS NULL),0)::bigint
                AS unattributed_events,
            max(last_activity_at) AS last_activity_at,
            COALESCE(jsonb_agg(jsonb_build_object(
                'username',username,'last_activity_at',last_activity_at,'devices',devices)
                ORDER BY last_activity_at DESC,username) FILTER (WHERE username IS NOT NULL),
                '[]'::jsonb) AS users
        FROM users GROUP BY product_id""",
        tenant,
        start,
        end,
        list(EVENT_PRODUCTS),
        list(EVENT_PRODUCTS.values()),
    )
    for row in activity:
        product = row.pop("product_id")
        products.setdefault(
            product, {"name": PRODUCT_NAMES.get(product, product)}
        ).update(row)
    approvals = list(approval_records(st, tenant).values())
    retired = {"codex-cli"} | {entry["product_id"] for row in approvals if row["product_id"] == "codex"
                             for entry in row["previous_decisions"] if entry["product_id"] not in ("codex", "chatgpt")}
    for row in approvals:
        product = row["product_id"]
        if product in retired:
            continue
        products.setdefault(product, {"name": row["name"]}).update(
            approved=bool(row["approved"]), approval_updated_at=row["updated_at"]
        )
    items = []
    for product, values in products.items():
        users = values.get("observed_users", 0)
        items.append(
            {
                "id": product,
                "name": values["name"],
                "approved": values.get("approved", False),
                "approval_updated_at": values.get("approval_updated_at"),
                "observed_users": users or None,
                "users": values.get("users", []),
                "usage_status": (
                    "unavailable"
                    if not users
                    else "partial"
                    if values["unattributed_events"]
                    else "observed"
                ),
                "activity_events": values.get("activity_events", 0),
                "unattributed_events": values.get("unattributed_events", 0),
                "last_activity_at": values.get("last_activity_at"),
                "last_installed_at": values.get("last_installed_at"),
            }
        )
    items.sort(
        key=lambda row: (-(row["observed_users"] or 0), row["name"].lower(), row["id"])
    )
    return {"window": {"start": start, "end": end, "days": days}, "items": items}


def save_approval(st, tenant, product, data, actor):
    require(
        set(data) == {"approved"} and type(data.get("approved")) is bool,
        "approved must be a boolean and the only request field",
    )
    require(len(product) <= 80, "invalid application id")
    requested = product
    product = approval_product(st, tenant, product)
    item = next(
        (row for row in overview(st, tenant, "30")["items"] if row["id"] == product), None
    )
    require(item is not None, "application not found", 404)
    return persist_approval(st, tenant, item, data["approved"], actor) | {"id": requested}


def persist_approval(st, tenant, item, approved, actor):
    product = item["id"]
    with st.transaction() as conn:
        # Serialize writes to one app so the audit records the actual prior choice.
        st.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            "ai-application-approval:" + tenant + ":" + product,
            conn=conn,
        )
        previous = approval_records(st, tenant, conn=conn).get(product) if product == "codex" else st.scalar(
            """SELECT (SELECT jsonb_build_object('approved',approved,'approval_conflict',approval_conflict,
                'previous_decisions',previous_decisions)
                FROM ai_application_approvals WHERE tenant_id=$1 AND product_id=$2)""",
            tenant,
            product,
            conn=conn,
        )
        row = st.one(
            """INSERT INTO ai_application_approvals(tenant_id,product_id,name,approved)
            VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,product_id) DO UPDATE SET
                name=EXCLUDED.name,approved=EXCLUDED.approved,updated_at=clock_timestamp(),approval_conflict=false
            RETURNING product_id AS id,approved,updated_at AS approval_updated_at""",
            tenant,
            product,
            item["name"],
            approved,
            conn=conn,
        )
        st.execute(
            """INSERT INTO audit_log
            (id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
            VALUES($1,$2,$3,$4,$5,'ai-application.approval','ai-application',$6,$7)""",
            new_id(),
            tenant,
            actor["type"],
            actor["id"],
            actor["name"],
            product,
            Jsonb(
                {
                    "name": item["name"],
                    "before": bool(previous and previous["approved"]),
                    "before_status": "monitoring" if previous is None or previous["approved"] is None
                        else "approved" if previous["approved"] else "unapproved",
                    **({"previous_decisions": previous["previous_decisions"]} if previous and previous["approval_conflict"] else {}),
                    "approved": row["approved"],
                }
            ),
            conn=conn,
        )
    return row
