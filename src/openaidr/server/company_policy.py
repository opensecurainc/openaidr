"""Tenant-authored instructions for model assessments, separate from evidence."""

from contextlib import nullcontext

from psycopg.types.json import Jsonb

from .httpx import require
from .store import new_id

MAX_PROMPT_CHARACTERS = 10_000


def read(st, tenant_id, *, conn=None, lock=False):
    if lock:
        # Materialize the empty policy too, so a first save cannot race a release.
        st.execute(
            "INSERT INTO tenant_company_policies(tenant_id) VALUES($1) ON CONFLICT DO NOTHING",
            tenant_id, conn=conn,
        )
    rows = st.many(
        "SELECT revision,prompt,updated_at FROM tenant_company_policies WHERE tenant_id=$1"
        + (" FOR SHARE" if lock else ""), tenant_id, conn=conn,
    )
    return rows[0] if rows else {"revision": 0, "prompt": "", "updated_at": None}


def save(st, tenant_id, payload, actor, *, conn=None):
    require(set(payload) == {"revision", "prompt"}, "revision and prompt are required")
    require(type(payload["revision"]) is int and payload["revision"] >= 0, "invalid policy revision")
    prompt = payload["prompt"]
    require(isinstance(prompt, str) and len(prompt) <= MAX_PROMPT_CHARACTERS and "\x00" not in prompt,
            f"policy must be text of at most {MAX_PROMPT_CHARACTERS} characters")
    try:
        prompt.encode("utf-8")
    except UnicodeError:
        require(False, "policy must be valid UTF-8 text")
    with nullcontext(conn) if conn is not None else st.transaction() as conn:
        st.execute(
            "INSERT INTO tenant_company_policies(tenant_id) VALUES($1) ON CONFLICT DO NOTHING",
            tenant_id, conn=conn,
        )
        current = st.one(
            "SELECT revision,prompt,updated_at FROM tenant_company_policies WHERE tenant_id=$1 FOR UPDATE",
            tenant_id, conn=conn,
        )
        require(current["revision"] == payload["revision"], "Company policy changed. Reload before saving.", 409)
        if current["prompt"] == prompt:
            return current
        saved = st.one(
            """UPDATE tenant_company_policies SET prompt=$2,revision=revision+1,
                   updated_at=clock_timestamp() WHERE tenant_id=$1
               RETURNING revision,prompt,updated_at""", tenant_id, prompt, conn=conn,
        )
        st.execute(
            """INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,
                   target_type,target_id,details)
               VALUES($1,$2,$3,$4,$5,'company_policy.update','company_policy',$2,$6)""",
            new_id(), tenant_id, actor.get("type", "user"), actor.get("id", ""), actor.get("name", ""),
            Jsonb({"revision": saved["revision"], "characters": len(prompt)}), conn=conn,
        )
        return saved
