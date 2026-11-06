"""Customer scan controls without converting retained provider budgets."""

import time

from . import service_skill_worker, skill_llm
from .httpx import require


def read(st, tenant, cfg, buffer):
    service_skill_worker.contracts()
    rows = st.many("SELECT mode,updated_at FROM tenant_skill_llm_settings WHERE tenant_id=$1", tenant)
    settings = rows[0] if rows else {"mode": "off", "updated_at": None}
    jobs = st.one("""SELECT count(*) FILTER (WHERE status='pending')::int AS pending,
        count(*) FILTER (WHERE status='running')::int AS running,
        count(*) FILTER (WHERE status='complete')::int AS completed,
        count(*) FILTER (WHERE status='failed')::int AS failed FROM skill_llm_jobs WHERE tenant_id=$1""", tenant)
    with buffer.lock:
        available = bool(cfg.tenant_id == tenant and cfg.skill_scanner_token
            and getattr(buffer, "llm_protocol", None) == service_skill_worker.PROTOCOL
            and getattr(buffer, "llm_profile", None)
            and time.monotonic() - getattr(buffer, "llm_seen", 0) < 720)
    return {**settings, **jobs, "pilot_size": skill_llm.PILOT_SIZE, "worker_available": available,
            "key_configured": bool(skill_llm.model_connection(cfg, tenant, st)), "budget_blocked": False}


def save(st, tenant, cfg, buffer, data, actor):
    service_skill_worker.contracts()
    require(isinstance(data, dict) and set(data) == {"mode"}, "provide a scan mode")
    mode = data["mode"]
    require(mode in ("off", "pilot", "automatic"), "invalid scan mode")
    with buffer.lock:
        if mode != "off":
            current = read(st, tenant, cfg, buffer)
            require(current["worker_available"], "Update or start the skill scanner before enabling model analysis.", 409)
            require(current["key_configured"], "Configure the tenant Intelligence service connection first.", 409)
        with st.transaction() as conn:
            st.execute("INSERT INTO tenant_skill_llm_settings(tenant_id) VALUES($1) ON CONFLICT DO NOTHING", tenant, conn=conn)
            previous = st.one("SELECT mode FROM tenant_skill_llm_settings WHERE tenant_id=$1 FOR UPDATE", tenant, conn=conn)
            st.execute("UPDATE tenant_skill_llm_settings SET mode=$2,updated_at=now() WHERE tenant_id=$1", tenant, mode, conn=conn)
            if mode == "pilot":
                # A new pilot can cancel unstarted work for this profile, but
                # never an accepted lease, prior attempt or retained profile.
                if previous["mode"] != "pilot":
                    st.execute("DELETE FROM skill_llm_jobs WHERE tenant_id=$1 AND profile=$2 "
                               "AND status='pending' AND lease_id IS NULL", tenant, buffer.llm_profile, conn=conn)
                pending = st.scalar("SELECT count(*) FROM skill_llm_jobs WHERE tenant_id=$1 AND profile=$2 "
                                    "AND status IN ('pending','running')", tenant, buffer.llm_profile, conn=conn)
                if not pending:
                    skill_llm.schedule(st, tenant, buffer.llm_profile, limit=skill_llm.PILOT_SIZE, conn=conn)
                require(st.scalar("SELECT count(*) FROM skill_llm_jobs WHERE tenant_id=$1 AND profile=$2 "
                                  "AND status IN ('pending','running')", tenant, buffer.llm_profile, conn=conn),
                        "No eligible collected bundles. Wait for a sensor upload or select automatic scanning.", 409)
    st.audit(tenant, actor, "skill_scanning.llm.configure", "skill_scanning", tenant, {"mode": mode})
    return read(st, tenant, cfg, buffer)


def expire(st, tenant, profile):
    service_skill_worker.contracts()
    with st.transaction() as conn:
        rows = st.many("""SELECT id,sha256 FROM skill_llm_jobs WHERE tenant_id=$1 AND profile=$2
            AND status='running' AND lease_until<=clock_timestamp()""", tenant, profile, conn=conn)
        st.many("""SELECT sha256 FROM skill_bundles WHERE tenant_id=$1 AND sha256=ANY($2::text[])
            ORDER BY sha256 FOR UPDATE""", tenant, [row["sha256"] for row in rows], conn=conn)
        # Reservation locks the bundle first. Read intents after acquiring that
        # lock, so a waiting expiry cannot miss a just-committed dispatch.
        st.execute("""UPDATE skill_llm_jobs j SET status='failed',completed_at=clock_timestamp()
            WHERE j.tenant_id=$1 AND j.id=ANY($2::uuid[]) AND j.status='running' AND j.lease_until<=clock_timestamp()
            AND NOT EXISTS(SELECT 1 FROM service_call_intents i WHERE i.tenant_id=j.tenant_id
                AND i.service='skill_assessment' AND i.scope_id=j.lease_id
                AND i.outcome IS DISTINCT FROM 'failed')""", tenant, [row["id"] for row in rows], conn=conn)
