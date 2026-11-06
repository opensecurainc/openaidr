"""Verified investigation identities and bounded, revocable history authority."""

from datetime import timedelta

from psycopg.types.json import Jsonb

from . import session_ownership
from .httpx import require
from .store import NotFound, new_id, valid_uuid


def bounds(job):
    """A job's context window never moves when a model asks for another page."""
    end = job["created_at"]
    return end - timedelta(days=job["configuration"].get("history_days", 7)), end


def owner(st, tenant_id, session_id, conn=None):
    rows = st.many(
        """SELECT i.owner_user_id,i.verified_at,u.name,u.email FROM detection_session_identities i
           JOIN tenant_users u ON u.id=i.owner_user_id AND u.tenant_id=i.tenant_id AND u.status='active'
           WHERE i.tenant_id=$1 AND i.session_id=$2""", tenant_id, session_id, conn=conn,
    )
    return rows[0] if rows else None


def read_owner(st, tenant_id, session_id):
    require(valid_uuid(session_id), "invalid session id")
    session = st.one("SELECT id,registration_id FROM agent_sessions WHERE tenant_id=$1 AND id=$2", tenant_id, session_id)
    bindings = st.many("SELECT revoked_at FROM session_detection_owners WHERE tenant_id=$1 AND session_id=$2", tenant_id, session_id)
    identity = owner(st, tenant_id, session_id)
    status = "managed" if session["registration_id"] else "revoked" if bindings and not identity else "verified" if identity else "unassigned"
    return {"session_id": session_id, "owner": identity, "status": status,
            "assignable": status == "unassigned", "revoked_at": bindings[0]["revoked_at"] if bindings else None}


def save_owner(st, tenant_id, session_id, owner_user_id, actor):
    """The caller must have the Security Analyst role. Never derive identity from evidence."""
    require(valid_uuid(session_id), "invalid session id")
    require(owner_user_id is None or valid_uuid(owner_user_id), "invalid owner_user_id")
    with st.transaction() as conn:
        session = st.one(
            "SELECT * FROM agent_sessions WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
            tenant_id, session_id, conn=conn,
        )
        require(session["registration_id"] is None, "registered ownership cannot be reassigned", 409)
        st.one("SELECT id FROM tenant_users WHERE tenant_id=$1 AND id=$2 AND status='active' AND 'security_analyst'=ANY(roles) FOR SHARE",
               tenant_id, actor.get("id"), conn=conn)
        session_ownership._active_sensor(st, {"tenant_id": tenant_id, "id": session["sensor_id"]}, conn)
        prior = st.many("SELECT * FROM session_detection_owners WHERE session_id=$1 FOR UPDATE", session_id, conn=conn)
        if owner_user_id is not None:
            st.one("SELECT id FROM tenant_users WHERE tenant_id=$1 AND id=$2 AND status='active' FOR SHARE",
                   tenant_id, owner_user_id, conn=conn)
            require(not prior or (prior[0]["owner_user_id"] == owner_user_id and prior[0]["revoked_at"] is None),
                    "session ownership is immutable; revoked bindings cannot be reused", 409)
            st.execute(
                """INSERT INTO session_detection_owners(session_id,tenant_id,owner_user_id,verified_by_user_id)
                   VALUES($1,$2,$3,$4) ON CONFLICT(session_id) DO NOTHING""",
                session_id, tenant_id, owner_user_id, actor["id"], conn=conn,
            )
        else:
            st.execute("UPDATE session_detection_owners SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND session_id=$2 AND revoked_at IS NULL",
                       tenant_id, session_id, conn=conn)
        st.execute("INSERT INTO ordinary_session_input_dirty(tenant_id,session_id) VALUES($1,$2)", tenant_id, session_id, conn=conn)
        st.execute(
            """INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
               VALUES($1,$2,'user',$3,$4,$5,'session',$6,$7)""",
            new_id(), tenant_id, actor["id"], actor.get("name", ""),
            "session-detection.owner-verify" if owner_user_id else "session-detection.owner-revoke",
            session_id, Jsonb({"owner_user_id": owner_user_id}), conn=conn,
        )
    return read_owner(st, tenant_id, session_id)


def authorize(st, job, session_id, conn, *, window=True):
    if not job.get("owner_user_id"):
        raise NotFound()
    rows = st.many(
        """SELECT s.*,i.owner_user_id,i.verified_at FROM agent_sessions s
           JOIN detection_session_identities i ON i.session_id=s.id AND i.tenant_id=s.tenant_id
           WHERE s.tenant_id=$1 AND s.id=$2 AND i.owner_user_id=$3""",
        job["tenant_id"], session_id, job["owner_user_id"], conn=conn,
    )
    if not rows:
        raise NotFound()
    row = rows[0]
    if window:
        start, end = bounds(job)
        if row["last_event_at"] < start or row["started_at"] > end:
            raise NotFound()
    session_ownership._active_sensor(st, {"tenant_id": job["tenant_id"], "id": row["sensor_id"]}, conn)
    st.one("SELECT id FROM tenant_users WHERE tenant_id=$1 AND id=$2 AND status='active' FOR SHARE",
           job["tenant_id"], job["owner_user_id"], conn=conn)
    if row["registration_id"]:
        st.one("SELECT id FROM session_registrations WHERE tenant_id=$1 AND id=$2 AND owner_user_id=$3 AND verified_at IS NOT NULL FOR SHARE",
               job["tenant_id"], row["registration_id"], job["owner_user_id"], conn=conn)
    else:
        st.one("SELECT session_id FROM session_detection_owners WHERE tenant_id=$1 AND session_id=$2 AND owner_user_id=$3 AND revoked_at IS NULL FOR SHARE",
               job["tenant_id"], session_id, job["owner_user_id"], conn=conn)
    return row
