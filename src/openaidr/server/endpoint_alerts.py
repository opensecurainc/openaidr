"""Manual, tenant-scoped device messages. Instructions are never executed."""

from uuid import UUID

from psycopg.types.json import Jsonb

from .httpx import require, uuid_param
from .session_ownership import _active_sensor
from .store import NotFound, new_id

TEXT_LIMITS = {"title": 160, "message": 2000, "command": 2000,
               "installed_version": 100, "required_version": 100}


def text(value, name, limit, *, required=False):
    require(isinstance(value, str) and len(value) <= limit
            and not any(ord(char) < 32 and char not in "\n\t" for char in value),
            f"invalid {name}")
    require(not required or bool(value.strip()), f"{name} is required")
    return value.strip()


def ids(value):
    require(isinstance(value, list) and 1 <= len(value) <= 100, "select 1 to 100 devices")
    result = [str(UUID(uuid_param(item, "device id"))) for item in value]
    require(len(set(result)) == len(result), "duplicate device id")
    return sorted(result)


def public(row):
    return {key: value for key, value in row.items() if key not in
            ("content", "request_id", "sensor_ids", "tenant_id", "sender_id")} | row["content"]


def create(st, tenant, data, actor):
    require(set(data) <= {*TEXT_LIMITS, "application_id", "sensor_ids", "request_id"}, "unknown alert field")
    request_id = uuid_param(data.get("request_id"), "request id")
    recipients = ids(data.get("sensor_ids"))
    application = text(data.get("application_id", ""), "application id", 256, required=True)
    content = {key: text(data.get(key, ""), key, limit, required=key in ("title", "message"))
               for key, limit in TEXT_LIMITS.items()}
    require(bool(content["installed_version"]) == bool(content["required_version"]),
            "provide both installed and required versions, or neither")
    with st.transaction() as conn:
        # Serialize sends per tenant so retries and concurrent backlog checks are atomic.
        st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "endpoint-alert:" + tenant, conn=conn)
        prior = st.many("SELECT * FROM endpoint_alerts WHERE tenant_id=$1 AND request_id=$2",
                        tenant, request_id, conn=conn)
        if prior:
            row = prior[0]
            require(row["content"] == content and row["sensor_ids"] == recipients
                    and row["application_id"] == application and row["sender_id"] == actor["id"],
                    "request id already used for another alert", 409)
            return public(row), False
        targets = st.many("""SELECT id FROM sensors WHERE tenant_id=$1 AND id=ANY($2::uuid[])
                            AND NOT disabled AND deleted_at IS NULL ORDER BY id FOR SHARE""",
                          tenant, recipients, conn=conn)
        require(len(targets) == len(recipients), "one or more devices are unavailable", 404)
        full = st.many("""SELECT r.sensor_id FROM endpoint_alert_receipts r
                           JOIN endpoint_alerts a ON a.tenant_id=r.tenant_id AND a.id=r.alert_id
                           WHERE r.tenant_id=$1 AND r.sensor_id=ANY($2::uuid[])
                             AND r.acknowledged_at IS NULL AND a.expires_at>now()
                           GROUP BY r.sensor_id HAVING count(*)>=100""", tenant, recipients, conn=conn)
        require(not full, "a device already has 100 unacknowledged alerts", 409)
        row = st.one("""INSERT INTO endpoint_alerts
                        (id,tenant_id,request_id,application_id,content,sensor_ids,sender_id,sender_name)
                        VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *""",
                     new_id(), tenant, request_id, application, Jsonb(content), Jsonb(recipients),
                     actor["id"], actor["name"], conn=conn)
        st.execute("""INSERT INTO endpoint_alert_receipts(tenant_id,alert_id,sensor_id)
                      SELECT $1,$2,unnest($3::uuid[])""", tenant, row["id"], recipients, conn=conn)
        st.execute("""INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
                      VALUES($1,$2,'user',$3,$4,'endpoint_alert.send','endpoint_alert',$5,$6)""",
                   new_id(), tenant, actor["id"], actor["name"], row["id"],
                   Jsonb({"application_id": application, "device_count": len(recipients)}), conn=conn)
    return public(row), True


def listing(st, tenant, query):
    application = text(query.get("application_id", ""), "application id", 256)
    try:
        offset = int(query.get("offset", "0"))
    except ValueError:
        offset = -1
    require(0 <= offset <= 1_000_000, "invalid offset")
    rows = st.many("""SELECT a.*,count(r.sensor_id) AS device_count,
                      count(r.received_at) AS received_count,count(r.acknowledged_at) AS acknowledged_count,
                      a.expires_at<=now() AS expired
                      FROM endpoint_alerts a LEFT JOIN endpoint_alert_receipts r
                      ON r.tenant_id=a.tenant_id AND r.alert_id=a.id
                      WHERE a.tenant_id=$1 AND ($2='' OR a.application_id=$2)
                      GROUP BY a.id ORDER BY a.created_at DESC,a.id DESC LIMIT 51 OFFSET $3""",
                   tenant, application, offset)
    return {"items": [public(row) for row in rows[:50]], "has_more": len(rows)>50}


def detail(st, tenant, ident):
    row = st.one("SELECT * FROM endpoint_alerts WHERE tenant_id=$1 AND id=$2", tenant, ident)
    recipients = st.many("""SELECT r.sensor_id,s.hostname,r.received_at,r.acknowledged_at,
                           s.disabled,s.deleted_at FROM endpoint_alert_receipts r
                           JOIN sensors s ON s.id=r.sensor_id AND s.tenant_id=r.tenant_id
                           WHERE r.tenant_id=$1 AND r.alert_id=$2 ORDER BY s.hostname,s.id""", tenant, ident)
    return public(row) | {"recipients": recipients}


def inbox(st, sensor):
    with st.transaction() as conn:
        _active_sensor(st, sensor, conn)
        rows = st.many("""SELECT a.*,r.received_at,r.acknowledged_at FROM endpoint_alert_receipts r
                          JOIN endpoint_alerts a ON a.tenant_id=r.tenant_id AND a.id=r.alert_id
                          WHERE r.tenant_id=$1 AND r.sensor_id=$2 AND a.expires_at>now()
                          ORDER BY r.acknowledged_at DESC NULLS FIRST,a.created_at DESC,a.id DESC LIMIT 120""",
                       sensor["tenant_id"], sensor["id"], conn=conn)
    return {"items": [public(row) for row in rows]}


def receipt(st, sensor, alert_ids, *, acknowledge=False):
    with st.transaction() as conn:
        _active_sensor(st, sensor, conn)
        rows = st.many("""SELECT r.alert_id FROM endpoint_alert_receipts r
                          JOIN endpoint_alerts a ON a.tenant_id=r.tenant_id AND a.id=r.alert_id
                          WHERE r.tenant_id=$1 AND r.sensor_id=$2 AND r.alert_id=ANY($3::uuid[])
                            AND a.expires_at>now() FOR UPDATE OF r""",
                       sensor["tenant_id"], sensor["id"], alert_ids, conn=conn)
        if len(rows) != len(alert_ids):
            raise NotFound("alert")
        result = st.many("""UPDATE endpoint_alert_receipts SET received_at=coalesce(received_at,now()),
                            acknowledged_at=CASE WHEN $4 THEN coalesce(acknowledged_at,now()) ELSE acknowledged_at END
                            WHERE tenant_id=$1 AND sensor_id=$2 AND alert_id=ANY($3::uuid[])
                            RETURNING alert_id,received_at,acknowledged_at""",
                         sensor["tenant_id"], sensor["id"], alert_ids, acknowledge, conn=conn)
    return {"items": result}
