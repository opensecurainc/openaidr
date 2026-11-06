"""Tenant channel notifications collected and delivered outside decision paths."""

import http.client
import json
import re

from cryptography.fernet import Fernet, InvalidToken
from psycopg.types.json import Jsonb

from . import host_metrics
from .httpx import APIError, require
from .store import new_id

WEBHOOK = re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9_-]+")
PUBLIC = "enabled,version,updated_at,(encrypted_webhook<>'') AS configured"


def _cipher(cfg):
    try:
        return Fernet(cfg.slack_webhook_key.encode())
    except (ValueError, TypeError):
        raise APIError(503, "Slack integration requires server setup") from None


def _lock(st, tenant, conn):
    st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "slack:" + tenant, conn=conn)


def read(st, tenant, cfg, conn=None):
    rows = st.many(f"SELECT {PUBLIC} FROM tenant_slack_settings WHERE tenant_id=$1", tenant, conn=conn)
    settings = rows[0] if rows else dict(enabled=False, version=0, updated_at=None, configured=False)
    delivery = st.one("""SELECT count(*) FILTER (WHERE status='pending') AS pending,
        count(*) FILTER (WHERE status='failed') AS failed, max(sent_at) AS last_sent_at
        FROM slack_outbox WHERE tenant_id=$1""", tenant, conn=conn)
    return {**settings, "available": bool(cfg.slack_webhook_key), "delivery": delivery}


def save(st, tenant, data, actor, cfg):
    require(set(data) in ({"enabled", "version"}, {"enabled", "version", "webhook_url"}),
            "enabled and version are required; webhook_url is optional")
    require(type(data["enabled"]) is bool, "enabled must be a boolean")
    require(type(data["version"]) is int and data["version"] >= 0, "invalid version")
    if "webhook_url" in data:
        value = data["webhook_url"]
        require(isinstance(value, str) and len(value) <= 512
                and (value == "" or WEBHOOK.fullmatch(value)), "Provide a Slack incoming webhook URL")
    with st.transaction() as conn:
        _lock(st, tenant, conn)
        rows = st.many("SELECT * FROM tenant_slack_settings WHERE tenant_id=$1 FOR UPDATE", tenant, conn=conn)
        previous = rows[0] if rows else dict(version=0, enabled=False, encrypted_webhook="")
        require(previous["version"] == data["version"], "Slack settings changed. Refresh and try again", 409)
        encrypted = previous["encrypted_webhook"]
        if "webhook_url" in data:
            encrypted = (_cipher(cfg).encrypt(json.dumps([tenant, data["webhook_url"]]).encode()).decode()
                         if data["webhook_url"] else "")
        if data["enabled"]:
            _cipher(cfg)
            require(bool(encrypted), "Provide a webhook before enabling Slack")
        reset = "webhook_url" in data or previous["enabled"] != data["enabled"]
        st.execute("""INSERT INTO tenant_slack_settings(tenant_id,encrypted_webhook,enabled) VALUES($1,$2,$3)
            ON CONFLICT(tenant_id) DO UPDATE SET encrypted_webhook=EXCLUDED.encrypted_webhook,
              enabled=EXCLUDED.enabled,version=tenant_slack_settings.version+1,updated_at=clock_timestamp(),
              next_delivery_at=CASE WHEN $4 THEN clock_timestamp() ELSE tenant_slack_settings.next_delivery_at END,
              enabled_since=CASE WHEN $4 THEN clock_timestamp() ELSE tenant_slack_settings.enabled_since END,
              disk_alerts=CASE WHEN $4 THEN '{}'::jsonb ELSE tenant_slack_settings.disk_alerts END""",
            tenant, encrypted, data["enabled"], reset, conn=conn)
        if reset:
            st.execute("UPDATE slack_outbox SET status='cancelled' WHERE tenant_id=$1 AND status='pending'",
                       tenant, conn=conn)
        st.execute("""INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
            VALUES($1,$2,$3,$4,$5,'slack.configure','slack',$2,$6)""",
            new_id(), tenant, actor.get("type", "user"), actor.get("id", ""), actor.get("name", ""),
            Jsonb({"enabled": data["enabled"], "webhook_changed": "webhook_url" in data,
                   "version": previous["version"] + 1}), conn=conn)
        return read(st, tenant, cfg, conn)


def _message(title, detail, url):
    return {"text": title + "\n" + detail + "\n" + url, "unfurl_links": False, "unfurl_media": False,
            "blocks": [{"type": "section", "text": {"type": "plain_text", "text": title + "\n" + detail}},
                       {"type": "actions", "elements": [{"type": "button", "text": {
                           "type": "plain_text", "text": "Open dashboard"}, "url": url}]}]}


def _enqueue(st, tenant, event_key, message, conn):
    st.execute("""INSERT INTO slack_outbox(id,tenant_id,event_key,message) VALUES($1,$2,$3,$4)
        ON CONFLICT(tenant_id,event_key) DO NOTHING""", new_id(), tenant, event_key, Jsonb(message), conn=conn)


def queue_test(st, tenant, data, actor, cfg):
    require(set(data) == {"version"} and type(data["version"]) is int, "version is required")
    _cipher(cfg)
    with st.transaction() as conn:
        _lock(st, tenant, conn)
        settings = read(st, tenant, cfg, conn)
        require(settings["version"] == data["version"], "Slack settings changed. Refresh and try again", 409)
        require(settings["enabled"], "Enable Slack before sending a test message", 409)
        require(not st.scalar("""SELECT EXISTS(SELECT 1 FROM slack_outbox WHERE tenant_id=$1
            AND event_key LIKE 'test:%' AND created_at>clock_timestamp()-interval '1 minute')""", tenant, conn=conn),
            "Wait one minute before sending another test message", 429)
        ident = new_id()
        _enqueue(st, tenant, "test:" + ident, _message("OpenAIDR Slack test",
                 "Notifications are enabled for detected incidents and low server disk space.",
                 cfg.browser_origin() + "/administration/integrations"), conn)
        st.execute("""INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
            VALUES($1,$2,$3,$4,$5,'slack.test','slack',$2,'{}'::jsonb)""",
            ident, tenant, actor.get("type", "user"), actor.get("id", ""), actor.get("name", ""), conn=conn)
        return {"queued": True}


def _collect_disk(st, tenant, settings, cfg, conn):
    # Local host metrics belong only to a dedicated, tenant-bound deployment.
    if cfg.tenant_id != tenant or not st.scalar(
            "SELECT count(*)=1 AND bool_and(id=$1) FROM tenants", tenant, conn=conn):
        return
    metrics = host_metrics.read_metrics(cfg.host_metrics_path, "1h")
    if metrics["status"] != "ok" or not metrics["samples"]:
        return
    sample = metrics["samples"][-1]
    if sample["time"] != metrics["last_sample_at"]:
        return
    disks = [("data", "Data disk", "disk")]
    if sample.get("disk_is_root") or metrics["disk_path"] == "/":
        disks = [("data", "Server disk", "disk")]
    elif sample.get("disk_is_root") is False and "root_disk_percent" in sample:
        disks.append(("root", "Boot disk", "root_disk"))
    active = dict(settings["disk_alerts"])
    for key, label, prefix in disks:
        percent = sample[prefix + "_percent"]
        available, total = sample.get(prefix + "_available_bytes"), sample.get(prefix + "_total_bytes")
        if available is not None and total:
            # Available space excludes filesystem reserves that the service cannot use.
            percent = max(percent, 100 * (1 - available / total))
        if percent >= 95 and key not in active:
            event_key = "disk:" + key + ":" + new_id()
            detail = f"{label}: {percent:.0f}% full."
            if available is not None:
                detail += f" {available / 1024**3:.1f} GiB available."
            _enqueue(st, tenant, event_key, _message("OpenAIDR: Low disk space", detail,
                     cfg.browser_origin() + "/administration/server"), conn)
            active[key] = event_key
        elif percent < 90 and key in active:
            st.execute("""UPDATE slack_outbox SET status='cancelled'
                WHERE tenant_id=$1 AND event_key=$2 AND status='pending'""",
                tenant, active.pop(key), conn=conn)
    if active != settings["disk_alerts"]:
        st.execute("UPDATE tenant_slack_settings SET disk_alerts=$2 WHERE tenant_id=$1",
                   tenant, Jsonb(active), conn=conn)


def collect(st, cfg):
    """Notify once per completed incident; keep policy activity in the dashboard."""
    for row in st.many("""SELECT s.tenant_id FROM tenant_slack_settings s JOIN tenants t ON t.id=s.tenant_id
                       WHERE s.enabled AND t.status='active' AND ($1::uuid IS NULL OR s.tenant_id=$1)""",
                       cfg.tenant_id or None):
        tenant = row["tenant_id"]
        with st.transaction() as conn:
            settings = st.many("SELECT * FROM tenant_slack_settings WHERE tenant_id=$1 AND enabled FOR UPDATE SKIP LOCKED",
                               tenant, conn=conn)
            if not settings:
                continue
            # Old workers can leave queued findings or digests during rollout.
            st.execute("""UPDATE slack_outbox SET status='cancelled'
                WHERE tenant_id=$1 AND status='pending' AND (event_key LIKE 'finding:%'
                    OR event_key LIKE 'report:%' OR event_key LIKE 'batch:%' OR event_key LIKE 'digest:%')""",
                tenant, conn=conn)
            reports = st.many("""SELECT j.id,counts.total,counts.critical,counts.high
                FROM session_investigation_jobs j
                JOIN LATERAL (SELECT report FROM session_investigation_attempts a
                    WHERE a.job_id=j.id AND a.tenant_id=j.tenant_id ORDER BY ordinal DESC LIMIT 1) a ON true
                JOIN LATERAL (SELECT count(*) AS total,
                    count(*) FILTER (WHERE severity='critical') AS critical,
                    count(*) FILTER (WHERE severity='high') AS high FROM findings f
                    WHERE f.tenant_id=j.tenant_id AND f.investigation_job_id=j.id) counts ON counts.total>0
                WHERE j.tenant_id=$1 AND j.completed_at>=$2 AND j.state='completed'
                  AND a.report->>'status'='finding'
                  AND NOT EXISTS(SELECT 1 FROM slack_outbox o WHERE o.tenant_id=$1
                    AND o.event_key='incident:'||j.id::text)
                  AND NOT EXISTS(SELECT 1 FROM slack_outbox o LEFT JOIN slack_outbox b ON b.id=o.batch_id
                    WHERE o.tenant_id=$1 AND o.event_key='report:'||j.id::text
                    AND (o.attempts>0 OR o.status IN ('sent','failed')
                         OR b.attempts>0 OR b.status IN ('sent','failed')))
                ORDER BY j.completed_at,j.id LIMIT 100""", tenant, settings[0]["enabled_since"], conn=conn)
            for report in reports:
                count = report["total"]
                detail = f"{count} finding{'s' if count != 1 else ''}."
                if report["critical"] or report["high"]:
                    detail += f" {report['critical']} critical, {report['high']} high."
                _enqueue(st, tenant, "incident:" + report["id"], _message(
                    "OpenAIDR: Incident detected", detail,
                    cfg.browser_origin() + "/detections/reports/" + report["id"]), conn)
            _collect_disk(st, tenant, settings[0], cfg, conn)


class DeliveryError(Exception):
    def __init__(self, code, retryable=True, retry_after=0):
        super().__init__(code)
        self.retryable = retryable
        self.retry_after = retry_after


def send(url, message):
    # http.client avoids HTTP client request logging, which would expose this secret URL.
    # The fixed host, default TLS verification and no redirects/proxies bound the destination.
    if not WEBHOOK.fullmatch(url):
        raise DeliveryError("credentials_unavailable", False)
    connection = http.client.HTTPSConnection("hooks.slack.com", timeout=5)
    try:
        connection.request("POST", url.removeprefix("https://hooks.slack.com"),
                           body=json.dumps(message).encode(), headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        body = response.read(128)
        if response.status == 200 and body.strip() == b"ok":
            return
        if response.status == 429:
            delay = response.getheader("Retry-After", "60")
            seconds = int(delay) if re.fullmatch(r"[0-9]{1,8}", delay) else 60
            raise DeliveryError("rate_limited", retry_after=max(1, seconds))
        raise DeliveryError("provider_unavailable" if response.status >= 500 else "webhook_rejected",
                            response.status >= 500)
    except (OSError, http.client.HTTPException):
        raise DeliveryError("provider_unavailable") from None
    finally:
        connection.close()


def dispatch_one(st, cfg):
    with st.transaction() as conn:
        # Lock the destination through delivery so disable/replacement cannot race a stale send.
        settings = st.many("""SELECT s.* FROM tenant_slack_settings s JOIN tenants t ON t.id=s.tenant_id
            WHERE s.enabled AND t.status='active'
            AND ($1::uuid IS NULL OR s.tenant_id=$1) AND s.next_delivery_at<=clock_timestamp()
            AND EXISTS(SELECT 1 FROM slack_outbox o WHERE o.tenant_id=s.tenant_id
                       AND o.status='pending' AND o.next_attempt_at<=clock_timestamp()
                       AND (o.event_key LIKE 'incident:%' OR o.event_key LIKE 'disk:%' OR o.event_key LIKE 'test:%'))
            ORDER BY s.next_delivery_at,s.tenant_id LIMIT 1 FOR UPDATE OF s SKIP LOCKED""", cfg.tenant_id or None, conn=conn)
        if not settings:
            return False
        setting = settings[0]
        row = st.one("""SELECT * FROM slack_outbox WHERE tenant_id=$1 AND status='pending'
            AND (event_key LIKE 'incident:%' OR event_key LIKE 'disk:%' OR event_key LIKE 'test:%')
            AND next_attempt_at<=clock_timestamp() ORDER BY next_attempt_at,id LIMIT 1 FOR UPDATE""",
            setting["tenant_id"], conn=conn)
        attempts, delay = row["attempts"] + 1, 1
        try:
            try:
                tenant, url = json.loads(_cipher(cfg).decrypt(setting["encrypted_webhook"].encode()))
                if tenant != setting["tenant_id"] or not isinstance(url, str):
                    raise ValueError("credential binding")
            except (InvalidToken, ValueError, TypeError, APIError):
                raise DeliveryError("credentials_unavailable", False) from None
            send(url, row["message"])
        except DeliveryError as exc:
            delay = min(24 * 60 * 60, max(exc.retry_after, min(3600, 30 * 2 ** min(attempts - 1, 7))))
            st.execute("""UPDATE slack_outbox SET attempts=$2,status=$3,error_code=$4,
                next_attempt_at=clock_timestamp()+make_interval(secs=>$5) WHERE id=$1""",
                row["id"], attempts, "pending" if exc.retryable and attempts < 8 else "failed", str(exc), delay, conn=conn)
        else:
            st.execute("UPDATE slack_outbox SET status='sent',attempts=$2,sent_at=clock_timestamp(),error_code='' WHERE id=$1",
                       row["id"], attempts, conn=conn)
        st.execute("UPDATE tenant_slack_settings SET next_delivery_at=clock_timestamp()+make_interval(secs=>$2) WHERE tenant_id=$1",
                   setting["tenant_id"], delay, conn=conn)
    return True
