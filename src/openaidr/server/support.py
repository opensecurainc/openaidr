"""Tenant support links, independent of Slack notification credentials."""

import re
from urllib.parse import parse_qs, urlencode, urlsplit

from psycopg.types.json import Jsonb

from .httpx import APIError, require
from .store import new_id


LINK_ERROR = "Paste an HTTPS Slack channel link, or leave it blank to remove it."


def channel_url(value):
    require(isinstance(value, str) and len(value) <= 2048, LINK_ERROR)
    value = value.strip()
    if not value:
        return ""
    require(not re.search(r"[\s\\\x00-\x1f\x7f]", value), LINK_ERROR)
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise APIError(400, LINK_ERROR) from None
    host = parsed.hostname or ""
    require(parsed.scheme == "https" and parsed.netloc.lower() == host, LINK_ERROR)
    if host == "app.slack.com" and re.fullmatch(r"/client/[TE][A-Z0-9]+/[CG][A-Z0-9]+/?", parsed.path):
        return "https://app.slack.com" + parsed.path.rstrip("/")
    if (host not in ("app.slack.com", "hooks.slack.com", "api.slack.com")
            and re.fullmatch(r"[a-z0-9][a-z0-9-]*\.slack\.com", host)
            and re.fullmatch(r"/archives/[CG][A-Z0-9]+/?", parsed.path)):
        return "https://" + host + parsed.path.rstrip("/")
    if host == "slack.com" and parsed.path == "/app_redirect":
        query = parse_qs(parsed.query, keep_blank_values=True)
        require(set(query) == {"team", "channel"} and all(len(values) == 1 for values in query.values()), LINK_ERROR)
        team, channel = query["team"][0], query["channel"][0]
        require(re.fullmatch(r"[TE][A-Z0-9]+", team) and re.fullmatch(r"[CG][A-Z0-9]+", channel), LINK_ERROR)
        return "https://slack.com/app_redirect?" + urlencode({"team": team, "channel": channel})
    raise APIError(400, LINK_ERROR)


def read(st, tenant_id, conn=None):
    rows = st.many("SELECT slack_channel_url,version,updated_at FROM tenant_support_settings WHERE tenant_id=$1",
                   tenant_id, conn=conn)
    return rows[0] if rows else {"slack_channel_url": "", "version": 0, "updated_at": None}


def save(st, tenant_id, payload, actor):
    require(set(payload) == {"slack_channel_url", "version"}, "slack_channel_url and version are required")
    require(type(payload["version"]) is int and payload["version"] >= 0, "invalid version")
    url = channel_url(payload["slack_channel_url"])
    with st.transaction() as conn:
        st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "support-settings:" + tenant_id, conn=conn)
        current = read(st, tenant_id, conn)
        require(current["version"] == payload["version"], "Support settings changed. Refresh and try again.", 409)
        updated = st.one("""INSERT INTO tenant_support_settings(tenant_id,slack_channel_url) VALUES($1,$2)
            ON CONFLICT(tenant_id) DO UPDATE SET slack_channel_url=EXCLUDED.slack_channel_url,
                version=tenant_support_settings.version+1,updated_at=clock_timestamp()
            RETURNING slack_channel_url,version,updated_at""", tenant_id, url, conn=conn)
        st.execute("""INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,
            target_type,target_id,details) VALUES($1,$2,$3,$4,$5,'support.configure','support',$2,$6)""",
            new_id(), tenant_id, actor.get("type", "user"), actor.get("id", ""), actor.get("name", ""),
            Jsonb({"before": current["slack_channel_url"], "slack_channel_url": url, "version": updated["version"]}),
            conn=conn)
    return updated
