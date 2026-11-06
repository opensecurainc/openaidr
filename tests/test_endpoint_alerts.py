"""Alert creation, isolation, and receipt transitions against real PostgreSQL."""

from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from openaidr.server import endpoint_alerts
from openaidr.server.auth import CONSOLE_COOKIE
from test_app_inventory_server import inventory  # noqa: F401

API = "/api/v1/endpoint-alerts"
INBOX = "/ingest/v1/alerts"


def sender(st, client, sensor, role="analyst"):
    user = st.create_user(sensor["tenant_id"], f"{uuid4()}@example.com", "Security team", "unused", role)
    client.cookies.set(CONSOLE_COOKIE, st.create_session(user["id"], sensor["tenant_id"]))
    return {"id": user["id"], "name": user["name"]}


def message(sensor, **changes):
    return {"request_id": str(uuid4()), "application_id": "litellm", "sensor_ids": [sensor["id"]],
            "title": "Upgrade LiteLLM", "message": "Use your project's Python environment.",
            "command": 'python -m pip install --upgrade "litellm==1.106.2"',
            "installed_version": "1.105.0", "required_version": "1.106.2", **changes}


def test_send_receive_acknowledge_isolation_and_permissions(inventory):
    st, cfg, client, identities = inventory
    sensor, token, session = identities[0]
    other, other_token, other_session = identities[1]
    headers = {"Authorization": "Bearer " + token}
    other_headers = {"Authorization": "Bearer " + other_token}
    client.headers["X-OpenAIDR-CSRF"] = "1"
    payload = message(sensor)
    assert client.post(API, json=payload).status_code == 403  # Leadership can read, not send.
    sender(st, client, sensor)
    assert client.post(API, json=payload, headers={"X-OpenAIDR-CSRF": ""}).status_code == 403
    assert client.post(API, json={**payload, "sender_name": "Forged"}).status_code == 400
    assert client.post(API, json={**payload, "sensor_ids": [sensor["id"], other["id"]]}).status_code == 404
    assert st.scalar("SELECT count(*) FROM endpoint_alerts") == 0
    sent = client.post(API, json=payload)
    assert sent.status_code == 201, sent.text
    alert = sent.json()
    assert alert["sender_name"] == "Security team"
    assert alert["command"] == payload["command"]
    assert client.post(API, json=payload).json()["id"] == alert["id"]
    assert client.post(API, json={**payload, "message": "changed"}).status_code == 409
    assert st.scalar("SELECT count(*) FROM audit_log WHERE action='endpoint_alert.send'") == 1
    assert client.get(API).json()["items"][0]["received_count"] == 0
    assert client.post(INBOX, json={}).status_code == 401
    assert client.post(INBOX, json={"sensor_id": other["id"]}, headers=headers).status_code == 400
    result = client.post(INBOX, json={}, headers=headers)
    assert result.headers["cache-control"] == "no-store"
    assert result.json()["items"][0]["received_at"] is None  # A response is not a receipt.
    assert client.post(INBOX, json={}, headers=other_headers).json()["items"] == []
    receipt = INBOX + "/received"
    ack = INBOX + "/" + alert["id"] + "/acknowledge"
    assert client.post(ack, json={}, headers=other_headers).status_code == 404
    assert client.post(receipt, json={"ids": [alert["id"], str(uuid4())]}, headers=headers).status_code == 404
    assert client.get(API).json()["items"][0]["received_count"] == 0
    received = client.post(receipt, json={"ids": [alert["id"]]}, headers=headers).json()
    assert received["items"][0]["acknowledged_at"] is None
    assert client.post(receipt, json={"ids": [alert["id"]]}, headers=headers).json() == received
    acknowledged = client.post(ack, json={}, headers=headers).json()
    assert acknowledged["items"][0]["acknowledged_at"]
    assert client.post(ack, json={}, headers=headers).json() == acknowledged
    assert client.post(receipt, json={"ids": [alert["id"]]}, headers=headers).json() == acknowledged
    assert client.get(API + "/" + alert["id"]).json()["recipients"][0]["acknowledged_at"]
    summary = client.get(API, params={"application_id": "litellm"}).json()["items"][0]
    assert (summary["device_count"], summary["received_count"], summary["acknowledged_count"]) == (1, 1, 1)
    assert client.get(API, params={"application_id": "other"}).json()["items"] == []
    client.cookies.set(CONSOLE_COOKIE, other_session)
    assert client.get(API).json()["items"] == []
    assert client.get(API + "/" + alert["id"]).status_code == 404
    client.cookies.set(CONSOLE_COOKIE, session)
    assert client.get(API).status_code == 200
    sender(st, client, sensor, "admin")
    assert client.post(API, json=message(sensor)).status_code == 201
    st.update_sensor(sensor["tenant_id"], sensor["id"], disabled=True)
    assert client.post(API, json=message(sensor)).status_code == 404
    assert client.post(INBOX, json={}, headers=headers).status_code == 403
    assert client.post(ack, json={}, headers=headers).status_code == 403
    cfg.tenant_id = sensor["tenant_id"]
    assert client.post(INBOX, json={}, headers=other_headers).status_code == 403


def test_concurrent_retry_expiry_bounds_and_validation(inventory):
    st, _, client, identities = inventory
    sensor, token, _ = identities[0]
    actor = sender(st, client, sensor)
    client.headers["X-OpenAIDR-CSRF"] = "1"
    payload = message(sensor)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: endpoint_alerts.create(st, sensor["tenant_id"], payload, actor), range(2)))
    assert sorted(created for _, created in results) == [False, True]
    assert len({row["id"] for row, _ in results}) == 1
    for invalid in ({"title": " "}, {"message": "x" * 2001}, {"command": "x\x00"},
                    {"sensor_ids": []}, {"sensor_ids": [sensor["id"], sensor["id"].upper()]},
                    {"sensor_ids": [None]}, {"required_version": ""}, {"request_id": 12}):
        assert client.post(API, json={**message(sensor), **invalid}).status_code == 400, invalid
    headers = {"Authorization": "Bearer " + token}
    st.execute("UPDATE endpoint_alerts SET expires_at=now()-interval '1 second'")
    assert client.post(INBOX, json={}, headers=headers).json()["items"] == []
    assert client.get(API).json()["items"][0]["expired"] is True
    assert client.post(INBOX + "/received", json={"ids": [results[0][0]["id"]]}, headers=headers).status_code == 404
    acknowledged = []
    for index in range(25):
        row, _ = endpoint_alerts.create(st, sensor["tenant_id"], message(sensor), actor)
        endpoint_alerts.receipt(st, sensor, [row["id"]], acknowledge=True)
        st.execute("UPDATE endpoint_alert_receipts SET acknowledged_at=now()-interval '1 day'+$2*interval '1 second' WHERE alert_id=$1",
                   row["id"], index)
        acknowledged.append(row["id"])
    for _ in range(100):
        endpoint_alerts.create(st, sensor["tenant_id"], message(sensor), actor)
    assert client.post(API, json=message(sensor)).status_code == 409
    inbox = client.post(INBOX, json={}, headers=headers).json()["items"]
    assert len(inbox) == 120
    assert all(item["acknowledged_at"] is None for item in inbox[:100])
    assert [item["id"] for item in inbox[100:]] == list(reversed(acknowledged[-20:]))
    first = client.get(API).json()
    second = client.get(API, params={"offset": 50}).json()
    assert len(first["items"]) == 50 and first["has_more"] and second["has_more"]
    assert not {row["id"] for row in first["items"]} & {row["id"] for row in second["items"]}
    assert client.get(API, params={"offset": -1}).status_code == 400
