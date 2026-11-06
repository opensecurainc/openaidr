"""Bounded desktop alert transport using the enrolled sensor's TLS identity."""

from datetime import datetime
from uuid import UUID

import httpx

from .config import Config, configuration_lock
from .runtime import Client, NOT_ENROLLED
from .usage import identity


def alert_id(value):
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Invalid alert ID.") from None


def inbox_items(result):
    rows = result.get("items") if isinstance(result, dict) else None
    if not isinstance(rows, list) or len(rows) > 120:
        raise ValueError("Invalid alert inbox response.")
    items = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Invalid alert inbox response.")
        item = {"id": alert_id(row.get("id"))}
        for key, maximum in {"title": 160, "message": 2000, "command": 2000,
                             "installed_version": 100, "required_version": 100,
                             "sender_name": 1024}.items():
            value = row.get(key, "")
            if not isinstance(value, str) or len(value) > maximum:
                raise ValueError("Invalid alert inbox response.")
            item[key] = value
        for key in ("created_at", "expires_at", "received_at", "acknowledged_at"):
            value = row.get(key)
            if value is None and key in ("received_at", "acknowledged_at"):
                item[key] = None
                continue
            try:
                if not isinstance(value, str) or datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is None:
                    raise ValueError()
            except ValueError:
                raise ValueError("Invalid alert inbox timestamp.") from None
            item[key] = value
        items.append(item)
    return items


def exchange(config, action, params):
    # Keep a receipt tied to the exact enrollment from which its inbox was read.
    with configuration_lock(config.path):
        config = Config.load(config.path)
        if not config.enrolled():
            raise ValueError(NOT_ENROLLED)
        scope = identity(config)
        path, data = "alerts", {}
        if action != "alerts.list":
            if params.get("scope") != scope:
                raise ValueError("Organization connection changed. Refresh alerts.")
            if action == "alerts.received":
                values = params.get("ids")
                if not isinstance(values, list) or not 1 <= len(values) <= 100:
                    raise ValueError("Choose 1 to 100 alert IDs.")
                values = [alert_id(value) for value in values]
                if len(values) != len(set(values)):
                    raise ValueError("Duplicate alert ID.")
                path, data = "alerts/received", {"ids": values}
            elif action == "alerts.acknowledge":
                path = "alerts/" + alert_id(params.get("id")) + "/acknowledge"
            else:
                raise ValueError("Unsupported alert action.")
        client = Client.from_config(config)
        try:
            result = client.post(path, data, timeout=5)
        except httpx.HTTPStatusError as exc:
            if action == "alerts.list" and exc.response.status_code == 404:
                return {"supported": False, "scope": scope, "items": []}
            raise ValueError("Could not update alerts. Check your organization connection and try again.") from None
        except httpx.HTTPError:
            raise ValueError("Could not connect to your organization. Try again.") from None
        finally:
            client.close()
        return {"supported": True, "scope": scope, "sensor_id": config["sensor_id"],
                "server_url": config["server_url"].rstrip("/"),
                "items": inbox_items(result) if action == "alerts.list" else result.get("items", [])}
