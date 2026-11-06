"""Read the connected device's posture without changing its collection scope."""

import httpx

from .config import Config, configuration_lock
from .runtime import Client, NOT_ENROLLED
from .usage import identity as enrollment_identity


def read(config):
    with configuration_lock(config.path):
        config = Config.load(config.path)
        if not config.enrolled():
            raise ValueError(NOT_ENROLLED)
        identity = dict(sensor_id=config["sensor_id"], server_url=config["server_url"].rstrip("/"),
                        scope=enrollment_identity(config))
        if config.get("connection_mode") in ("free", "api_key"):
            from .local_posture import read as local_read

            return {**local_read(config), **identity, "supported": True}
        client = Client.from_config(config)
        try:
            result = client.post("posture/summary", {}, timeout=5)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return dict(supported=False, reason="server_unavailable", **identity)
            raise ValueError("Could not read device posture. Check your organization connection.") from None
        except (httpx.HTTPError, ValueError):
            raise ValueError("Could not read device posture. Try again.") from None
        finally:
            client.close()
        if (not isinstance(result, dict) or type(result.get("schema_version")) is not int
                or result["schema_version"] != 1 or not isinstance(result.get("groups"), dict)
                or set(result["groups"]) != {"apps", "components", "skills"}
                or not isinstance(result.get("coverage"), dict)
                or "collected_at" not in result
                or (result["collected_at"] is not None and not isinstance(result["collected_at"], str))):
            raise ValueError("Invalid device posture response.")
        return {key: result[key] for key in ("schema_version", "groups", "coverage", "collected_at")} | {
            **identity, "supported": True,
        }
