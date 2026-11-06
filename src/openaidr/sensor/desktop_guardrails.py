"""Desktop access to ordinary hook activity and fixed per-agent setup."""

from uuid import UUID

import httpx

from . import hooks, service
from .config import Config, configuration_lock
from .runtime import Client, NOT_ENROLLED
from .usage import identity as enrollment_identity


def summary(config, days):
    if type(days) is not int or days not in (1, 30):
        raise ValueError("days must be 1 or 30")
    return exchange(config, "summary", {"days": days})


def exchange(config, action, params):
    data = dict(params)
    version = data.get("review_version", 0)
    if type(version) is not int or version not in (0, 1):
        raise ValueError("Unsupported review version.")
    if "decision" in data and (action not in ("denials", "check") or data["decision"] not in ("ask", "deny")):
        raise ValueError("Unsupported check decision.")
    if action == "denials":
        if type(data.get("days")) is not int or data["days"] not in (1, 30):
            raise ValueError("days must be 1 or 30")
        if any(not isinstance(data.get(key), str) or len(data[key]) > limit for key, limit in (("until", 64), ("cursor", 256))):
            raise ValueError("Invalid denial window.")
    elif action in ("check", "review"):
        try:
            data["id"] = str(UUID(data.get("id")))
        except (ValueError, TypeError, AttributeError):
            raise ValueError("Invalid check ID.") from None
        labels = ("correct_denial", "false_positive", "insufficient_context") if version else ("correct_denial", "false_positive")
        if action == "review" and (data.get("label") not in labels
                or not isinstance(data.get("note"), str) or len(data["note"]) > 2000 or "\x00" in data["note"]):
            raise ValueError("Invalid review label or note.")
        if action == "review" and version:
            try:
                data["request_id"] = str(UUID(data.get("request_id")))
            except (ValueError, TypeError, AttributeError):
                raise ValueError("Invalid review request ID.") from None
            digest = data.get("evidence_sha256")
            if (not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)
                    or type(data.get("expected_revision")) is not int or data["expected_revision"] < 0):
                raise ValueError("Invalid review evidence or revision.")
        elif action == "review" and {"evidence_sha256", "expected_revision", "request_id"} & set(data):
            raise ValueError("Review evidence requires an updated review version.")
    with configuration_lock(config.path):
        config = Config.load(config.path)
        if not config.enrolled():
            raise ValueError(NOT_ENROLLED)
        scope = enrollment_identity(config)
        if action in ("check", "review") and data.pop("scope", None) != scope:
            raise ValueError("Organization connection changed. Reopen checks.")
        identity = dict(sensor_id=config["sensor_id"], server_url=config["server_url"].rstrip("/"))
        client = Client.from_config(config)
        try:
            result = client.post("guardrails/" + action, data, timeout=5)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404 and action in ("summary", "denials"):
                return dict(supported=False, **identity)
            if action == "review":
                raise ValueError("Could not save the label. Reopen the check and try again.") from None
            raise ValueError("Could not read guardrail activity. Check your organization connection.") from None
        except (httpx.HTTPError, ValueError):
            if action == "review":
                raise ValueError("Could not confirm the saved label. Reopen the check before trying again.") from None
            raise ValueError("Could not read guardrail activity. Try again.") from None
        finally:
            client.close()
        if not isinstance(result, dict):
            raise ValueError("Invalid guardrail activity response.")
        return {**result, **identity, "scope": scope, "supported": True}


def agent_request(config, action, params):
    agent = params.get("agent")
    if not isinstance(agent, str) or agent not in hooks.AGENTS:
        raise ValueError("Choose a supported coding agent.")
    if action == "guardrails.configure" and type(params.get("enabled")) is not bool:
        raise ValueError("enabled must be a boolean")
    with configuration_lock(config.path):
        config = Config.load(config.path)
        if not config.enrolled():
            raise ValueError(NOT_ENROLLED)
        path = hooks.settings_path(agent, config)
        config_toml = hooks.codex_config_path(config)
        profile = params.get("profile")
        if profile is not None:
            candidates = {str(path): (path, config_toml) for path, config_toml in hooks.codex_paths(config).items()}
            if agent != "codex" or not isinstance(profile, str) or profile not in candidates:
                raise ValueError("Choose a detected Codex profile. Refresh agent setup.")
            path, config_toml = candidates[profile]
        if action == "guardrails.configuration":
            if not path.is_file():
                raise ValueError("The agent configuration file does not exist yet.")
            return {"path": str(path.resolve())}
        if params["enabled"]:
            hooks.install(path, service.hook_executable(), agent, config_path=config.path,
                          config_toml=config_toml, explicit=True)
        else:
            hooks.uninstall(path, agent, config_toml, config_path=config.path)
        hooks.set_opt_out(config, agent, not params["enabled"], profile=profile)
        from .bridge import status

        return status(config)
