"""Desktop distribution choices come from immutable build metadata."""

from openaidr import build_info


MESSAGE = "This enterprise app requires an organization enrollment link from your administrator."


def enterprise_only():
    return build_info.current().get("desktop_edition") == "enterprise"


def needs_organization(config):
    if not enterprise_only() or not config.enrolled():
        return False
    from . import local_runtime

    return (config.get("connection_mode", "organization") != "organization"
            or (config.get("server_url") == local_runtime.ORIGIN
                and (local_runtime.directory(config) / "state.json").exists()))
