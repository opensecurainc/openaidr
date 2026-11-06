"""OpenAIDR tables registered through the osquery extension SDK."""

from importlib.metadata import version
from openaidr import __version__

import osquery

from .app_inventory import COLUMNS as APP_COLUMNS, app_rows
from .skill_inventory import COLUMNS, skill_rows
from .mcp_inventory import COLUMNS as MCP_COLUMNS, mcp_rows
from .plugin_inventory import COLUMNS as PLUGIN_COLUMNS, plugin_rows


@osquery.register_plugin
class ExtensionInfo(osquery.TablePlugin):
    def name(self):
        return "openaidr_extension_info"

    def columns(self):
        return [
            osquery.TableColumn(name="version", type=osquery.STRING),
            osquery.TableColumn(name="schema_version", type=osquery.STRING),
        ]

    def generate(self, context):
        return [{"version": __version__, "schema_version": "1"}]


@osquery.register_plugin
class Applications(osquery.TablePlugin):
    def name(self):
        return "openaidr_apps"

    def columns(self):
        return [
            osquery.TableColumn(name=name, type=osquery.STRING) for name in APP_COLUMNS
        ]

    def generate(self, context):
        return app_rows(context)


@osquery.register_plugin
class Skills(osquery.TablePlugin):
    def name(self):
        return "openaidr_skills"

    def columns(self):
        return [osquery.TableColumn(name=name, type=osquery.STRING) for name in COLUMNS]

    def generate(self, context):
        return skill_rows(context)


@osquery.register_plugin
class MCPServers(osquery.TablePlugin):
    def name(self):
        return "openaidr_mcp_servers"

    def columns(self):
        return [
            osquery.TableColumn(name=name, type=osquery.STRING) for name in MCP_COLUMNS
        ]

    def generate(self, context):
        return mcp_rows(context)


@osquery.register_plugin
class Plugins(osquery.TablePlugin):
    def name(self):
        return "openaidr_plugins"

    def columns(self):
        return [
            osquery.TableColumn(name=name, type=osquery.STRING)
            for name in PLUGIN_COLUMNS
        ]

    def generate(self, context):
        return plugin_rows(context)


def main():
    osquery.start_extension(
        name="openaidr",
        version=__version__,
        sdk_version=version("osquery"),
    )
    # The SDK returns without an error when it cannot connect to the manager.
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
