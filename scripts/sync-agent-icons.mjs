import { cpSync, rmSync } from "node:fs";

/** Copy the shared artwork and catalog to an app's generated public directory. */
export function syncAgentIcons(destination) {
  rmSync(destination, { recursive: true, force: true });
  cpSync(new URL("../packages/ui/agent-icons/", import.meta.url), destination, {
    recursive: true,
    filter: (source) => !source.endsWith(".d.ts"),
  });
}
