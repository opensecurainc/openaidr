import { cp, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const output = path.join(root, ".next", "standalone", "apps", "dashboard");
await mkdir(path.join(output, ".next"), { recursive: true });
await cp(path.join(root, "public"), path.join(output, "public"), {
  recursive: true,
});
await cp(
  path.join(root, ".next", "static"),
  path.join(output, ".next", "static"),
  { recursive: true },
);
