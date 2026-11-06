// Prepare generated assets before `next dev` and `next build`.
// The OpenSecura mark and palette are committed in this repository
// (public/icon.svg, public/icon-dark.svg, src/app/brand.css); the private brand
// submodule is not part of the public tree. Coding agent icons come from the
// shared set under packages/ui/agent-icons. Dashboard previews use the shared
// Geist fonts, whose license also covers the fonts bundled by next/font.
import { copyFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { syncAgentIcons } from "../../../scripts/sync-agent-icons.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
syncAgentIcons(path.join(root, "public/agent-icons"));
await mkdir(path.join(root, "public/fonts"), { recursive: true });
for (const name of ["Geist-OFL.txt", "Geist-Variable.woff2", "GeistMono-Variable.woff2", "geist.css"]) {
  await copyFile(
    path.join(root, "../../packages/ui/fonts", name),
    path.join(root, "public/fonts", name),
  );
}
