// Fail on styling that bypasses the dashboard design system (see DESIGN.md).
// Primitives in src/components/ui own their own styling and are not checked.
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const scanned = ["src/app", "src/components"];
const skipped = [path.join("src", "components", "ui") + path.sep];

const rules = [
  {
    level: "error",
    name: "raw code block",
    help: "use CodeBlock from components/ui so every text block includes the shared copy action",
    pattern: /<pre(?=[\s/>]|$)/g,
  },
  {
    level: "error",
    name: "native select",
    help: "use Select or NativeSelect from components/ui to preserve dropdown arrow spacing",
    pattern: /<select(?=[\s/>]|$)/g,
  },
  {
    level: "error",
    name: "type scale",
    help: "use text-xs, text-sm, text-base, text-display, or text-hero",
    pattern: /(?<![\w-])text-(?:\[\d[^\]]*\]|(?:lg|xl|[2-9]xl))(?![\w-])/g,
  },
  {
    level: "error",
    name: "radius scale",
    help: "use rounded-xs for bars, rounded-sm, rounded-md, rounded-lg, or rounded-full for dots and avatars",
    pattern: /(?<![\w-])rounded(?:-(?:xl|2xl|3xl|4xl))?(?=[\s"'`]|$)/g,
  },
  {
    level: "error",
    name: "shadow scale",
    help: "cards use borders; overlays use shadow-overlay",
    pattern: /(?<![\w-])shadow-(?:2xs|xs|sm|md|lg|xl|2xl)(?![\w-])/g,
  },
  {
    level: "error",
    name: "raw palette color",
    help: "use a semantic token such as text-status-warning or bg-muted",
    pattern:
      /(?<![\w-])(?:bg|text|border|ring|from|to|via|fill|stroke|outline)-(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\d{2,3}(?![\w-])/g,
  },
  {
    level: "error",
    name: "hex color",
    help: "use a token from globals.css (see COLORS.md)",
    // 3, 4, 6, and 8 digits: CSS hex colors with and without alpha.
    pattern: /(?<![\w&-])#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3,4})(?![\w-])/g,
  },
  {
    level: "error",
    name: "hardcoded white surface",
    help: "use bg-card",
    pattern: /(?<![\w-:])bg-white(?![\w/-])/g,
  },
  {
    level: "error",
    name: "letter spacing",
    help: "do not track body text or uppercase labels",
    pattern: /(?<![\w-])tracking-(?:\[[^\]]+\]|wide|wider|widest)(?![\w-])/g,
  },
];

async function* files(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* files(full);
    else if (/\.(tsx|ts)$/.test(entry.name)) yield full;
  }
}

const counts = { error: 0 };
for (const dir of scanned) {
  for await (const file of files(path.join(root, dir))) {
    const relative = path.relative(root, file);
    if (skipped.some((prefix) => relative.startsWith(prefix))) continue;
    const lines = (await readFile(file, "utf8")).split("\n");
    lines.forEach((line, index) => {
      for (const rule of rules) {
        for (const match of line.matchAll(rule.pattern)) {
          counts[rule.level] += 1;
          console.log(
            `${rule.level}: ${relative}:${index + 1} ${match[0]} (${rule.name}: ${rule.help})`,
          );
        }
      }
    });
  }
}
console.log(`${counts.error} errors`);
process.exit(counts.error ? 1 : 0);
