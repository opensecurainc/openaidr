// Verify the measurable rules in COLORS.md against the values in globals.css.
// Run with `pnpm run check:colors`; it exits non-zero when a rule fails.
//
// Contrast follows WCAG 2.x relative luminance. Color distance is Euclidean
// in OKLab, scaled by 100. Color-vision deficiency is simulated with the
// Machado, Oliveira, and Fernandes (2009) matrices at severity 1.0, applied
// in linear sRGB.
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
// brand.css is generated from the brand submodule by scripts/sync-brand.mjs
// (run by `pnpm run dev` and `pnpm run build`); status tokens resolve through it.
const css = await readFile(path.join(root, "src/app/globals.css"), "utf8");
const brand = await readFile(path.join(root, "src/app/brand.css"), "utf8").catch(() => {
  throw new Error("src/app/brand.css is missing; run `pnpm run sync-brand` first");
});

/** Resolve the hex colors, references, and white sRGB tints used by our tokens. */
function token(name) {
  for (const source of [css, brand]) {
    const match = source.match(new RegExp(`--${name}:\\s*([^;]+);`));
    if (!match) continue;
    const value = match[1].trim();
    if (/^#[0-9a-fA-F]{6}$/.test(value)) return value.toLowerCase();
    if (/^#[0-9a-fA-F]{3}$/.test(value))
      return "#" + [...value.slice(1)].map((c) => c + c).join("").toLowerCase();
    const reference = value.match(/^var\(--([\w-]+)\)$/);
    if (reference) return token(reference[1]);
    const mix = value.match(/^color-mix\(in srgb, var\(--([\w-]+)\) (\d+)%, white\)$/);
    if (mix) return tint(token(mix[1]), Number(mix[2]) / 100);
    throw new Error(`--${name} has an unsupported color value: ${value}`);
  }
  throw new Error(`no --${name} in globals.css or brand.css`);
}

const rgb = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
const linear = (c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
const luminance = (hex) => {
  const [r, g, b] = rgb(hex).map(linear);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const contrast = (a, b) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};
/** `amount` of `hex` over white, as a hex color (a tint). */
const tint = (hex, amount) =>
  "#" +
  rgb(hex)
    .map((c) => Math.round((c * amount + (1 - amount)) * 255).toString(16).padStart(2, "0"))
    .join("");

function oklab([r, g, b]) {
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  return [
    0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
    1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
  ];
}
const SIMULATIONS = {
  normal: null,
  protan: [
    [0.152286, 1.052583, -0.204868],
    [0.114503, 0.786281, 0.099216],
    [-0.003882, -0.048116, 1.051998],
  ],
  deutan: [
    [0.367322, 0.860646, -0.227968],
    [0.280085, 0.672501, 0.047413],
    [-0.01182, 0.04294, 0.968881],
  ],
};
function seen(hex, matrix) {
  const lin = rgb(hex).map(linear);
  if (!matrix) return lin;
  return matrix.map((row) =>
    Math.min(1, Math.max(0, row[0] * lin[0] + row[1] * lin[1] + row[2] * lin[2])),
  );
}
const distance = (a, b, matrix) => {
  const [x, y] = [oklab(seen(a, matrix)), oklab(seen(b, matrix))];
  return 100 * Math.hypot(x[0] - y[0], x[1] - y[1], x[2] - y[2]);
};
const lightness = (hex) => oklab(rgb(hex).map(linear))[0];

const WHITE = "#ffffff";
const failures = [];
const report = (ok, message) => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${message}`);
  if (!ok) failures.push(message);
};

// Keep the downloadable reference palette aligned with the application.
const palette = JSON.parse(await readFile(path.join(root, "palette.json"), "utf8"));
const preview = await readFile(path.join(root, "preview.htm"), "utf8");
const embedded = preview.match(/<script id="palette" type="application\/json">([\s\S]*?)<\/script>/);
report(!!embedded && JSON.stringify(JSON.parse(embedded[1])) === JSON.stringify(palette), "preview download matches palette.json");
const matches = (name, value) =>
  report(token(name) === value.toLowerCase(), `palette.json matches --${name}`);
for (const [name, value] of Object.entries(palette.brand))
  matches(`brand-${name.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`, value);
for (const [key, name] of Object.entries({
  background: "background", surface: "card", text: "foreground",
  secondaryText: "muted-foreground", border: "border", mutedSurface: "muted",
  controlBorder: "input", sidebar: "sidebar", sidebarText: "sidebar-foreground",
  primary: "primary", primaryText: "primary-foreground", selection: "accent", focus: "ring",
})) matches(name, palette.foundations[key]);
for (const [key, name] of Object.entries({
  primary: "chart-1", secondary: "chart-2", tertiary: "chart-3",
  track: "muted", grid: "chart-grid", axisText: "muted-foreground",
})) matches(name, palette.charts[key]);
report(palette.charts.areaOpacity === 0.08, "reference chart area opacity is 8%");
report(tint(token("chart-1"), 0.08) === palette.charts.areaOnWhite.toLowerCase(), "reference chart area matches its 8% tint");
for (const [level, values] of Object.entries(palette.severity)) {
  matches(`severity-${level}`, values.mark);
  matches(`severity-${level}-text`, values.text);
  matches(`severity-${level}-on`, values.onMark);
  report(tint(token(`severity-${level}`), 0.12) === values.tint.toLowerCase(), `reference ${level} badge matches its 12% tint`);
}
for (const [key, name] of Object.entries({
  healthy: "ok", warning: "warning", error: "critical", information: "info", unknown: "neutral",
})) matches(`status-${name}`, palette.statusColors[key]);
for (const [name, value] of Object.entries(palette.activity)) matches(`activity-${name}`, value);
for (const [name, value] of Object.entries(palette.reasoningEffort)) matches(`chart-effort-${name}`, value);

// Readable labels and visible controls on the dashboard's light surfaces.
for (const surface of ["card", "background", "muted", "accent"]) {
  for (const name of ["foreground", "muted-foreground", "primary"]) {
    const ratio = contrast(token(name), token(surface));
    report(ratio >= 4.5, `${name} on ${surface} ${ratio.toFixed(2)}:1 >= 4.5`);
  }
  for (const name of ["input", "ring"]) {
    const ratio = contrast(token(name), token(surface));
    report(ratio >= 3, `${name} on ${surface} ${ratio.toFixed(2)}:1 >= 3`);
  }
}

// Severity: one hue per level, distinguishable side by side. A severity bar
// drops zero-count levels, so any two levels can touch: check every pair.
const levels = ["critical", "high", "medium", "low", "info"];
const marks = levels.map((level) => token(`severity-${level}`));
const pairs = levels.flatMap((_, i) => levels.slice(i + 1).map((__, k) => [i, i + 1 + k]));
for (const [i, j] of pairs) {
  const [a, b] = [marks[i], marks[j]];
  const pair = `${levels[i]}/${levels[j]}`;
  report(distance(a, b, null) >= 15, `severity ${pair} normal-vision ΔE ${distance(a, b, null).toFixed(1)} >= 15`);
  for (const kind of ["protan", "deutan"]) {
    const d = distance(a, b, SIMULATIONS[kind]);
    report(d >= 8, `severity ${pair} ${kind} ΔE ${d.toFixed(1)} >= 8`);
  }
}
for (const [i, level] of levels.entries()) {
  const L = lightness(marks[i]);
  report(L >= 0.43 && L <= 0.77, `severity ${level} lightness ${L.toFixed(3)} within 0.43–0.77`);
}

// Severity text steps clear 4.5:1 on their 12% tint and on white.
for (const level of levels) {
  const text = token(`severity-${level}-text`);
  const background = tint(token(`severity-${level}`), 0.12);
  report(contrast(text, background) >= 4.5, `severity ${level} text on tint ${contrast(text, background).toFixed(2)}:1 >= 4.5`);
  report(contrast(text, WHITE) >= 4.5, `severity ${level} text on white ${contrast(text, WHITE).toFixed(2)}:1 >= 4.5`);
}

// Letter marks set text on the solid severity fill.
for (const level of levels) {
  const on = token(`severity-${level}-on`);
  const mark = token(`severity-${level}`);
  report(contrast(on, mark) >= 4.5, `severity ${level} text on its mark ${contrast(on, mark).toFixed(2)}:1 >= 4.5`);
}

// Status colors are text on white and on their 10% tint (badges, alerts).
for (const state of ["critical", "warning", "ok", "info", "neutral"]) {
  const color = token(`status-${state}`);
  const background = tint(color, 0.1);
  report(contrast(color, WHITE) >= 4.5, `status ${state} on white ${contrast(color, WHITE).toFixed(2)}:1 >= 4.5`);
  report(contrast(color, background) >= 4.5, `status ${state} on tint ${contrast(color, background).toFixed(2)}:1 >= 4.5`);
}

// Chart series stay distinguishable side by side and clear 3:1 as marks.
const series = [1, 2, 3].map((n) => token(`chart-${n}`));
for (let i = 0; i < series.length; i++) {
  for (let j = i + 1; j < series.length; j++) {
    for (const kind of ["protan", "deutan"]) {
      const d = distance(series[i], series[j], SIMULATIONS[kind]);
      report(d >= 8, `chart-${i + 1}/chart-${j + 1} ${kind} ΔE ${d.toFixed(1)} >= 8`);
    }
  }
}
for (const [i, hex] of series.entries()) {
  report(contrast(hex, WHITE) >= 3, `chart-${i + 1} on white ${contrast(hex, WHITE).toFixed(2)}:1 >= 3`);
  const ratio = contrast(hex, tint(hex, 0.08));
  report(ratio >= 3, `chart-${i + 1} on its 8% fill ${ratio.toFixed(2)}:1 >= 3`);
}

report(contrast(token("chart-supply-chain-plugins"), WHITE) >= 3, "supply-chain plugins mark on white >= 3:1");
report(contrast(token("chart-model-cost-guardrail"), WHITE) >= 3, "model-cost Live Guardrail mark on white >= 3:1");
report(contrast(token("chart-model-cost-verification"), WHITE) >= 3, "model-cost verification mark on white >= 3:1");
report(contrast(token("chart-model-cost-benchmark"), WHITE) >= 3, "model-cost benchmark mark on white >= 3:1");

const effortLevels = ["none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"];
for (const [index, level] of effortLevels.entries()) {
  const color = token(`chart-effort-${level}`);
  if (index > 0) {
    const previous = token(`chart-effort-${effortLevels[index - 1]}`);
    report(lightness(color) < lightness(previous), `effort ${level} is darker than ${effortLevels[index - 1]}`);
  }
  if (index >= 2) {
    const ratio = contrast(color, token("muted"));
    report(ratio >= 3, `effort ${level} on track ${ratio.toFixed(2)}:1 >= 3`);
  }
}

for (const category of ["prompt", "tool", "result", "response", "decision", "session"]) {
  const background = token(`activity-${category}`);
  report(contrast(WHITE, background) >= 4.5, `activity ${category} white text on solid fill ${contrast(WHITE, background).toFixed(2)}:1 >= 4.5`);
}

console.log(failures.length ? `${failures.length} color checks failed` : "All color checks pass");
process.exit(failures.length ? 1 : 0);
