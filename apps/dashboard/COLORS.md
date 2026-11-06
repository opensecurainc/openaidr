# Dashboard color specification

Every color in the dashboard has one job. This file lists each palette, its exact values, where it may appear, and the measurements that make it safe. `DESIGN.md` covers the rest of the visual system; when the two disagree about color, this file wins.

All values are defined once in `src/app/globals.css` and used through Tailwind tokens (`bg-severity-high`, `text-status-ok`) or CSS variables (`var(--chart-1)` for chart libraries). Feature code never uses hex values, raw Tailwind palette classes, or `bg-white`; `pnpm --filter openaidr-dashboard check:design` rejects all three.

Open [preview.htm](preview.htm) locally to compare the approved palette with the previous colors on an illustrative Overview. It embeds the OpenSecura marks, Geist fonts and their license, and the palette download, so the file works offline on its own. [palette.json](palette.json) is the downloadable reference; `check:colors` verifies its values against the application tokens and the preview's embedded download.

## The five jobs

| Job | Question it answers | Palette | Example |
| --- | --- | --- | --- |
| Neutral | Structure and reading | Ink, slate, paper, line, white | Text, borders, surfaces |
| Accent | What can I act on, what is selected | Navy (`primary`) | Primary button, link, focus ring, selected row |
| Severity | How serious is this finding | Critical, high, medium, low, info | Severity bar, legend, letter mark, finding badge |
| Status | What state is this thing in | Ok, warning, critical, info, neutral | Online, delayed, failed, unknown |
| Data | Which series, how much | Chart series, magnitude, activity categories | Logs/metrics/traces lines, findings per day |

Each token has one job. Severity and status use related hues but separate tokens: a finding's severity is fixed when it is raised, while a sensor's status changes from moment to moment. Never use a status token for a severity or a severity token for a status.

## Neutral

| Token | Value | Use | Contrast |
| --- | --- | --- | --- |
| `foreground` | Ink `#1c2230` | Primary and body text | 15.9:1 on white, 14.7:1 on paper |
| `muted-foreground` | Slate `#5a6372` | Secondary text, axis labels, captions | 6.1:1 on white, 5.4:1 on muted |
| `background` | Paper `#f5f6f8` | Page | |
| `card` | White `#ffffff` | Section surfaces, popovers | |
| `muted` | `#f0f2f5` (Line at 35%) | Table header row, code blocks, empty tracks | |
| `border` | `#e4e7ec` (Line at 65%) | The only divider color | Decorative; never the only carrier of meaning |
| `input` | `#838a95` (Slate at 75%) | Inputs, selects, outlined buttons, category filters | 3.48:1 on white, 3.10:1 on muted |
| `sidebar` | Deep navy `#0f2244` | Sidebar surface | Sidebar text `#d5e0f2` at 11.8:1 |

Muted text is for context, never for the value a reader came for.

## Accent

| Token | Value | Use | Contrast |
| --- | --- | --- | --- |
| `primary` | Navy `#17376f` | One primary button per section, links, selection, the active state of toggles | 11.6:1 on white |
| `ring` | Navy `#17376f` | Solid keyboard focus outline, with an offset around controls | 11.6:1 on white |
| `accent` | Navy at 8% | Hover and selected fills | |

Ordinary data uses teal. Navy identifies actions, selection, and informational status. Activity categories use their own muted palette below.

## Severity

How serious a finding is, from the detection rule that raised it. Every severity mark on every page uses these tokens, so one severity has one color everywhere: a chart segment, a legend swatch, a C/H/M/L letter mark, and a finding badge.

| Level | Mark | Text | On mark | 12% tint |
| --- | --- | --- | --- | --- |
| Critical | `#8b2b27` | `#872420` | `#ffffff` | `#f1e6e5` |
| High | `#b56220` | `#964d09` | `#000000` | `#f6ece4` |
| Medium | `#d5a12e` | `#805c09` | `#000000` | `#faf4e6` |
| Low | `#58758a` | `#3d586d` | `#ffffff` | `#ebeef1` |
| Info | `#9ea7b3` | `#5a6372` | `#000000` | `#f3f4f6` |

Tokens are `--severity-<level>`, `--severity-<level>-text`, and `--severity-<level>-on`; badges apply the mark at 12% over white.

Where each step goes:

- **Mark** fills shapes: bar segments, legend swatches, dots, the 2px rule, letter marks, and the swatch at the start of a badge. Every severity indicator on every page shows the mark color itself, so a reader matches a badge in a table to a segment in a chart by color alone.
- **On mark** is the letter set on a solid mark (C, H, M, L, I). White on critical and low; black on high, medium, and info. Each pairing clears 4.5:1.
- **Text** colors the label inside a tinted badge. It is the same hue darkened until it clears 4.5:1 on its tint and on white.
- **Tint** (`bg-severity-*/12`) is the background of a badge. Nowhere else.

Anatomy of each severity indicator:

| Indicator | Look | Where |
| --- | --- | --- |
| Bar segment, legend swatch, key swatch | Solid mark | Overview charts |
| Letter mark (`SeverityMark`, `SeverityCounts`) | Solid mark circle, on-mark letter | User Risk, dense rows |
| Badge (`Badge variant="critical|high|medium|low|informational"`) | Solid mark swatch, then the label in the text step on the tint | Detection Queue, finding details, Detection Rules |
| Tag (`SeverityTag`) | Solid mark swatch, then the label in foreground | Overview recent findings |
| Filter option | Solid mark swatch, then the label | Detection Queue severity filter |

Rules:

1. **Always with words.** Every severity color appears next to its name ("High", "11 high"), as a legend, a badge label, or a letter mark whose accessible name spells the level out. Color is never the only way to tell severities apart.
2. **Order is fixed.** Critical, high, medium, low, info, from left to right in a stacked bar and from top to bottom in a legend. Do not sort by count.
3. **Use the text step for labels.** Medium gold is 2.34:1 and the info gray 2.43:1 on white. These fills require readable labels beside them; use `-text` for every severity label, including high, whose mark is below 4.5:1.
4. **Info appears only when present.** Legends and keys show info when at least one counted finding is informational, so the visible parts always add up to the total.
5. **Badges:** `<Badge variant="critical|high|medium|low|informational">`. `informational` is the info severity; the status `info` tone is a different thing.

### Validation

`pnpm --filter openaidr-dashboard check:colors` (`scripts/check-colors.mjs`) reads the values from `globals.css` and checks the palette measurements described below. It computes OKLab distance ×100, simulates color-vision deficiency with the Machado, Oliveira, and Fernandes (2009) matrices at full severity, and computes WCAG contrast. For severity it checks every pair of levels, info included: a severity bar drops zero-count levels, so any two can end up side by side. It also checks each status color as text on white and on its 10% tint, resolving the brand values from the generated `brand.css`.

| Check | Target | Result |
| --- | --- | --- |
| Normal-vision distance | ≥ 15 | 15.9 worst (medium/info) |
| Deuteranopia distance | ≥ 8 | 14.9 worst (critical/low) |
| Protanopia distance | ≥ 8 | 14.2 worst (high/low) |
| OKLab lightness | 0.43–0.77 | 0.435 to 0.739, info 0.725 |
| Severity text on tint and on white | ≥ 4.5:1 | 5.36:1 worst (high on tint) |
| Letter on solid mark | ≥ 4.5:1 | 4.73:1 worst (black on high) |
| Status text on white and on 10% tint | ≥ 4.5:1 | 5.01:1 worst (ok on tint) |

The warm severity marks are variants of brand Red, Orange, and Gold with enough lightness separation to remain distinct in the simulations. Critical is brand Red at 97% over white; high and medium use lighter variants. Low is a muted slate blue, and info a lighter slate. Text uses the exact brand Red, Orange, Gold, and Slate where those meet contrast requirements. Medium and info marks rely on the readable labels required by rule 1.

## Status

The state of a thing: a sensor, a server component, a connection, an enrollment token, a finding's workflow. Shown with `<Status tone="…">`, an 8px dot beside a text label, or a 4px left rule on an alert.

| Token | Value | Meaning | Text on white | Text on 10% tint |
| --- | --- | --- | --- | --- |
| `status-ok` | Green `#3c723d` | Healthy, online, reporting, allowed, resolved | 5.73:1 | 5.01:1 |
| `status-warning` | Gold `#805c09` | Delayed, offline, degraded, needs attention, open | 6.08:1 | 5.29:1 |
| `status-critical` | Red `#872420` | Failed, unreachable, blocked, error | 9.12:1 | 7.66:1 |
| `status-info` | Navy `#17376f` | Informational notice, triaged | 11.59:1 | 9.70:1 |
| `status-neutral` | Slate `#5a6372` | Unknown, ended, disabled, not reported | 6.07:1 | 5.28:1 |

Rules:

1. A status dot always has its label beside it ("● Online"). The dot reinforces; the word informs.
2. Status tints (10%) appear only on alerts (`ErrorState`, `PageNotice`, refresh warnings) and their badges (`warning`, `destructive`, `ok`, `info`). The solid status fill with white text appears only on the AI Inventory approval-group header rows and their card borders: `status-info` Navy for Monitoring, `status-critical` Red for Unapproved, and `status-ok` Green for Approved (white on each fill is the "text on white" ratio in the table above, 5.73:1 or better). Each header pairs the fill with a distinct icon, eye, cross, or check, and its label. Application rows remain neutral, and the Monitoring state uses the `info` tone wherever it appears as a `Status`.
3. Log levels are states: ERROR and FATAL use `destructive`, WARN uses `warning`.
4. Finding workflow is status, not severity: open `warning`, triaged `info`, resolved `ok`, false positive `neutral`.

## Data

### Chart series (categorical)

Telemetry signals, in this fixed order, never reordered or cycled:

| Slot | Token | Value | Series | Contrast on white |
| --- | --- | --- | --- | --- |
| 1 | `--chart-1` | Teal `#03707c` | Logs | 5.81:1 |
| 2 | `--chart-2` | Light plum `#a67fa9` | Metrics | 3.37:1 |
| 3 | `--chart-3` | Dark slate `#3b4351` | Traces | 9.96:1 |

Teal is the exact brand harmony color. Light plum is brand Plum at 71% over white; dark slate is an equal sRGB mix of brand Slate and Ink, rounded. The original Teal and Plum have similar lightness, so the lighter plum variant keeps the series distinct. `pnpm --filter openaidr-dashboard check:colors` checks every series pair under protanopia and deuteranopia (minimum distances 10.5 and 11.6; target ≥ 8). It also enforces 3:1 contrast on white and on each series' own 8% fill (5.20:1, 3.12:1, and 8.73:1).

Supply-chain attention uses four fixed, solid category marks: npm uses
`--chart-1`, Python uses `--chart-2`, MCP uses `--chart-3`, and plugins use
`--chart-supply-chain-plugins` (`#527da8`). The fourth mark is specific to this
approved view and clears 3:1 on white. Named legend and readout rows identify
all categories; the three-series pairwise distance guarantee does not extend
to this four-category view. Do not add hatch patterns.

Credits & Usage uses six fixed, solid category colors: Investigations use
`--chart-1`, AI Assets use `--chart-2`, Assistant uses `--chart-3`,
Live Guardrail uses `--chart-model-cost-guardrail` (`#527da8`), Rules use
`--chart-model-cost-verification` (`#7b6041`), and Threat Intelligence uses
`--chart-model-cost-benchmark` (`#66558f`). Existing token names are retained.
The additional colors clear 3:1 on white. Named legend and readout keys use
the same solid colors. The three-series pairwise distance guarantee does not
extend to this six-category view. Do not add hatch patterns or dashed keys.

Other measures use stable named assignments from the same slots. A single CPU, memory, disk-space, or cost series uses `--chart-1`; disk I/O uses `--chart-1` for read and `--chart-2` for write. Filtering a series out never changes another series' color. Use matching dash or marker keys and text labels to distinguish multiple series without color. Host disk I/O is an exception: both series use solid lines, with named Read and Write legend and readout rows.

App Health's relative version age histogram uses `--chart-1` for online sensors
and the neutral grey `--input` for offline sensors. This limited exception uses
the same colors in the stacks and their named legend and readout keys. Counts
and sensor status remain available in text and a screen-reader table; the
histogram does not use warning or severity colors to imply that older builds
are unsafe.

Series colors belong on plotted marks and their legend or tooltip keys. Line and area plots may use a flat 8% fill of the series token inside the plot, with a full-opacity boundary line, as specified in [DESIGN.md](DESIGN.md#charts). The fill is supporting context; it is never the only way to identify a series. Do not use series tints on surrounding cards, text, or chip borders. Warning annotations such as unknown prices use `--status-warning` with a triangle and a text explanation; they do not change the series color or imply a zero value.

Guardrail History latency is a percentile-range exception to the categorical line and 8% area treatment. It uses one teal token for the median and both upper ranges: p50 to p95 at 25% fill, p95 to p99 at 10% fill, with a full-opacity 2px median and 1px upper contours at 58% and 36% opacity. The legend names the ranges and the readout gives all three percentiles; the lighter fills and contours are supporting context. This exception applies only inside the latency plot and its legend.

### Magnitude (sequential)

Agent cost composition uses the approved single-hue exception: each user has a
different lightness of `--chart-1`, mixed with `--card` in sRGB. Up to five named
users plus Other users use evenly spaced teal weights from 100% to 35%. Three
users use 100%, 67.5%, and 35%. The bar segments, legend swatches, and tooltip
keys match; isolating a user preserves its shade. These light tints are not the
categorical palette and do not claim its 3:1 contrast or pairwise separation.
Names, numeric readouts, and user-isolation controls provide identification
without relying on color. Labels remain neutral and selection uses `accent`.

"How much" in one series (findings per day, findings by category, records per service, sensors online) uses teal `--chart-1`, with `--muted` for the empty track. Do not color magnitude bars by value; the length already says it. Severity colors belong to severity composition charts. Keep both encodings consistent when they appear in neighboring cards.

Reasoning-effort cost bars use a truncated, reversed `gist_heat` scale: higher
effort has a darker fill. The `--chart-effort-*` tokens sample the continuous
[Matplotlib definition](https://github.com/matplotlib/matplotlib/blob/main/lib/matplotlib/_cm.py)
at the positions below. Channels are `r = 1.5x`, `g = 2x - 1`, and
`b = 4x - 3`, clipped to 0–1 and rounded to 8-bit sRGB. Trimming the near-white
end keeps the bars visible on the light track.

| Effort | Position | Token suffix | Color |
| --- | --- | --- | --- |
| None | 0.84 | `none` | `#ffad5c` |
| Minimal | 0.74 | `minimal` | `#ff7a00` |
| Low | 0.64 | `low` | `#f54700` |
| Medium | 0.54 | `medium` | `#cf1400` |
| High | 0.44 | `high` | `#a80000` |
| Extra high | 0.34 | `xhigh` | `#820000` |
| Max | 0.24 | `max` | `#5c0000` |
| Ultra | 0.14 | `ultra` | `#360000` |
| Auto / Unknown | Not ranked | `unknown` | `#5a6372` |

Color identifies the reported effort setting; bar length still shows cost
relative to the largest row. Sorting and filtering preserve each level's
color. Low through Ultra clear 3:1 contrast against the track. None and
Minimal use lighter supporting fills; labels and numeric costs remain the
primary readout. The palette check verifies decreasing lightness and the
contrast requirement; these shades do not claim categorical pairwise separation.

The AI Inventory review-priority bar is the one banded exception. Its 40px track beside each Monitoring score fills to the score and takes the severity mark of the score's band: 75 and above `severity-critical`, 50 to 74 `severity-high`, 25 to 49 `severity-medium`, below 25 `severity-low`. The bands use the marks so the bar reads like the Overview severity bar, and the score text beside it and the disclosure under the cards state the thresholds; the band orders review work and is not a finding severity. No other magnitude bar uses the severity marks.

### Activity categories (live timeline)

Activity categories use a dark, muted palette separate from chart series and severity colors:

| Category | Token | Color |
| --- | --- | --- |
| Prompt | `--activity-prompt` | Slate blue `#345E87` |
| Tool call | `--activity-tool` | Muted violet `#66558F` |
| Tool result | `--activity-result` | Teal `#2F6B63` |
| Response | `--activity-response` | Indigo `#3D528F` |
| Policy | `--activity-decision` | Bronze `#7B6041` |
| Session | `--activity-session` | Slate `#5B6472` |

Live activity uses these colors for timeline dots and solid category labels and filters with white text. Selected filters add an outline and a check mark. Category dots and policy-outcome dots are 12px; filter dots are white against the solid fill. White text on every category fill meets 4.5:1 contrast, verified by `check:colors`. These six categories rely on their labels for identification; they are not a six-series chart palette. Category colors identify event kinds, not their success or risk.

### Chart chrome

Horizontal gridlines use `--chart-grid`, the same `#e4e7ec` as decorative borders, at 1px. Axis labels use `--muted-foreground` (Slate `#5a6372`, 6.1:1 on white), the same readable secondary text as the rest of the interface. Reserve `--chart-axis` (brand Line `#d5dae2`) for the 1px interaction guide, never label text. Plot surfaces inherit the containing card; tooltip surfaces use `--popover` with `--border` and neutral text.

`check:colors` validates palette values and specified color pairs; it does not inspect rendered styles or interaction. Use the [chart review checklist](DESIGN.md#enforcement-and-review) to verify those requirements in the browser.

## Using color in code

| Need | Use |
| --- | --- |
| A finding's severity in a table or list | `<Badge variant="critical|high|medium|low|informational">` |
| Severity counts in a dense row | `<SeverityMark>` or `<SeverityCounts>` |
| Severity composition | `<SeverityBar>` with `<SeverityLegend>` (counts) or `<SeverityKey>` (no counts) |
| Severity beside chart marks, without a badge | `<SeverityTag>` (swatch and label) |
| A thing's state | `<Status tone="ok|warning|critical|info|neutral">` |
| A recoverable failure or notice | `<ErrorState>`, `<PageNotice>` |
| A chart series | `--chart-1..3` in the fixed order |

## Changing a color

1. Change the value in `src/app/globals.css` (or, for brand-derived tokens, in the brand repository).
2. Run `pnpm --filter openaidr-dashboard check:colors` (after `pnpm --filter openaidr-dashboard sync-brand`, which `dev` and `build` run for you). Every check must pass. It covers severity separation for every pair and lightness, every severity text step on its tint and on white, every status color on white and on its tint, and chart series separation and contrast. A brand palette change goes through the same check.
3. Update these tables, `palette.json`, and `preview.htm` with the new values and results in the same pull request. Keep the preview's Previous comparison as the historical reference.
4. Review charts, severity indicators, controls, and keyboard focus on desktop and mobile. Verify the preview comparison and download locally.
