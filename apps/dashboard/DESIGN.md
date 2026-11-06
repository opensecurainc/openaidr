# Dashboard design system

## Navigation and layout

`src/lib/navigation.ts` is the source of truth for paths, category labels, titles, descriptions, icons, and telemetry filter eligibility. Preserve the six category names. Use plain task labels without slogans. The shell owns the single `h1`, breadcrumb, organization identity, navigation, and account controls. Feature pages start with `h2` sections.

Use `navTitle` when a shorter navigation label can use its category for context. Credits & Usage uses the same name in navigation, the page heading, and the breadcrumb.

The desktop sidebar is 256px wide, with 28px navigation rows (4px vertical padding around 20px line height) and 12px between groups. The sidebar shows the organization name once, under the wordmark; the header does not repeat it. Group labels are `text-xs` semibold at 75% of `--sidebar-foreground`, items are `text-sm` in `--sidebar-foreground` with a 16px icon at 70% opacity, and the active item is white, semibold, on a 10% white fill with a 2px white bar. The avatar is a plain 10% white circle with initials. Navigation scrolls independently while the account footer stays visible. Below 1024px the same groups appear in a Radix modal drawer with 40px minimum tap targets. Navigation closes it; Escape closes it and returns focus to the trigger. The header is opaque white with a bottom border: breadcrumb on the left and, on telemetry pages, the connection `Status` (Connected, Connecting, Data delayed) on the right. The page header is the `text-display` `h1`, a one-line description, and the page action on the right; telemetry filters sit in an unframed toolbar row below it. Content has a 1560px maximum width, 16px horizontal padding on phones, and 24px on larger screens. Flexible content uses `min-w-0`; wide tables scroll within their own boundaries.

The global **Local / UTC** control sits immediately before **Ask about this page** in the header. Use `TimeZoneControl`, with two visible native radio labels, a sliding Navy selection, white selected text, `border-input`, 6px outer radius, 4px selection radius, and 14/20 medium text. Header controls share a 32px height from `sm` upward and 40px on phones; icon buttons use `header-icon`. Keep 8px between controls. The local label identifies the browser's IANA zone on hover. Keyboard arrows change the selection, focus remains visible, and reduced motion disables sliding. Hide the parent breadcrumb on phones and the build label below `xl` to leave space for the controls.

Default to Local and remember an explicit selection in browser storage. Use `useTimeZone` for displayed timestamps, chart ticks, tooltips, and refresh/build times. Do not reload data or reset page state when the preference changes. Only midnight-aligned 24-hour series use UTC calendar-day labels. Rolling buckets keep their start times in the selected zone. Use UTC until the browser zone is available so the first server and browser renders agree. Relative durations, API windows, and raw evidence stay unchanged.

The top bar has a 48px minimum height from `sm` upward. Breadcrumbs stay on one line; a truncated page label retains its full text in a tooltip. Phone controls retain their 40px touch targets.

Credits & Usage places the range and refresh controls above the balance. Available credits, reserved credits, and usage in the selected period remain distinct. The conversion is $1 = 100 credits, with fractional credits. Unavailable amounts never become zero. Service status is visible above the balance; disabled charging does not invent an allowance or historical charges. Pausing charging keeps known earlier customer credit charges visible.

## Principles

1. Data first, chrome last. Borders, fills, badges, and icons exist only when they separate or classify something.
2. One container level. A page is a stack of sections; a section is one card. Inside a card, use dividers, spacing, and `h3` sub-headings, never another bordered box.
3. Color means something. Surfaces and text are neutral. Color encodes severity, state, selection, or a chart series, and always has a text label.
4. Hierarchy comes from weight and color, not size. There are four sizes.
5. Controls in one row share a height, and actions sit next to the content they act on.
6. Readable first, exact on demand. Lists show humanized values; the exact value is one hover or click away.
7. Explanations on demand. Put long background explanations behind a short, descriptive label. Show the data, current status, and next action first.
8. Summaries in lists, content on demand. A list row says what happened in a line or two of summary, never the raw record; full commands, payloads, and output open in a detail view. A list never shows the raw content of every record at once.
9. Fill the space or fold the band. A full-width band exists only when its contents use the width. One or two small items join a neighboring header, list, or toolbar instead of sitting alone in a strip.
10. Mark the exceptions. Badges and colors flag what differs from the norm. A value every row shares, or a "nothing found" result, is not badged on every row. Record provenance (`EventSourceBadge`) is part of each record's identity rather than an exception marker, and stays on every event row.

## Typography

The interface face is Geist and the code face is Geist Mono, the defaults of shadcn/ui ([ui.shadcn.com](https://ui.shadcn.com/)). The pinned `geist` package provides both; `next/font` in `src/app/layout.tsx` bundles them into the build and preloads them, and nothing loads from a CDN. `scripts/sync-brand.mjs` copies the font license to `public/fonts/Geist-OFL.txt`. Geist Sans and Geist Mono are also the brand typefaces. Static dashboard previews load the same locally bundled faces from `public/fonts/geist.css`; shared console and admin styles use `packages/ui/fonts/geist.css`. Labels, descriptions, and tool display names such as `Bash` use Geist. Literal technical values use the monospace standard below, including when they appear beside a label or within metadata.

The theme defines four text sizes and one figure size, and removes the rest of the Tailwind scale, so other `text-*` utilities produce no CSS:

| Utility        | Size / line | Use |
| -------------- | ----------- | --- |
| `text-xs`      | 12 / 16     | Metadata labels, captions, table headers, badges, timestamps |
| `text-sm`      | 14 / 20     | Body, table cells, controls, navigation, technical values and code |
| `text-base`    | 16 / 24     | Section, card, and dialog titles |
| `text-display` | 28 / 32     | The page `h1` and stat figures |
| `text-hero`    | 48 / 52     | The one headline figure a view leads with (at most one per page); never a heading |

Weights are regular (400), medium (500), and semibold (600). Within a size, primary text is `text-foreground` 500 or 600, body is `text-foreground` 400, and secondary is `text-muted-foreground`. Technical values use regular weight even when they are primary text. Do not use muted text for the value a user came to read. A component sets the size on its own root so nothing inherits a size by accident. Child text is never larger than its parent, except for technical values within smaller metadata. Use at most two sizes in one row. Do not letter-space body text or uppercase labels. Use tabular numerals (`number`) for aligned counts and `figure` for large standalone values. Long labels wrap; truncated values need accessible full text or a title.

### Technical values

Use the masked Decision model API key in Settings as the typography reference. IDs and code must match that value's font, size, line height, and weight across the dashboard.

| Property | Standard |
| --- | --- |
| Font | Geist Mono, the existing `font-mono` family |
| Size | `text-sm`: 0.875rem, 14px at the default root size |
| Line height | 1.25rem, 20px at the default root size |
| Weight | `font-normal`: regular, 400 |
| Classes | `font-mono text-sm font-normal` |

Apply this standard to IDs and UUIDs, hashes, masked API keys and tokens, file names and paths, literal URLs, commands, regular expressions, code snippets, payloads, and file contents. It applies in table cells, detail rows, form values, inline code, and code blocks. Labels such as "Tenant ID" and "Decision model API key" retain the interface typography; only their technical values use monospace. Human-readable names, status messages, counts, and timestamps retain their existing styles.

Use `CodeBlock` and `InlineCode` from `@/components/ui/code-block` for code blocks and inline code. Set their shared typography defaults to this standard instead of adding size overrides at each call site. An unframed technical value, such as a tenant ID or masked API key, uses the same classes without adding a code background or border. Explicitly set regular weight so the value does not inherit `font-medium` or `font-semibold` from its parent.

Keep the same font size on desktop and mobile. Let long IDs and paths wrap; let code scroll within its container when needed to preserve formatting. Existing excerpts may truncate if the full permitted value remains accessible. Do not shrink technical values to `text-xs` to make them fit. Preserve the stored characters, existing secret masking, and copy behavior.

Acceptance criteria:

- Tenant ID and the masked Decision model API key have the same computed font family, 14px size, 20px line height, and 400 weight at the default root size.
- Technical values in tables, detail views, inline code, and code blocks use this same typography, including inside smaller metadata or medium-weight rows.
- At desktop and phone widths, long values remain accessible without widening the page or reducing the font size. User font scaling remains supported through the existing rem tokens.
- Labels and descriptive text retain Geist, and styling does not change the value or expose a masked secret.

This is the required design standard. The current Tenant ID rendering and the `CodeBlock` and `InlineCode` defaults still use `text-xs`; they require an implementation update. Their current appearance is not an exception to this specification.

## Color

The `brand/` submodule is the source of truth for the mark and the brand palette. `src/app/brand.css` is generated from it and exposes `--brand-navy`, `--brand-red`, `--brand-ink`, `--brand-slate`, `--brand-line`, `--brand-paper`, `--brand-deep-navy`, and the harmony colors. Semantic tokens in `src/app/globals.css` use those values and the measured dashboard variants documented in `COLORS.md`. Changes to exact brand colors belong in the brand repository; dashboard variants must pass the color checks. On Deep navy surfaces use `/icon-dark.svg`, the brand's keyline variant; on light surfaces use `/icon.svg`.

Feature code uses semantic tokens only. Raw Tailwind palette classes (`amber-50`, `blue-100`, `emerald-700`) and `bg-white` are not used outside `src/components/ui`. `pnpm --filter openaidr-dashboard check:design` fails on them, on hex colors in feature code, on off-scale text, radius, and shadow utilities, and on letter-spaced text; `pnpm --filter openaidr-dashboard check:colors` verifies the contrast and color-vision rules in `COLORS.md`. Run both with the typecheck before opening a pull request.

| Role           | Token                   | Current value |
| -------------- | ----------------------- | ------------- |
| Background     | `bg-background`         | Brand Paper   |
| Main text      | `text-foreground`       | Brand Ink     |
| Surface        | `bg-card`               | White         |
| Primary        | `bg-primary`            | Brand Navy    |
| Muted surface  | `bg-muted`              | Brand Line at 35% on white |
| Secondary text | `text-muted-foreground` | Brand Slate   |
| Border         | `border-border`         | Brand Line at 65% on white |
| Control border | `border-input`          | Brand Slate at 75% on white |
| Focus ring     | `ring-ring`             | Solid Brand Navy |
| Destructive    | `bg-destructive`        | Brand Red     |
| Sidebar        | `--sidebar`             | Brand Deep navy |
| Chart series   | `--chart-1..3`          | Teal `#03707c`, light plum `#a67fa9`, dark slate `#3b4351` |

Navy (`primary`) marks the one primary action per section, links, selection, focus, and informational status. Ordinary data uses teal; activity categories use the muted palette in `COLORS.md`.

Severity, status, and data colors are specified in [`COLORS.md`](COLORS.md): each palette's values, where each step may appear, and the contrast and color-vision measurements behind them. In short:

- **Severity** (how serious a finding is) has one hue per level, used on every severity mark and badge: critical red, high orange, medium gold, low slate blue, info gray.
- **Status** (what state a thing is in) uses `Status` and status-toned alerts: ok green, warning gold, critical red, info navy, neutral slate.
- **Data** uses the chart series in a fixed order and one hue for magnitude.

Detection severity maps to badges `critical`, `high`, `medium`, `low`, and `informational`. Finding state uses `Status`: open is `warning`, triaged is `info`, resolved is `ok`, and false positive is `neutral`.

Chart series use stable assignments from `COLORS.md`: logs, metrics, and traces keep their fixed slots; a single measure uses brand Teal (`--chart-1`). Light plum and dark slate provide distinct additional series with at least 3:1 contrast on white and on their own 8% fills. Every pair passes protanopia and deuteranopia separation checks. Use matching dash patterns in multi-series lines and legends. Bars that show a share of one measure use teal on a neutral `bg-muted` track. Categorical colors appear on data marks and their legend or tooltip keys. A subtle area fill is allowed inside the plot under the [chart rules](#charts); series colors never tint surrounding cards, label text, or chip borders. The approved [palette preview](preview.htm) demonstrates the colors together.

## Spacing, shape, and elevation

Spacing follows a 4px grid: 4, 8, 12, 16, 24, and 32px. Use 4 to 8px between a label and its value or an icon and its text, 8px between controls in a toolbar, 16px card padding (12px vertical in card headers), 12px between list rows that have a divider, and 16px between sections. Table headers are 32px and table cells use 8px vertical padding. Empty states use a 128px minimum height and grow for longer content. Reduce spacing rather than font size, and let wrapped text determine row height.

Radius has four steps and the theme removes the rest: `rounded-xs` (2px) for chart bars and meter fills and tracks, `rounded-sm` (4px) for badges and inline code, `rounded-md` (6px) for buttons, inputs, selects, code blocks, and alerts, and `rounded-lg` (8px) for cards, dialogs, and popovers. `rounded-full` is only for status dots and avatars, never for chart bars or anything that holds text.

There are no decorative shadows. Popovers, menus, and dialogs use `shadow-overlay`, the only shadow in the theme. Cards separate from the page by their border.

## Components

Primitives in `src/components/ui` own size, color, radius, and padding. Feature code chooses a `variant` and `size` and adds layout classes only (`grid`, `col-span-*`, `w-*`, `min-w-0`, margins). If a call site needs a different look, change or extend the primitive instead.

Use `Select` or `NativeSelect` for dropdowns. `NativeSelect` preserves native form and keyboard behavior with a 12px arrow inset and at least 8px of clearance from the text. `check:design` rejects raw `<select>` elements outside `src/components/ui`. See the [verified dropdown spacing](../../docs/images/dashboard-select-spacing.png).

- **Buttons.** Console controls are 32px: `default` and `sm` are the same size. `xs` (24px) is for actions inside table and list rows; `lg` (40px) is for full-page forms such as sign-in. Icon buttons match: `icon` 32px, `icon-xs` 24px. Variants: `default` for the one primary action, `outline` for secondary actions, `ghost` for tertiary, dismiss, and row actions, `destructive` for irreversible actions.
- **Inputs and selects** are 32px with a white surface and no shadow, so they line up with buttons in a toolbar. The sign-in form uses the input `lg` size (40px) beside its `lg` button.
- **Badge** classifies and is never clickable: a 20px, 4px-radius label in `text-xs` medium. `default` is neutral (muted fill); `outline` is a neutral border. The severity tones `critical`, `high`, `medium`, `low`, and `informational` mark a finding's severity; the status tones `destructive`, `warning`, `ok`, and `info` mark a state (see `COLORS.md`). If a chip filters or toggles, it is a control, not a badge.
- **Status** (`@/components/ui/status`) shows state as an 8px dot and a `text-xs` label with no container: `<Status tone="ok">Online</Status>`. Use it for device, session, sensor, and connection state instead of a colored pill.
- **Review boards.** AI Inventory and AI Skills Inventory open with the same board: an unframed `h2` with a one-line summary and the page actions, a wide work-queue card, and two stacked cards beside it. `ReviewCard` (`src/components/review-card.tsx`) renders the card: a 36px solid status header row (`critical` Red for a queue of exceptions, `info` Navy for a neutral breakdown, `neutral` Slate for coverage, `ok` Green for cleared items) with white `text-base` semibold text, a 16px icon, and a count pill; the border repeats the fill; the body is a capped, keyboard-focusable scroll region with sticky `text-xs` column headers. Supply Chain uses a compact variant: a full-width 192px daily category chart, a full-width **Needs attention** table with inline Max CVSS and affected-device counts, then a full-width **Scan coverage** summary. The **All components** button expands the inventory and its filters. The chart defaults to device-weighted counts, uses only solid category marks, and distinguishes missing snapshots from zero. Its header keeps controls and latest totals compact; the page title and description share a row when space permits. Scan locations and advisory details remain in their existing dialogs. History covers the tenant; the review queue covers loaded records in the search and device scope. Skills use **Monitoring**, **Unapproved**, and **Approved**, with one review-scoped first page per card. Monitoring sits beside the stacked Unapproved and Approved cards. Monitoring and Unapproved show risk scores; Unapproved adds Notify users and Approved omits scores. The menu records an organization decision for the exact collected content. Scanner assessment and review status stay separate. Search, scope, assessment, and approval filters in **All skills** scope only that table. See skill review.
- **Approval groups.** Monitoring, Unapproved, and Approved are three peer cards under one unframed `h2` ("Application review") whose one-line description states the queue size, device and user totals, the highest-risk application, and any unapproved software. From `2xl`, Monitoring targets two thirds of the board width beside a stack of Unapproved and Approved cards with at least 33rem for notification actions. Narrower screens stack the queue above the other cards. The side stack is capped at the Monitoring card's maximum height so Approved fills the column. Approved omits Risk score; Unapproved includes Notify users. All three groups offer Approve, Mark unapproved, and Move to monitoring in the row menu. Each card's header row is the solid `status-info` (Navy), `status-critical` (Red), or `status-ok` (Green) fill with white `text-base` semibold text, a 16px eye, cross, or check icon, and the app count in a white-on-fill `rounded-sm` pill; the card border repeats the fill. Shape and text distinguish the groups without color; rows and column headers stay neutral.
- **Approval lists.** Each card body is a table in a separately scrolling, keyboard-focusable region capped at `min(28rem, 60dvh)` (the top stacked card at `min(14rem, 30dvh)` from `md`), with sticky column headers inside it. Long lists and Show more stay inside that boundary. Rows show the name in `font-medium`, then right-aligned Devices and Users links that open their respective lists. A Report column opens the application report. Monitoring and Unapproved add Risk score sorted highest first (`aria-sort`); Unapproved also adds Notify users. Monitoring adds a single-line Classification column from `lg` (inline under the name below that) and a 40px `rounded-xs` bar beside each score filled by the score's band in the severity marks: 75 and above critical, 50 to 74 high, 25 to 49 moderate, below 25 low. Keep the Monitoring score, bar, and risk band on one line; show Low confidence on one unbroken second line when applicable. Refresh delays remain visible. The bands describe estimated product risk, not finding severity; the disclosure under the cards explains the estimate and its limits. Approval choices, device counts, and user counts do not change risk scores. The review cards never filter: the software filters below scope only the All installed software table and the device and user lists it opens; see application review.
- **Card and PageSection.** One border, 8px radius, white surface. The header has a `text-base` semibold title, an optional one-line muted description, and actions on the right, top-aligned with the title in both `PageSection` and `CardAction`. The title column keeps at least 240px; on narrower cards the actions wrap below it. Sub-sections inside a card use an `h3` (`text-sm` semibold) and a divider, not a nested card.
- **Tables** in a `PageSection` run edge to edge inside the card through `TableLayout`, so the card border is the only frame; the header row is the divider under the section header, and the first and last columns keep 16px of padding so they align with the card text. Outside a section, `TableLayout` keeps its own border. Do not wrap a section table in a padded or bordered box.
- **Lists of records** such as rules, roles, notes, and evidence are divided rows (`divide-y`), not a grid of bordered boxes. Each row leads with its name in `text-sm` semibold, followed by badges and a right-aligned `Status`, then a muted description.
- **Overview.** A compact, cited AI summary sits above the shared Live Guardrail activity flow. Summary details and source metadata open in dialogs. Both pages use the same flow layout, text, measurements, status, and scope disclosure, without page-specific flow styling. Node selection on Overview opens matching checks. The page scrolls as needed to preserve the full flow. See Overview behavior and data scope.
- **Severity mark** (`@/components/ui/severity-mark`). A count with a one-letter C, H, M, L, or I on the solid severity mark, for dense rows where a full badge does not fit: `SeverityCounts` shows the nonzero counts most severe first. The accessible name spells the severity out. Use the full `Badge` tone where a row has room for one severity.
- **Stat strip.** Except for the separate cards specified under Cost views, summary figures are peers, so they share one bordered strip with hairline dividers (`StatCards`) instead of separate cards: a `text-xs` muted label, the value in `text-display` with `figure`, and one `text-xs` line of context. No icon chips or per-tile accent colors; a sparkline uses the first series color. A page whose figures already appear as section counts does not repeat them in a strip: AI Inventory states its totals in the Application review description instead.
- **Table content.** Cells inherit `text-sm` from the primitive. The first column is the row's name in `font-medium`; a second line of context under it is `text-xs` muted. Technical values retain the [technical-value typography](#technical-values), including in the first column or a second line. Do not shrink whole cells to `text-xs`, and do not put icon tiles in rows. Row actions are `xs` or `icon-xs` ghost buttons.
- **Timelines** (live activity) follow [Activity views](#activity-views): turns headed by their prompt, then one summary line per event on a 1px rail with a 12px dot in its category color. Category names use the `activity` badge variant with matching solid filters and white text. Category-filter and policy-outcome dots are 12px; selected filters add an outline and a check mark.
- **Code.** `CodeBlock` must render commands, payloads, and file contents on a muted surface in 14px Geist Mono, regular weight, with 20px lines; long content scrolls inside the block; pass `lines` to clamp an excerpt without showing a partial line. `InlineCode` marks a hash, identifier, or path with the same font, size, line height, and weight. Both follow the [technical-value typography](#technical-values).
- **Copying code and evidence.** Every `CodeBlock` includes the shared copy button at the top right, outside its scrolling text, with keyboard access and success or failure feedback. It copies the complete text, including lines hidden by a clamp. Pass `copyText` with the exact retained value when a preview trims or formats evidence, and `copyLabel` when a specific accessible name helps. Keep redaction and binary-content handling intact. Use this component for all new code, JSON, command, and file-content boxes, including Markdown code fences; do not add separate copy controls. `check:design` rejects raw `<pre>` elements outside the UI primitives.
- **Informational disclosures.** Use `PageNotice` with `collapsible` for background explanations, methodology, and caveats. Start closed with an information icon, a short `text-sm` label, and a chevron. The label toggles the full explanation inline on click, tap, Enter, or Space. Use native disclosure semantics, visible keyboard focus, wrapping labels, and at least a 40px tap target on phones. The closed state has no banner fill or border. Expanded text uses `text-foreground` and a readable line length. For example, User Risk shows "Findings grouped by OS username" and reveals the complete grouping explanation on activation.
- **Notices and errors.** Keep current failures, delayed data, permission requirements, and required next steps visible. Use `PageNotice` without `collapsible` for these notices and `ErrorState` for errors: 6px-radius blocks with a 4px left rule in the status color and a 10% tint (5% for informational notices).

Keep page and section descriptions brief, usually one short sentence. Move longer explanations of grouping, filters, attribution, collection, or calculation into a nearby disclosure. Put search scope beside its filters and section context before long result lists. Reference sections such as role definitions and collection requirements can also be collapsed; the current role, availability state, and setup actions stay visible.

## Cost views

AI Agent Costs uses compact summary cards with 8px gaps and 12px padding. Use two columns, expanding to four at extra-large widths. Keep the time range, filters, and refresh in one wrapping toolbar. Use a 192px chart with its user selection and displayed total in the header. User summaries use `text-base` values beside their names and call counts, with four summaries in one row at extra-large widths. Credits & Usage uses one stacked credit chart and a feature usage table. Live Guardrail, Investigations, AI Assets, Assistant, Rules, and Threat Intelligence use fixed colors. Exact service rows remain available in the table. Charts have keyboard and touch readouts and share 24h, 30d, and 90d controls. Data refreshes every 30 seconds from one API-authoritative snapshot. Refresh failures retain explicitly stale data; changing ranges clears the prior result. Missing credit rates and pending settlement stay separate from known charges. Purchases and automatic reload controls appear only when those actions are supported. Provider models, token counts, price quotes, and underlying costs are not customer dashboard fields. Captured evidence and native AI Agent Costs remain exact.

Display USD costs with the shared `src/lib/cost.ts` formatter in summaries, tooltips, and tables: a dollar sign, thousands separators, and exactly two decimal places. For example, `$0.01101408` displays as `$0.01` and `159.85` as `$159.85`. Positive values below one cent display as `<$0.01`, measured zero as `$0.00`, and missing prices as `Unavailable`. Chart axes use increments of at least one cent so rounded tick labels stay distinct, and may use compact currency ticks for large amounts. Retain full precision in accounting data and calculations; round only for display. Keep partial-price coverage visible beside cost estimates.

The agent cost breakdowns show name, cost, and share, with a small cost bar below each name. Cost remains sortable and names filter all views. Arrange the four breakdowns in one row when the content is at least 1024px wide, two columns from 672px, and one column below that. Wrap names and large values within their columns. Keep unpriced usage indicators visible beside costs.

## Charts

These rules are mandatory across the dashboard: Overview widgets, App Health, Server Health, cost views, detail views, and future charts. All chart types share the typography, colors, layout, formatting, interaction, and data-state rules below. Line and area charts also follow the reference treatment. Existing chart implementations are migration targets wherever they differ from this specification.

### Visual reference

![Line and area chart reference: a smooth trend with a light area fill, hollow sample markers, filled event markers, horizontal gridlines, and a compact tooltip.](../../docs/images/dashboard-line-area-reference.png)

The supplied "Daily detection processing cost" example is the visual reference for line and area plots. Use its clear line, restrained fill, readable labels, and compact tooltip with the dashboard's existing semantic palette and Geist typography. Marker meanings remain specific to each dataset.

### Shared frame and axes

- **Header and layout.** Use the existing section title scale: `text-base` for a card, `text-sm` for a subsection. Put scope, units, timezone, and essential context in compact secondary text. Place an optional latest value and legend together; keep collection-method explanations in a disclosure. Titles, legends, and actions wrap without clipping. Charts in the same grid row align their plot areas and baselines even when their headers differ in length.
- **Plot surface.** Inherit the containing card's surface, with no nested border or decorative background. The standard chart region is 256px high including axes; compact charts may use 192px, and Overview charts fill the existing 288px widget body. Use the available width and reserve enough edge space for the first and last labels, markers, and the widest Y label. Small screens reduce tick density before reducing text size.
- **Grid and ticks.** Use 1px horizontal `--chart-grid` lines, normally four or five labeled Y ticks. Hide axis rules, tick marks, and permanent vertical gridlines. Axis labels are 12px Geist in `--muted-foreground`, with tabular numerals. The lighter `--chart-axis` token is reserved for the interaction guide. A vertical guide appears only at the active timestamp.
- **Values and units.** Keep units beside the axis or in every tick, including `%`, `USD`, and `KiB/s`. Use compact, readable ticks such as `18k`; show the full value with appropriate precision in the tooltip and data table. Counts use whole-number ticks. A small nonzero value must not be formatted as zero. Tooltip, legend, summary, and table formatters agree on units and precision.
- **Scale.** Counts, nonnegative costs, and rates start at zero and use a rounded upper bound above the largest visible value. Capacity percentages use 0 to 100%. Unstacked areas extend to zero; signed measures include zero and all observed negative values. Related charts being compared use the same unit and scale. Avoid dual Y axes; separate measures with incompatible units.
- **Time.** Space observations by their actual timestamps. An automatic range fits the available observations with modest edge padding. Preserve a window explicitly chosen by the user; when history covers only a small part, state the coverage (for example, "Data since 21:00") and make a shorter supported range available. Never silently crop a selected window or stretch irregular samples into equally spaced categories. Show dates when a range crosses midnight so its endpoints cannot both read only "09:12 PM". Daily buckets retain their defined timezone; tooltips identify the full date, time where applicable, and timezone.

### Line and area treatment

- **Line.** Use a 2px stroke in the assigned series token, with rounded joins and caps. The primary series is solid.
- **Curve.** Use monotone interpolation for trend views, passing through samples without overshoot. Use linear segments for raw measurements where smoothing would mislead, and steps only for values held until the next observation. Explain these exceptions in the chart change.
- **Area.** For a single nonnegative trend, use a flat 8% fill of its series color to zero, with the line at full opacity above it. No gradients or opaque fills. Use an unfilled line when the baseline or overlapping fills would obscure the comparison.
- **Multiple series.** Keep names, colors, and legend order stable across pages and filters. Add a distinct dash or marker shape for each additional line and repeat it in the legend. Prefer unfilled lines for comparisons; stack areas only when the parts add to a meaningful total in the same unit. Stacked areas use the same 8% fill and visible boundaries.
- **Sample markers.** Use hollow circles with a 3px radius, a 2px outline in the series color, and a fill matching the plot surface. Show routine markers when neighboring samples are at least 12px apart. Suppress routine markers on denser series while retaining isolated points, active points, and event markers. Do not discard observations to hide dots.
- **Active marker.** On hover, keyboard focus, or touch selection, use a filled marker with a 4px radius, a 2px halo matching the surface, and a solid 1px vertical guide in `--chart-axis`.
- **Event markers.** A persistent filled marker denotes a named event or flag from the data or a documented rule. Explain its meaning in the legend and tooltip. Do not label every visual peak an anomaly. A warning such as a pricing gap uses a labeled triangle in `--status-warning`; place it in an annotation row when no Y value exists.
- **Motion.** Disable animations that draw lines or introduce points on load and refresh. Preserve the visible data while refreshing.

Sparklines may omit axes, grids, legends, and routine markers when the adjacent text supplies the measure, value, unit, and time scope; they retain the line, color, gap, and data-access rules.

The App Health relative version age summary is a compact histogram within the
KPI strip. It uses eleven categorical buckets (0d through 9d, then >9d), a 40px
zero-based plot, and explicit device counts above the columns instead of Y ticks
or gridlines. Its label follows the strip's `text-xs` scale. Online and offline
segments have a named legend, shared readouts, and a screen-reader data table.
The bars fill their columns with 2px gaps. The card moves below the other KPIs
when five columns cannot fit comfortably.

### Bar and meter treatment

- **Shared style.** Bar charts use the same frame, axes, formatting, and tooltip, with solid fills from `COLORS.md` and a zero baseline. Do not apply line interpolation or sample markers to bars.
- **Corners.** All horizontal bar fills and tracks use `rounded-xs` (2px), including inline table bars, magnitude bars, coverage meters, and empty tracks. Use the same radius at every bar height; do not use pill ends or increase the radius for larger bars.
- **Stacks.** Round only the two outer ends of a stacked bar to 2px. Keep internal segment edges square and preserve the 2px surface gaps. A single segment rounds both ends.
- **Columns.** Round the exposed top corners to 2px and keep the baseline corners square. In Recharts use `radius={[2, 2, 0, 0]}` for the positive columns used by the dashboard.
- **Small values.** Keep widths proportional to the data and show zero as an empty track. Let the browser or chart library clamp the radius when a mark is smaller than 4px; do not enlarge a value to fit its corners. Include short bars, full tracks, zero values, and stacks in desktop and phone visual checks. The [palette preview](preview.htm) follows the same geometry.

### Tooltip, legend, and access

- Use one tooltip treatment for all chart types: `bg-popover`, `border-border`, `rounded-lg`, 12px horizontal and 8px vertical padding, and `shadow-overlay`. Show the timestamp or bucket first, followed by a row per series with its key, name, and right-aligned value. Use 12px secondary labels and 14px foreground values with tabular numerals, with at least 12px between label and value. A single-series tooltip may use the reference's 2px colored rule. Keep text neutral and the tooltip within the viewport.
- Order tooltip rows like the legend. State qualifiers such as "Estimated", "Partial", "Stale", or "Not reported" beside the affected value. Never coerce null values to zero or sum missing values into an apparently complete total.
- Legends use neutral text and small keys matching the plotted stroke, dash, or marker. A single named series does not need a redundant legend. Event symbols always have a text explanation, and color never carries their meaning alone.
- Make the same readout available by pointer, keyboard, and touch, with visible keyboard focus. Provide an accessible chart name and a data table containing every plotted observation and its units, timestamps, and flags. Tooltips are not the only way to retrieve values. Keep controls reachable at phone widths.

### Sparse data and states

- A single observation is a visible point, with its value and timestamp available in the readout and table. Do not stretch it into a line or filled area. Constant and all-zero series remain visible against the grid with a usable Y range.
- Missing observations, collection outages, and unknown prices break the line and fill. Use `connectNulls={false}` and explicit gaps for missing intervals; never interpolate across an outage. An empty bucket becomes zero only when the data contract establishes an observed zero.
- Loading, no observations, permission denial, unavailable metrics, and failed requests use the shared states. Keep the chart's space stable. A failed refresh retains the last plot with its last-sample time and a stale warning. A selected range with no observations shows an empty state rather than an unexplained blank grid.

### Enforcement and review

Use `ChartReadout` from `src/components/chart-readout.tsx` for chart tooltips and its `SampleMarker` for routine hollow markers. `src/lib/chart.ts` provides UTC labels, rounded ticks, and marker-spacing rules. Host resource charts use linear segments because they show raw measurements; cost trends and telemetry activity use monotone curves.

Model cost history in both Detection and Guardrail sections, telemetry activity, and host resource charts display directly without a data table or display tabs. Their values remain available through pointer, keyboard, and touch readouts. Model cost coverage remains in the summary and chart readouts. Host Disk I/O series use solid lines and solid legend keys for both Read and Write, with named rows in the pointer, keyboard, and touch readouts.

Chart changes must follow this section and `COLORS.md`. Reuse shared chart styling, formatters, and tooltip components as they are introduced; keep styling defaults in shared code rather than adding page-specific variants. The current charts in `host-metrics.tsx`, `agent-costs.tsx`, and `telemetry-panels.tsx` must be brought into conformance when changed. Their current library defaults and custom styles do not define exceptions.

Before accepting a chart change:

- Compare the running chart with the reference at desktop and phone widths. Check plot alignment, readable labels, unclipped endpoints and tooltips, and identical styling for the same element on other pages.
- Check populated, dense, sparse, single-point, constant, zero, missing, stale, loading, empty, and error states. Exercise a range spanning midnight and values large enough to test unit formatting.
- Verify keyboard and touch readouts, the data table, and series identification without color. For behavior changes, extend the relevant existing browser tests with the affected cases.
- Run `pnpm --filter openaidr-dashboard check:design` and `pnpm --filter openaidr-dashboard check:colors`, plus the typecheck and affected tests for implementation changes. The scripts check token usage and palette properties; layout, interpolation, markers, tooltips, and data honesty require the review above. Passing those scripts alone does not establish chart compliance.

## Overview

The Overview is available to all dashboard roles and shows aggregate reporting only. Every widget is a chart or a figure. Named-user findings and captured action evidence belong on Security Analyst investigation pages. It is a grid of dashboard widgets (one column on phones, two at `md`, three at `xl`):

- Open findings: the hero figure, new findings in the last 7 whole UTC days (today included) against the 7 before, named by their first day ("since Sep 24 (UTC)") because the server counts by calendar day, and one severity bar with its legend.
- New findings per day over the 30 most recent UTC days (the server's oldest, partial bucket is dropped): a column chart, two columns wide, with a hover readout and a screen-reader table of every day.
- Agent risk signals: one-hue horizontal bars by detection category, largest first, zero shown as an empty track.
- Coverage: a meter of sensors online and two 30-day figures.

Telemetry volume, source services, and recent exports belong on App Health. Overview loads only aggregate risk counts and shows links to investigation or administration pages only when the signed-in user can open them.

## Activity views

Live activity appears directly below Activity flow and above Actions on Live Guardrail (`/guardrail/live`). Only Security Analysts can open it. It loads device status without service filters, preserves `?session=` links, and clears captured activity on access denial. The old `/activity` route redirects to this panel with the selected session intact. Its live event window, category filters, session selection, and pause control remain independent of the completed-check flow and Actions table.

These rules apply to views of agent activity: Live Activity, session pages, Evidence Search events, and finding evidence. Layout, Session list, and the session header apply to session-browsing surfaces. Evidence Search shares session buttons, category filters, and timeline summary buttons with Live activity. Its sessions are grouped by reported device and show the latest loaded prompt, or the latest record's summary, without inferred live status. It keeps one row per stored record, including tool results, accepted decisions, and native records. Date headings use the selected display time zone. Category chips filter only loaded matches in the selected session; they do not change the search request or its pagination. Finding evidence remains a cross-session record list. Live Guardrail's action table is a cross-session table specified under [Real-time Guardrail](#real-time-guardrail); it follows the Timeline rules below for one line per event (except that the decision cell keeps the rule name below its `Status`), folded results, content that is not text, and badges marking exceptions, but not the master-detail layout or the session header. Each rule names the failure it prevents.

### Layout

- **Master-detail for sessions.** A view of several sessions is a two-pane card at `lg` and wider: a session list on the left (280 to 360px) and the selected session's timeline on the right. Each pane scrolls on its own inside a fixed height, so the card never grows with its data. On a full page it fills the viewport below the page header. Below `lg`, the list comes first and selecting a session shows its timeline with a back control. Live activity keeps its selected session in the URL (`?session=`). Evidence Search keeps its selection while loading more matches or refreshing. The most recently active session is selected by default. Prevents: sessions stacked in one long column with no way to pick one, and a feed several screens tall.
- **Devices group the list.** Devices are group headers in the session list (name, `Status`, and session count), not a separate strip of cards. A device filter, when needed, is a select in the list header. Prevents: one small device card alone in a full-width band.
- **Height budget.** No Overview widget or panel is taller than one viewport. Longer content scrolls inside its own pane or links to a full page. Prevents: a widget that pushes the rest of the page off screen.

### Session list

- Each row is one session: the agent name and `Status` (Active, Idle, Ended) on the first line, the session's latest prompt on the second line in `text-sm` truncated to one line with a title, and the last activity time and event count in muted `text-xs` on the third. The row keeps the latest prompt seen for its session after that prompt leaves the bounded live window, so a busy session does not lose its summary. When no prompt for a session has been loaded, as on a fresh load during a long session, the row fetches the session's newest collector prompt once (`events?kind=prompt&session_id=…&source=collector&limit=1`). If it has no text, the row also asks for the newest native prompt (`source=otlp`), which can contain opted-in Codex text. When neither result contains text, the row shows "No prompt text" muted. The selected row uses the highlighted-row treatment (`bg-primary/5`, 3px primary left accent, `aria-current`).
- The list is kept independently of the bounded event window: a session stays listed with its last known row after all its events leave the window, until it has been inactive for one hour. Selecting such a session shows its header and "Its events are outside the live window." instead of a timeline. The list is built from the live feed only: a session with no event in the window since the page loaded appears when it next has activity. A server-side session inventory is out of scope for these rules.
- Device groups are ordered by their newest session activity, and sessions within a group by last activity. New activity on a session updates its row in place and moves it to the top of its group, and its group to the top of the list, without changing the selection.

### Timeline

- **Category labels.** Live activity and Evidence Search label Prompt, Tool call, Tool result, Response, Policy, and Session with a 20px solid badge and white text. The label and its filter share the category color from `COLORS.md`; text remains readable without relying on color. The session panel shrinks at phone widths so filters wrap and labels stay inside the card. Evidence Search shows each record's source beside its summary on wider screens and in its expanded details at every width.
- **Prompts are landmarks.** Events are grouped into turns. Each user prompt starts a turn and is its heading row: the prompt text in `text-sm` medium `text-foreground` on a `bg-muted` fill, up to three lines, with the time in muted `text-xs`. The tool calls, results, and response of that turn are indented under it. Events before the first prompt form an untitled turn. Prevents: prompts that look like every other row, so a session cannot be read at a glance.
- **One line per event.** A tool call row shows the time in a fixed 80px `text-xs` column, the tool name in `text-sm` medium, and one muted summary line: the command's first line (with "+N lines" when it has more), the file path, the URL, or the MCP tool and its first argument. Its result is not a separate row: the call row shows the outcome inline (duration, and "failed" or an exit code when not zero) and carries the most severe labeled risk of the call, its result, and its merged native record, so a risky record is never hidden by folding or merging. A result whose call cannot be matched (no call id, or the call is outside the live window) keeps its own row with the same one-line treatment, so no output is dropped. A response row shows its first line of text. Rows never show more than one line of code. Prevents: a wall of raw commands and output.
- **The row is the action.** Each row's summary line is a button with `aria-expanded` whose accessible name includes the one-line summary; clicking it, or pressing Enter or Space, expands the row in place and collapses it the same way. The expanded content is the button's sibling, never inside it, so its own controls stay reachable: for a tool call, the stored command or input in a `CodeBlock` and the output below it; for a result without a matched call, its stored output; for a prompt or response, its stored text. Each is clamped to 12 lines with "Show all" and a copy action (content of 12 lines or fewer is not clamped). Below them are the JSON view and, only when the event or its merged native record has an export reference, "Open telemetry record". Only one row is expanded per session at a time. There is no per-row `View` link or button on collapsed rows. Prevents: the same link repeated on every row.
- **Collection changes are disclosed.** The sensor marks an event `truncated` when it kept only a prefix of some field and `redacted` when it replaced matching values. These flags describe the event, not a specific field, so the expanded row and detail dialog say so once for the event ("Truncated at collection: stored values may be a prefix", "Redacted at collection: matching values were replaced") next to the copy and download actions, and never claim that a particular value was clipped. Prevents: an investigator copying or downloading altered evidence as if it were complete.
- **Content that is not text.** Stored output that is binary or encoded (base64, image data, archives) as a whole is never rendered as text in a row or a detail view. Show its type and size ("PNG image, 18 KB"); when the event was truncated at collection, the size is what was captured ("PNG image, 12 KB captured"). Text that contains an encoded operand, such as a command that decodes base64 and pipes it to a shell, is still text and stays readable. Content the collector did not retain, such as an image block dropped from a tool result, has nothing to describe or download. The expanded row and the detail dialog offer "Download raw output", generated in the browser from the stored string, so the exact evidence stays available on demand. Output longer than the clamp shows its line count.
- **Badges mark exceptions.** A risk badge appears only at Low and above; Minimal, no identified risk, and accepted policy checks are not badged per row. Live activity counts accepted checks and merged native records in the session header. Evidence Search keeps accepted decisions and native records as separate rows so no stored record disappears. An unknown risk is shown only in the expanded row. A denied, warned, or approval-asked sensor policy decision is always shown on its row as a `Status`. Only sensor policy decisions are counted as accepted checks or shown as guardrail outcomes; a native agent permission decision (OTLP `tool_decision`) keeps its own row labeled "Agent permission" with the agent's reported value, whether it accepted or rejected.
- **Session header.** The selected session's header has the agent name and `Status`, then one muted line with user and host, the working directory as `InlineCode` truncated from the start, and the start time. Counts (events, accepted checks, merged records) are a single muted `text-xs` line. Nothing in the header repeats what the session list row already shows twice.

### Review

Check an activity view with a long busy session (hundreds of tool calls with multi-line commands and long output), a session with only prompts, a session without prompt text, binary output, a single device and several devices, a phone width, and keyboard-only use. The view passes when the activity card stays within one viewport, every event row (tool call, result, response, decision, session boundary) is one line until expanded, prompt headings and session list rows stay within their stated line limits, and a reader can tell what each session with prompt text was about from its prompts alone.

## Real-time Guardrail

[Compact Activity flow header with synthetic browser-test data](../../docs/images/guardrail-compact-header.png).

Live Guardrail uses one page of up to 100 completed backend checks from `hook-decisions?classified=true` for its activity flow and Actions table. There is no separate summary strip: the Activity flow header states the loaded page's completed, prompt, tool-call, tool-result, and failed check counts on one line, and the identity and session columns state shown-of-total counts. The header uses two compact rows when space permits: title, help, and controls above page counts and inline measurements. The selection hint opens from the title's help button. The latest page says `Last N checks`; older pages say `This page: N checks`. The page does not carry the hook mode control; Shadow or Enforce is set on Guardrail Configuration, and each Actions row still shows the mode its check ran under. The live flow has four columns: reported identities, sessions, Guardrail decisions, and risk categories. It associates activity with outcomes; the separate Company Policy and Knowledge diagram explains evaluation order. It uses neutral connectors and `FlowNode` controls as interactive data marks. Selection uses the primary accent; decision nodes use `Status`, never whole-node status fills. Up to six sessions are drawn, while counts include every check in the page. Identity, session, assessment, and decision selections filter Actions. Pagination changes all three views together. Checks that never reach the backend and managed-session approvals are outside this view.

The OS user dropdown defaults to All users and scopes the summary, flow counts and sessions, and Actions to one OS username across devices and accounts. Show the visible label `OS user:` and list unique OS usernames alphabetically, including sessions outside the six drawn nodes. Checks without an OS username appear under All users. The selection persists through refresh, pause, and pagination, with an explicit empty state when that user has no checks in the page. Selecting another user clears the previous identity, session, or assessment selection; action-type and decision filters still apply to Actions. All users clears the user filter. This is a loaded-page filter, not a search across retained history.

New checks animate as dots on the same solid SVG paths as their connectors. The complete-window summary includes up to 100 recent check IDs and their source and risk routes; at most 24 new checks animate at once. Counts still cover every matching check. Initial history, filter changes, unchanged refreshes, and assessment updates to existing checks do not replay dots. Motion respects reduced motion, and Pause view stops the dots. Selecting an identity, source, or outcome keeps the flow live so new matching sessions appear. The identity directory fixes only its own search and pagination window. Searching or paging Explore activity fixes the shared window until Resume live. Small screens scroll the diagram within its section. Guardrail p95 duration remains an organization-wide measurement of service operations started in the last five minutes, with the label `Last 5 min · All sources`. Sample counts open from the latency button. The optional `recent_checks` field requires the updated backend for animation; older backends continue to show counts and live identity filtering. Deploy the backend before the dashboard. No migration is required, and rollback does not change stored decisions.

The combined decision is the evaluated policy result, not proof of enforcement. Shadow returns Allow; Enforce returns supported decisions. Each Actions row shows mode, returned response, and delivery status separately. Failed checks appear explicitly and allow the action. An unavailable model assessment adds no restriction, while a valid fixed-rule restriction can still apply. Unassessed and Check failed have separate filters. Captured content and decision reasons remain exact; details expand in the row. Scored assessments use risk badges. In the Actions table, insufficient evidence uses a neutral `Risk 0/100 · Minimal` badge; its tooltip and Decision details explain that the assessment was inconclusive. This is a display value: stored scores remain null, flow categories remain Unassessed, and policy thresholds use only scored assessments. Other assessment failures retain their failure labels. Policy evaluation failure labels include a red circle-exclamation icon and show their recorded cause in Decision details, with an explicit fallback when older records have no cause. The separate Company Policy and Knowledge explainer shows fixed rules, model assessment, and combined results. It distinguishes ordinary hooks, managed-session controls, and background assessment.

This dashboard change uses the existing completed-check API and needs no backend migration. Deploy it with a backend that supports classified checks; rolling the dashboard back restores the legacy flow without changing hook policy or stored decisions.

Guardrail History reads `guardrail/stats` for a selected range using a segmented radio control styled like Local/UTC. A Source filter defaults to All, with Endpoints and Gateways as narrower views. All combines raw samples with one time range and shows a line for each populated source in the Decisions chart. Empty sources appear as compact notices. The selected source controls four metric cards in one row when the content is wide enough, two columns at intermediate widths, and one column on phones: Decisions, combined Allowed/Asked/Denied rates, end-to-end latency (p50, p95, p99), and failure rate. Summary figures sit above aligned charts in the existing four-card layout. Decisions, decision rates, and failures retain unfilled monotone lines. Latency uses a solid teal p50 line and two adjacent teal percentile bands: p50 to p95 at 25% fill and p95 to p99 at 10% fill. Thin p95 and p99 contours use 58% and 36% stroke opacity. These are upper percentile ranges, not confidence intervals or a distribution centered on the median. Latency lines and bands use linear segments so the percentile bounds remain aligned without implying smooth movement between intervals. The legend names both bounds of each band; pointer, keyboard, and touch readouts retain the individual p50, p95, and p99 values. Missing either bound breaks that band, zero remains a measured value, and isolated samples remain visible as points. Allowed includes warned calls; the combined rate series use `--chart-1..3` in Allowed/Asked/Denied order with solid, dashed, and dotted lines on a shared 0 to 100% scale. Failures use recorded attempted checks with confirmed outcomes as their denominator, independently of decision counts. Valid allow, ask, warn, and deny decisions are successful. Not evaluated and Pending or unconfirmed counts appear separately below Failure rate. Combined percentages and latency percentiles use raw samples, never averages of source summaries. Intervals without measured rates or latency remain gaps, and unavailable execution trends have an explicit empty state. Charts have pointer, keyboard, and touch readouts without a data table or display tabs. The separate per-rule table remains. Decisions from sensors that predate full recording are excluded and announced with a `PageNotice`.

Both sources use measured guardrail end-to-end latency, excluding tool execution and model response generation. Missing e2e timing is never replaced with backend policy latency or model request duration. Confirmed delivery failures, backend evaluation errors, and expired checks count as failures; disabled or unsupported evaluation is Not evaluated. Pending checks and missing delivery receipts are excluded from the failure denominator. Request ledger filters apply only to that ledger, whose time range follows the charts unless custom times override it. History refreshes on source, range, or Refresh changes to keep ledger pagination stable. Endpoint rule details follow the shared charts. See [the API and rollout contract](docs/gateways.md#history-metrics).

The four shared charts synchronize their tooltip timestamps and vertical guides. Each card shows its own values for the selected interval, including `No data` for missing measurements. Moving the pointer to another plot clears a previous chart's keyboard selection so it can follow the hovered timestamp. The [offline HTML mockup](hook-chart-sync-mockup.html) demonstrates the interaction with illustrative data.

The API adds optional `executions: {total, failed}` to each series bucket, using the same snapshot and window as its execution totals. Deploy the additive API change before the dashboard when possible; an older API retains its summary and shows an unavailable failure trend. Either component can be rolled back independently; no migration is required.

## Managed session archives

Session details show stored canonical risk and its projection time, four coverage axes, and verified account ownership separately from reported OS user. Keep assessment, policy decision, approval, consumption, and native outcome separate. An approved ask remains an ask. Unknown risk or cost is not zero, and budget reservations are not measured usage.

Expanding a Guardrail action shows its state summary followed by Evidence, Decision history, and Approval history as stacked subsections. Each history loads, retries, and paginates independently. Keep empty histories concise and identify unavailable histories explicitly when the canonical assessment is missing. Do not hide these subsections behind tabs; captured context, raw metadata, and identifiers can remain disclosures.

Finding links pin the investigation, attempt, snapshot and retained citations. Use safe text and code components, follow server cursors to the cited item, and show missing archives explicitly. Do not substitute live events or attach retained evidence to page chat. Operator archive pages are read-only; owner approval controls remain in the owner flow.

## Template API

Import from `@/components/page-layout`. Optional properties have `?`:

- `PageSection({ title, titleAction?, description?, action?, children, className? })`: semantic section, `h2`, optional control beside the title, explanation/action, and card body.
- `EmptyState({ title, description, icon?: LucideIcon, action? })`: honest empty result with optional next step.
- `PageNotice({ title, children, collapsible? })`: informational notice; pass `collapsible` for a background explanation that starts closed. Current status and required actions stay visible.
- `LoadingState({ label? })`: announced loading state and decorative skeletons.
- `ErrorState({ message, onRetry? })`: announced error and optional retry.
- `PageToolbar({ children, action? })`: wrapping filters/search and optional actions.
- `TableLayout({ children, footer? })`: bordered, keyboard-scrollable table boundary. Place the existing `Table` inside.
- `SettingsLayout({ children })`: one column, two at `xl`. Children should normally be `PageSection` cards.
- `CollectionFooter({ count, hasMore, busy, onLoadMore, label? })`: loaded count and optional Load more action. Default label is `items`; supply a meaningful plural noun.

Detection Queue shows Investigation reports and detection coverage. Risky Sessions/Users shows the session and user case board at `/user-risk`. The collapsed **Policy findings and user totals** section retains Policy findings below Findings by reported user; `?view=findings` opens it directly. Each section owns its filters, pagination, loading, and errors. An empty or failed section must not hide another section's results. Keep date-range controls on Detection Queue; do not use tabs to switch between sections.

Risky Sessions/Users follows `risk-cases-mockup.html`: two 192px daily stacked charts above two compact, independently paged columns. **Top activity** is the default and ranks observed sessions and reported users, including activity below the investigation threshold. **Cases** retains reports, outcomes, and case filters; `?view=cases` opens it directly. Activity scores use measured actions in the displayed 30-day window; case scores use retained snapshot peaks. Null is unavailable, and measured zero remains zero. Activity links open the session archive; user rows link to their highest-scoring session. Charts always count actual investigation cases. Use a shared integer Y scale and chart tokens 1, 2, and 3 for Under review, TP, and FP. Each keyboard-accessible day opens Cases with that opening-date filter. Search and outcome filters apply to the lists, not chart totals. Stack cards on phones and keep controls reachable. Report previews reuse the retained investigation narrative and citation links. HTML downloads include all contributing reports. Show save conflicts in the report dialog as well as the page and never optimistically claim a verdict was saved. Reported account identities may span devices; OS users remain device-scoped. Missing or conflicting identities stay unattributed sessions. Model conclusions and session/user analyst verdicts remain independent. Cases close at TP/FP; later investigations open a new case. The backend contract and rollout order are documented in Risk cases.

Evidence Search shows one Activity table with user name, device name, session ID, calendar date, and optional activity type filters. Search submits the filters together; Clear filters includes all retained dates. Default to today in the selected Local or UTC zone. Expand a row in place for captured content, raw event data, and linked telemetry records. Optional grouping collects loaded matching activities by native session ID within the sensor and agent product, with the server session UUID as a fallback. Records without usable session identity stay separate. Keep every stored record, including tool results and native records. Group counts describe loaded matches, never complete sessions. Groups sort by latest activity; their activities run oldest first. Changing grouping or the display timezone must not submit unfinished filter edits.

Reported-user finding usernames and counts open a focused `/user-risk/findings` view across both finding sources. Severity links show the full severity name and select open plus triaged findings. The All findings count includes every status. Preserve the exact OS username, including case and whitespace; an empty username means unattributed findings, while no username filter means all users. Keep filters and the selected finding in the URL for refresh, sharing, and browser history. Show removable filter chips, a source selector, and an evidence drawer with links to the exact retained session report where available. On phones, collapse filter editing and keep the drawer close control outside the evidence scroll area. The finding summary and this view both cover all retained findings. Explain that counts can change as records arrive or change status. The reported-user finding summary shows the retained finding total and reported user count without sampling or pagination. The separate Policy findings section lists individual findings with status and severity filters and Load more pagination. Never show missing aggregate fields as measured zero; retain valid cached counts under a warning when a refresh fails.

`TelemetryFilters()` is exported from `@/components/dashboard-shell`. The shell renders telemetry filters, refresh, and status on AI Inventory and App Health (`telemetryFilters`). Live Activity uses `telemetryStatus` for device status without telemetry filters. Overview does not load telemetry snapshots or live activity. Evidence Search uses its own retained event query and does not load telemetry overview snapshots. Do not apply native telemetry controls or errors to administrative resources or legacy event queries.

```tsx
<PageSection title="Members" description="Accounts in this organization.">
  {loading ? (
    <LoadingState label="Loading members…" />
  ) : error ? (
    <ErrorState message={error} onRetry={reload} />
  ) : members.length === 0 ? (
    <EmptyState
      title="No members found"
      description="No accounts matched the current query."
    />
  ) : (
    <>
      <TableLayout>{/* Table, TableHeader, TableBody */}</TableLayout>
      <CollectionFooter
        count={members.length}
        label="members"
        hasMore={Boolean(cursor)}
        busy={loadingMore}
        onLoadMore={loadMore}
      />
    </>
  )}
</PageSection>
```

## Actions, tables, and states

Use buttons for actions and links for navigation. Prefer one primary action per section; refresh, pagination, and cancel use outline or ghost variants. Disable in-flight actions and label their progress. Preserve existing data during refresh. Do not display controls that cannot perform the advertised operation. Never persist credentials in local storage.

Use semantic table headers. The shared `TableHead` primitive renders sentence-case, 12px semibold, muted headers on a muted header row; do not uppercase header text or restyle it per table. Left-align names and descriptions; right-align numeric columns with the `number` class. Keep units explicit: records, exports, spans, metric points, or pending OTLP exports. Zero, unknown, unavailable, and not reported are distinct. Use an explanatory label for unavailable values; never invent zero. Paginated views state the number loaded and expose continuation. Small screens scroll tables without overflowing the whole page.

Status labels include text. Green means confirmed healthy or online; amber means warning or delay; neutral gray means unknown or not reported. Do not infer health because an unrelated endpoint responded. Telemetry connection badges belong only on pages consuming that telemetry.

Highlighted table row (the record a finding points to): the row gets `bg-primary/5`, a 3px primary left accent on its first cell (`[&>td:first-child]:shadow-[inset_3px_0_0_0_var(--primary)]`), `aria-current="true"`, and a primary "Matched record" badge in the first cell so the state never depends on color alone. Scroll the row into view once on mount (`scrollIntoView({ block: "center" })`). When the target lies beyond a table's row cap, show a window centered on it and state the shown range in the footer rather than dropping the row. `RecordsTable` in `src/components/telemetry-panels.tsx` is the reference implementation.

Cross-links from derived data to raw evidence use an outline `xs` button with a Lucide icon and the literal label "Open telemetry record"; the accessible name also includes the event name. Source provenance is a small outline badge with text: "Native telemetry" or "Collector" (`EventSourceBadge`).

Initial requests show loading feedback. Empty successful responses name what has no records and give one short next-step sentence. Keep detailed methodology in the nearby disclosure instead of repeating it in the empty state. Unsupported features use `PageNotice` to explain the missing data or capability. Errors show the recoverable problem and offer retry when available. Permission denial differs from an empty result. Stale data remains visible with an explicit warning.

## Accessibility and review

Use labeled inputs, named icon buttons, visible keyboard focus, semantic landmarks, one `h1`, and ordered heading levels. Decorative icons use `aria-hidden`. Use Radix primitives for dialog, tab, and select keyboard behavior. Loading announcements are polite; failures use alerts. Never rely only on color or put secrets/raw telemetry payloads in screenshots or client logs.

Review phone and desktop widths, keyboard navigation, long names, loading, empty, error, permission, and real populated states. Check that the sidebar scrolls while account controls stay accessible, the mobile drawer closes after navigation, and page-specific controls appear only where relevant. Run the existing typecheck and production build. New pages do not require new dependencies or CI workflows.

## Users and roles

Use the three neutral role tags: IT Admin, Security Analyst, and Security Leadership. Each user can have one, two, or all three. Role filters match membership in the selected role. Sidebar groups and direct page access follow the union of the user's roles; User Risk belongs to Detection and Response.

Use `RoleTags` for noninteractive badges and `RoleSelection` for checkboxes in divided rows. Put the ghost `Edit roles` action in each user row. Reuse the shared dialog, buttons, error state, and typography. The edit dialog opens with the user's current tags, saves explicitly, preserves the draft on errors, and discards it on Cancel. The invitation dialog uses the same selection control. Require at least one role and explain why the last active IT Admin tag cannot be removed. Dialogs scroll within small viewports and keep Save and Cancel reachable.

Only IT Admins manage tags. A role change updates navigation and clears cached page data. Direct visits to unavailable pages show an access restriction message without mounting the page or its data requests. See dashboard role access for the access matrix and API contract.
