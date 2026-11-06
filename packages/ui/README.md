# @openaidr/ui

Shared React components, API clients, hooks, and assets for the Vite
[console](../../apps/console/) and [admin](../../apps/admin/) apps.
The Next.js dashboard owns its shadcn/ui components and Geist fonts; the Tauri
desktop owns its TypeScript and CSS interface. They share the framework-neutral
[coding agent icons](agent-icons/README.md) with the Vite apps.

- `tokens.css`: brand and semantic CSS custom properties (light and dark),
  Geist Sans and Geist Mono font faces, and base element styles. Brand colors mirror
  [`brand/brand.py`](../../brand/brand.py); this file is maintained manually,
  unlike the dashboard's generated brand CSS.
- `fonts/`: unmodified Geist 1.7.2 variable WOFF2 files and shared font-face CSS
  (SIL OFL, see `fonts/Geist-OFL.txt`). Console and admin bundle these assets;
  dashboard previews receive local copies during `sync-brand`.
- `agent-icons/`: original publisher artwork and the shared product-to-icon map.
- `opensecura-mark.svg`, `opensecura-mark-dark.svg`: the mark for light
  and dark backgrounds.
- `src/`: React components, API clients and types, formatting helpers, and hooks.
- `src/styles.css`: imports the tokens and shared component styles.
- `src/fixtures/`: deterministic mock API data and handlers. The apps load these
  through `@openaidr/ui/fixtures` when `VITE_MOCK=1`.

Apps import TypeScript directly from `@openaidr/ui` and styles from
`@openaidr/ui/styles.css`. Their Vite builds bundle the package; it has no
separate build or deployment step. Its React, React Router, and Recharts peer
requirements are declared in [package.json](package.json).

From the repository root, after the workspace setup:

```sh
pnpm --filter @openaidr/ui typecheck
pnpm build
```

The root build compiles the two consuming apps, console and admin.
