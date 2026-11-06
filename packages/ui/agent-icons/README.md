# Coding agent icons

This directory is the source of truth for coding agent artwork across the
repository. `index.js` maps reported product IDs and existing UI aliases to the
same local image. Unknown products return no image so the caller can show its
neutral fallback. Model-provider marks are separate from coding agent icons.

Import `agentIcon` from `index.js` and render the returned URL as an image with
its original colors and aspect ratio. The Codex image uses a black background
and rounded corners, as in the OpenAIDR desktop app. Images beside a visible
agent name should have empty alt text.

`scripts/sync-agent-icons.mjs` copies this directory into consuming apps at
`public/agent-icons/`. Dashboard, desktop, and console development and build
commands run it automatically. These generated copies are ignored by Git.
The inventory preview imports the same catalog from `/agent-icons/index.js`.
Add or replace artwork here, update the catalog, and restart the development
server. Do not edit generated copies or add a second agent icon catalog.

Publisher artwork, retrieved on 2026-10-23:

- `codex.png`: the exact asset previously bundled by the desktop app, from
  [Codex by OpenAI](https://marketplace.visualstudio.com/items?itemName=openai.chatgpt),
  [publisher image](https://openai.gallerycdn.vsassets.io/extensions/openai/chatgpt/26.51007.21434/1791508178385/Microsoft.VisualStudio.Services.Icons.Default).
- `claude-code.png`: the exact asset previously bundled by the desktop app, from
  [Claude Code by Anthropic](https://marketplace.visualstudio.com/items?itemName=anthropic.claude-code),
  [publisher image](https://anthropic.gallerycdn.vsassets.io/extensions/anthropic/claude-code/2.1.309/1792707671491/Microsoft.VisualStudio.Services.Icons.Default).
  Cowork and Claude chat use this same Claude artwork.
- `github-copilot.png`: [GitHub Copilot](https://marketplace.visualstudio.com/items?itemName=GitHub.copilot),
  [publisher image](https://GitHub.gallerycdn.vsassets.io/extensions/github/copilot/1.388.0/1761326434179/Microsoft.VisualStudio.Services.Icons.Default).
  Both Copilot product IDs use this image.
- `cursor.png`: `App Icons/PNG/APP_ICON_25D_LIGHT.png` from
  [Cursor's brand asset archive](https://ptht05hbb1ssoooe.public.blob.vercel-storage.com/assets/brand/cursor-brand-assets.zip),
  linked by [Cursor's brand guidelines](https://cursor.com/brand).
- `gemini-cli.png`: [Gemini CLI's site icon](https://geminicli.com/icon.png).
- `antigravity.svg`: [Google Antigravity's favicon](https://antigravity.google/favicon.svg).
- `opencode.png`: [OpenCode's favicon](https://github.com/anomalyco/opencode/blob/dev/packages/ui/src/assets/favicon/favicon-96x96.png),
  under the [MIT license](opencode.LICENSE).
- `aider.png`: [Aider's favicon](https://aider.chat/assets/icons/favicon-32x32.png),
  under the [Apache 2.0 license](aider.LICENSE).
- `windsurf.svg`: [Windsurf's favicon](https://windsurf.com/favicon.svg), used by
  the application inventory preview.

All image files retain their publisher bytes. They are bundled locally, so
displaying an agent icon makes no request to the publisher or Marketplace.
Product trademarks remain the property of their respective owners.

- `workbuddy.svg`: the [WorkBuddy publisher favicon](https://download.codebuddy.ai/web/workbuddy/170b416d2eccaaf590ea40cd918d5a6b4f07178f/assets/logo.svg),
  linked by [WorkBuddy's official site](https://www.workbuddy.ai/), retrieved on
  2026-11-03.

- `hermes.png`: [Hermes Agent publisher favicon](https://github.com/NousResearch/hermes-agent/blob/290080e19e8e143d35f67427e89aed662161faf8/website/static/img/favicon-32x32.png),
  under the [MIT license](hermes.LICENSE).
