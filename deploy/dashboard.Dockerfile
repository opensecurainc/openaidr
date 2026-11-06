FROM node:22-bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends python3 tzdata && rm -rf /var/lib/apt/lists/*
RUN corepack enable && corepack prepare pnpm@9.15.9 --activate
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1 DASHBOARD_API_PROXY=http://server:8081
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/dashboard/package.json apps/dashboard/
COPY apps/desktop/package.json apps/desktop/
RUN pnpm --filter openaidr-dashboard... install --frozen-lockfile
COPY apps/dashboard/ apps/dashboard/
# The dashboard imports the shared agent icons, one shared API module, and the
# gateway plugin catalog by relative path.
COPY packages/ui/ packages/ui/
COPY scripts/build-version.mjs scripts/build-version.d.mts scripts/build_version.py scripts/
COPY scripts/sync-agent-icons.mjs scripts/sync-agent-icons.d.mts scripts/
COPY src/openaidr/build_info.py src/openaidr/build_info.py
COPY src/openaidr/core/gateway-plugins.json src/openaidr/core/gateway-plugins.json
ARG OPENAIDR_BUILD_COMMIT
ARG OPENAIDR_COMMIT_TIMESTAMP
RUN pnpm --filter openaidr-dashboard build
FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=3000
COPY --from=builder --chown=node:node /app/apps/dashboard/.next/standalone ./
USER node
EXPOSE 3000
CMD ["node", "apps/dashboard/server.js"]
