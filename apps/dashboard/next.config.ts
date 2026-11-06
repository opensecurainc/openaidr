import path from "node:path";
import type { NextConfig } from "next";
import { PHASE_DEVELOPMENT_SERVER } from "next/constants";
import { buildInfo } from "../../scripts/build-version.mjs";

export default function config(phase: string): NextConfig {
  const info = buildInfo({ development: phase === PHASE_DEVELOPMENT_SERVER });
  return {
  agentRules: false,
  output: "standalone",
  outputFileTracingRoot: path.resolve(__dirname, "../.."),
  env: {
    NEXT_PUBLIC_BUILD_VERSION: info.version,
    NEXT_PUBLIC_BUILD_COMMIT: info.source_commit,
    NEXT_PUBLIC_BUILD_TIME: info.built_at,
  },
  poweredByHeader: false,
  async rewrites() {
    // Optional development-only same-origin proxy. Production routes these in Caddy.
    const backend = process.env.DASHBOARD_API_PROXY;
    return backend
      ? [
          { source: "/api/:path*", destination: `${backend}/api/:path*` },
          { source: "/ingest/:path*", destination: `${backend}/ingest/:path*` },
          { source: "/otlp/:path*", destination: `${backend}/otlp/:path*` },
          ...["/mcp", "/authorize", "/token", "/revoke", "/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource/mcp"].map((route) => ({ source: route, destination: `${backend}${route}` })),
        ]
      : [];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "same-origin" },
          { key: "X-Frame-Options", value: "DENY" },
        ],
      },
      {
        source: "/:path(accept-invite|enroll)",
        headers: [{ key: "Referrer-Policy", value: "no-referrer" }],
      },
      {
        source: "/mcp/:path*",
        headers: [{ key: "Referrer-Policy", value: "no-referrer" }, { key: "Cache-Control", value: "no-store" }],
      },
    ];
  },
  };
}
