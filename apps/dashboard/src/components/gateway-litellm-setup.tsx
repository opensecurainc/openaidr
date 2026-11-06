"use client";

import { PageNotice, PageSection } from "@/components/page-layout";
import { CodeBlock, InlineCode } from "@/components/ui/code-block";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function LiteLLMSetup({ origin, onOriginChange }: { origin: string; onOriginChange: (value: string) => void }) {
  return <PageSection title="Install on LiteLLM" description="Add the OpenAIDR plugin to an operator-approved LiteLLM deployment."><div className="space-y-4">
    <PageNotice title="Contract validation only"><p>This plugin has passed OpenAIDR contract tests. It has not been tested in a running LiteLLM proxy. Verify it in an isolated, approved deployment before relying on enforcement.</p></PageNotice>
    <ol className="list-decimal space-y-3 pl-5 text-sm">
      <li>Extract the OpenAIDR LiteLLM plugin archive into /opt/openaidr on each proxy worker. It contains only OpenAIDR code and shared secret-detection rules. It does not install LiteLLM.</li>
      <li>Inject <InlineCode>OPENAIDR_GATEWAY_TOKEN</InlineCode> from your secret manager. Set a stable, unique node ID for each worker. Add these environment settings, preserving existing Python paths and startup hooks.</li>
    </ol>
    <div className="space-y-2"><Label htmlFor="litellm-backend-url">OpenAIDR backend origin</Label><Input id="litellm-backend-url" type="url" value={origin} onChange={(event) => onOriginChange(event.target.value)} /><p className="text-xs text-muted-foreground">Use the HTTPS origin reachable from LiteLLM. This value only changes the example.</p></div>
    <CodeBlock>{`PYTHONPATH=/opt/openaidr\nLITELLM_WORKER_STARTUP_HOOKS=openaidr_litellm:startup\nOPENAIDR_BACKEND_URL=${JSON.stringify(origin || "https://YOUR_OPENAIDR_HOST")}\nOPENAIDR_NODE_ID=litellm-worker-1\nOPENAIDR_CAPTURE_CONTENT=false\nOPENAIDR_TIMEOUT_MS=1000`}</CodeBlock>
    <p className="text-sm">Append this callback after existing request-transforming callbacks in your proxy configuration, then restart each worker. Keep the backend Guardrail classifier outside this proxy to prevent recursive checks.</p>
    <CodeBlock>{'litellm_settings:\n  callbacks:\n    - openaidr_litellm.plugin'}</CodeBlock>
    <PageNotice title="Capture is opt-in in two places"><p>A security analyst must permit capture under Settings, and the proxy administrator must set OPENAIDR_CAPTURE_CONTENT to true. Configure the backend Guardrail model credential, then verify heartbeats and evaluated requests in Shadow before enabling Enforce.</p></PageNotice>
    <p className="text-sm text-muted-foreground">This pilot checks text chat completions, including streaming requests. Tool definitions, multimodal content and detected secrets are not sent for assessment. Provider completion remains unconfirmed. Evaluation failures allow traffic. For a private CA, set OPENAIDR_CA_FILE to the trusted public certificate file; TLS verification stays enabled.</p>
  </div></PageSection>;
}
