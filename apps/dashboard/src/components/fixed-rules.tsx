"use client";

import { useState } from "react";
import { Plus, RefreshCw, ShieldCheck } from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import { useTimeZone } from "@/components/time-zone-context";
import { EmptyState, ErrorState, LoadingState, PageSection, TableLayout } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Status } from "@/components/ui/status";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, APIError, number } from "@/lib/api";
import { displayText } from "@/lib/display";
import { hasRole } from "@/lib/roles";
import { useResource } from "@/lib/use-resource";
import { FixedRuleEditor, type RuleDraft } from "./fixed-rule-editor";

export type Policy = {
  version: number;
  updated_at?: string;
  rules: {
    id: string;
    name: string;
    enabled: boolean;
    action: string;
    source?: string;
    authoring?: RuleDraft;
    reason?: string;
    match?: {
      kinds?: string[];
      products?: string[];
      tool_name?: string;
      command_regex?: string;
      path_glob?: string;
      host_glob?: string;
    };
  }[];
};

function PolicyMatch({ match }: { match: Policy["rules"][number]["match"] }) {
  const conditions = [
    match?.kinds?.length ? `Kinds: ${match.kinds.join(", ")}` : "",
    match?.products?.length ? `Products: ${match.products.join(", ")}` : "",
    match?.tool_name ? `Tool: ${match.tool_name}` : "",
    match?.command_regex ? `Command regex: ${match.command_regex}` : "",
    match?.path_glob ? `Path: ${match.path_glob}` : "",
    match?.host_glob ? `Host: ${match.host_glob}` : "",
  ].filter(Boolean);
  return conditions.length ? (
    <ul className="max-w-md space-y-1 whitespace-normal break-words text-xs leading-5 text-muted-foreground">
      {conditions.map((condition, index) => (
        <li key={index}>{condition}</li>
      ))}
    </ul>
  ) : (
    <span className="text-muted-foreground">All events</span>
  );
}

export function FixedRules() {
  const { user } = useDashboard();
  return <FixedRulesContent key={`${user?.id}:${user?.tenant.id}:${user?.roles.join(",")}`}
    editable={hasRole(user, "security_analyst")} />;
}

function FixedRulesContent({ editable }: { editable: boolean }) {
  const { dateTime } = useTimeZone();
  const policy = useResource<Policy>("response/policy");
  const [editor, setEditor] = useState<"new" | Policy["rules"][number] | null>(null);
  const [saving, setSaving] = useState("");
  const [saveError, setSaveError] = useState("");

  async function disable(id: string) {
    if (!policy.data || saving || !editable) return;
    setSaving(id);
    setSaveError("");
    try {
      const result = await api<{ policy: Policy }>(`response/policy/rules/${id}`, {
        method: "PATCH", body: JSON.stringify({ version: policy.data.version, enabled: false }),
      });
      policy.setData(result.policy);
    } catch (cause) {
      setSaveError(cause instanceof Error ? cause.message : "Unable to disable the rule.");
      if (cause instanceof APIError && cause.status === 409) await policy.reload();
    } finally {
      setSaving("");
    }
  }

  return (
    <PageSection
      title="Fixed rules"
      description="Rules used by the backend to evaluate installed hooks. Create a draft from a description, then test it before enabling."
      action={
        <div className="flex flex-wrap gap-2">
        {editable && <Button size="sm" disabled={!policy.data || !!policy.error || policy.loading || !!saving}
          onClick={() => setEditor("new")}><Plus />Create rule</Button>}
        <Button variant="outline" size="sm" onClick={policy.reload} disabled={policy.loading}>
          <RefreshCw className={policy.loading ? "animate-spin" : ""} />
          Refresh
        </Button>
        </div>
      }
    >
      {saveError && <p role="alert" className="mb-3 text-sm text-destructive">{saveError}</p>}
      {editor && policy.data && editable && <FixedRuleEditor policy={policy.data}
        existing={editor === "new" ? undefined : editor} onSaved={policy.setData}
        onReload={policy.reload} onClose={() => setEditor(null)} />}
      {policy.error && (
        <ErrorState
          message={`${policy.error}${policy.data ? " Showing stale data from the last successful response." : ""}`}
          onRetry={policy.reload}
        />
      )}
      {!policy.data ? (
        !policy.error && <LoadingState label="Loading fixed rules" />
      ) : (
        <>
          <div className="mb-5 flex flex-wrap gap-5 text-sm">
            <span>
              Version <strong>{policy.data.version}</strong>
            </span>
            <span>
              <strong>
                {number(
                  policy.data.rules.filter((rule) => rule.enabled).length,
                )}
              </strong>{" "}
              enabled rules
            </span>
            <span className="text-muted-foreground">
              Updated {dateTime(policy.data.updated_at ?? null)}
            </span>
          </div>
          {!policy.data.rules.length ? (
            <EmptyState
              icon={ShieldCheck}
              title="No fixed rules"
              description="The current policy has no configured rules. This does not describe detection rules or local telemetry capture settings."
            />
          ) : (
            <TableLayout>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Rule</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Match conditions</TableHead>
                    {editable && <TableHead><span className="sr-only">Manage generated rule</span></TableHead>}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {policy.data.rules.map((rule) => (
                    <TableRow key={rule.id}>
                      <TableCell>
                        <div className="font-medium">
                          {displayText(rule.name || rule.id)}
                        </div>
                        {rule.reason && (
                          <p className="mt-1 max-w-sm whitespace-normal text-xs leading-5 text-muted-foreground">
                            {rule.reason}
                          </p>
                        )}
                      </TableCell>
                      <TableCell>
                        <Status tone={rule.enabled ? "ok" : "neutral"}>
                          {rule.enabled ? "Enabled" : "Disabled"}
                        </Status>
                      </TableCell>
                      <TableCell className="capitalize">
                        {rule.action}
                      </TableCell>
                      <TableCell>
                        <PolicyMatch match={rule.match} />
                      </TableCell>
                      {editable && <TableCell>
                        {rule.source === "tenant_ai" && <Button variant="ghost" size="xs"
                          disabled={!!saving || policy.loading || !!policy.error}
                          onClick={() => rule.enabled ? void disable(rule.id) : setEditor(rule)}>
                          {saving === rule.id ? "Disabling…" : rule.enabled ? "Disable" : "Review and enable"}
                        </Button>}
                      </TableCell>}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableLayout>
          )}
        </>
      )}
    </PageSection>
  );
}
