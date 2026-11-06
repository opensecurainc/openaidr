"use client";

import { hasRole } from "@/lib/roles";

import { useState } from "react";
import { useDashboard } from "@/components/dashboard-context";
import { ErrorState, LoadingState, PageSection } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";
import { useResource } from "@/lib/use-resource";

type DetectionOwner = {
  session_id: string; status: "unassigned" | "verified" | "revoked" | "managed"; assignable: boolean;
  owner: null | { owner_user_id: string; verified_at: string; name: string; email: string };
  revoked_at: string | null;
};
type TenantAccount = { id: string; name: string; email: string };

export function SessionDetectionOwner({ sessionId }: { sessionId: string }) {
  const { user } = useDashboard();
  const canEdit = hasRole(user, "security_analyst");
  const resource = useResource<DetectionOwner>(user ? `sessions/${sessionId}/detection-owner` : null);
  const accounts = useResource<{ items: TenantAccount[] }>(canEdit && resource.data?.assignable ? "users/detection-owners" : null);
  const [selected, setSelected] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const save = async (owner: string | null) => {
    setSaving(true); setError("");
    try {
      resource.setData(await api<DetectionOwner>(`sessions/${sessionId}/detection-owner`, { method: "PUT", body: JSON.stringify({ owner_user_id: owner }) }));
      setSelected("");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to update session ownership."); }
    finally { setSaving(false); }
  };
  const data = resource.data;
  return <PageSection title="Detection user context" description="Verified ownership permits the investigator to retrieve this user's recent sessions within the tenant.">
    <div className="space-y-3 text-sm">
      {resource.error && <ErrorState message={resource.error} onRetry={resource.reload} />}
      {!data && !resource.error && <LoadingState label="Loading detection ownership…" />}
      {error && <ErrorState message={error} />}
      {data?.owner && <p className="break-words">Verified user: {data.owner.name || data.owner.email}{data.owner.name && data.owner.email ? ` (${data.owner.email})` : ""}</p>}
      {data?.status === "unassigned" && <p>No verified user is assigned. Reported device usernames do not authorize access to other sessions.</p>}
      {data?.status === "revoked" && <p>Detection ownership was revoked. This session cannot be reassigned or used to authorize new cross-session reads.</p>}
      {canEdit && data?.assignable && <form className="space-y-3" onSubmit={(event) => { event.preventDefault(); if (selected) void save(selected); }}>
        <p className="max-w-3xl text-xs text-muted-foreground">Assign only after verifying who owns this session. The assignment cannot be changed to another user. Revocation permanently removes its history authorization.</p>
        {accounts.error && <ErrorState message={accounts.error} onRetry={accounts.reload} />}
        <div className="flex flex-wrap gap-2">
          <Select value={selected} onValueChange={setSelected} disabled={saving || accounts.loading}>
            <SelectTrigger aria-label="Verified session user" className="w-full max-w-md"><SelectValue placeholder="Select an active tenant user" /></SelectTrigger>
            <SelectContent>{accounts.data?.items.map((account) =>
              <SelectItem key={account.id} value={account.id}>{account.name ? `${account.name} (${account.email})` : account.email}</SelectItem>)}</SelectContent>
          </Select>
          <Button type="submit" disabled={!selected || saving}>Assign verified user</Button>
        </div>
      </form>}
      {canEdit && data?.status === "verified" && <Button variant="outline" disabled={saving} onClick={() => void save(null)}>Revoke detection ownership</Button>}
    </div>
  </PageSection>;
}
