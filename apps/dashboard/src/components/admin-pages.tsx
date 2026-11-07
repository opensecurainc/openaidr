"use client";

import { SessionDetectionToggle } from "@/components/session-detection-toggle";
import { MCPConnections } from "@/components/dashboard-mcp";

import { useTimeZone } from "@/components/time-zone-context";
import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import Link from "next/link";
import {
  ArrowUpRight,
  Check,
  Copy,
  KeyRound,
  Plus,
  Pencil,
  RefreshCw,
  Terminal,
  Users,
} from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import { DatabaseHealthPanel } from "@/components/database-health";
import { HostMetricsPanel } from "@/components/host-metrics";
import { DatabaseDiagnosticsPanel } from "@/components/database-diagnostics";
import { TelemetryRetention } from "@/components/telemetry-retention";
import { SlackNotifications } from "@/components/slack-notifications";
import { SupportSettings } from "@/components/support";
import { ModelApiKeys } from "@/components/model-api-keys";
import { SummaryReportSharing } from "@/components/summary-report-sharing";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  PageNotice,
  PageSection,
  PageToolbar,
  SettingsLayout,
  TableLayout,
} from "@/components/page-layout";
import { Status } from "@/components/ui/status";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api, number } from "@/lib/api";
import { ROLES, hasRole, roleNames, type Role } from "@/lib/roles";
import { RoleTags, RoleSelection } from "@/components/role-tags";
import { useResource } from "@/lib/use-resource";
import { desktopInstallCommand } from "@/lib/install-command";
import type { DesktopPlatform } from "@/lib/desktop-downloads";

type TenantUser = {
  id: string;
  name: string;
  email: string;
  roles: Role[];
  status: string;
  created_at: string;
  last_login_at: string | null;
};
type EnrollmentToken = {
  id: string;
  label: string;
  created_at: string;
  expires_at: string | null;
  uses: number;
  max_uses: number;
  revoked_at: string | null;
};
type CreatedToken = EnrollmentToken & { enrollment_url: string };
type SystemStatus = {
  version: string;
  services: {
    name: string;
    status: string;
    last_seen_at: string | null;
    lag_events?: number;
    last_run_at?: string;
  }[];
  database: { ok: boolean; latency_ms: number };
  ingest: { events_last_hour: number; sensors_online: number };
};
function Refresh({
  reload,
  loading,
}: {
  reload: () => void;
  loading: boolean;
}) {
  return (
    <Button variant="outline" size="sm" onClick={reload} disabled={loading}>
      <RefreshCw className={loading ? "animate-spin" : ""} />
      Refresh
    </Button>
  );
}
function Detail({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid gap-1 border-b py-2 last:border-0 sm:grid-cols-[150px_1fr] sm:gap-4">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words text-sm font-medium">{children}</dd>
    </div>
  );
}
function ErrorMessage({ message }: { message: string }) {
  return message ? (
    <p
      role="alert"
      className="rounded-md border-l-4 border-status-critical bg-status-critical/10 px-3 py-2 text-sm text-foreground"
    >
      {message}
    </p>
  ) : null;
}

export function UsersPage() {
  const { dateTime } = useTimeZone();
  const { user } = useDashboard();
  const resource = useResource<{ items: TenantUser[] }>(user ? "users" : null);
  const [query, setQuery] = useState("");
  const [role, setRole] = useState("");
  const users = useMemo(
    () =>
      (resource.data?.items ?? []).filter(
        (item) =>
          (!role || item.roles.includes(role as Role)) &&
          `${item.name} ${item.email}`
            .toLowerCase()
            .includes(query.toLowerCase()),
      ),
    [resource.data, query, role],
  );
  return (
    <div className="space-y-4">
      <PageSection
        title="Tenant users"
        description="Accounts with access to this tenant and their assigned roles."
        action={
          <div className="flex flex-wrap gap-2">
            <Refresh reload={resource.reload} loading={resource.loading} />
            {hasRole(user, "it_admin") && <InviteUserDialog />}
          </div>
        }
      >
        <PageToolbar>
          <div className="flex flex-wrap gap-3">
            <Input
              aria-label="Search users"
              placeholder="Search name or email"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              className="w-full sm:w-64"
            />
            <Select
              value={role || "all"}
              onValueChange={(value) => setRole(value === "all" ? "" : value)}
            >
              <SelectTrigger aria-label="Filter by role">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All roles</SelectItem>
                {ROLES.map((item) => (
                  <SelectItem key={item.name} value={item.value}>
                    {item.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </PageToolbar>
        {resource.error && (
          <ErrorState
            message={`${resource.error}${resource.data ? " Showing stale data from the last successful response." : ""}`}
            onRetry={resource.reload}
          />
        )}
        {!resource.data ? (
          !resource.error && <LoadingState label="Loading users" />
        ) : !users.length ? (
          <EmptyState
            icon={Users}
            title={
              resource.data.items.length
                ? "No matching users"
                : "No users returned"
            }
            description={
              resource.data.items.length
                ? "Change the search or role filter to see other accounts."
                : "User accounts will appear here when they are available."
            }
          />
        ) : (
          <TableLayout
            footer={`${number(users.length)} ${users.length === 1 ? "user" : "users"}`}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Roles</TableHead>
                  <TableHead>Account status</TableHead>
                  <TableHead>Last sign-in</TableHead>
                  <TableHead><span className="sr-only">Actions</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell>
                      <div className="font-medium">
                        {item.name || item.email}
                        {item.id === user?.id && (
                          <span className="ml-2 text-xs text-muted-foreground">
                            You
                          </span>
                        )}
                      </div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {item.email}
                      </div>
                    </TableCell>
                    <TableCell>
                      <RoleTags roles={item.roles} />
                    </TableCell>
                    <TableCell>
                      <Status tone={item.status === "active" ? "ok" : "neutral"} className="capitalize">{item.status || "Not reported"}</Status>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {item.last_login_at
                        ? dateTime(item.last_login_at)
                        : "No sign-in recorded"}
                    </TableCell>
                    <TableCell className="text-right">
                      {hasRole(user, "it_admin") && <EditRolesDialog
                        target={item}
                        retainAdmin={item.status === "active" && item.roles.includes("it_admin") && (resource.data?.items ?? []).filter((account) => account.status === "active" && account.roles.includes("it_admin")).length === 1}
                        onSaved={resource.reload}
                      />}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableLayout>
        )}
      </PageSection>
      <PageNotice title="Role permissions" collapsible>
        <p>Users can have multiple roles. Access combines across their assigned roles. IT Admins can add or remove role tags for users in this tenant.</p>
        <dl className="divide-y">
          {ROLES.map((item) => (
            <div
              key={item.name}
              className="grid gap-1 py-3 first:pt-0 last:pb-0 sm:grid-cols-[180px_1fr] sm:gap-4"
            >
              <dt className="text-sm font-semibold">{item.name}</dt>
              <dd className="text-sm text-muted-foreground">
                {item.description}
              </dd>
            </div>
          ))}
        </dl>
      </PageNotice>
    </div>
  );
}

function EditRolesDialog({ target, retainAdmin, onSaved }: {
  target: TenantUser;
  retainAdmin: boolean;
  onSaved: () => void;
}) {
  const { user, refreshUser } = useDashboard();
  const [open, setOpen] = useState(false);
  const [selectedRoles, setSelectedRoles] = useState<Role[]>(target.roles);
  const [busy, setBusy] = useState(false);
  const submitting = useRef(false);
  const [error, setError] = useState("");
  function changeOpen(value: boolean) {
    if (submitting.current) return;
    setOpen(value);
    setSelectedRoles(target.roles);
    setError("");
  }
  async function save(event: FormEvent) {
    event.preventDefault();
    if (submitting.current || !selectedRoles.length) return;
    submitting.current = true;
    setBusy(true);
    setError("");
    try {
      await api(`users/${target.id}`, { method: "PATCH", body: JSON.stringify({ roles: selectedRoles }) });
      if (target.id === user?.id) await refreshUser();
      onSaved();
      setOpen(false);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Unable to save roles.");
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }
  const unchanged = selectedRoles.length === target.roles.length && selectedRoles.every((role) => target.roles.includes(role));
  return (
    <Dialog open={open} onOpenChange={changeOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="xs" aria-label={`Edit roles for ${target.name || target.email}`}><Pencil />Edit roles</Button>
      </DialogTrigger>
      <DialogContent
        className="max-h-[calc(100dvh-2rem)] overflow-y-auto"
        onInteractOutside={(event) => { if (busy) event.preventDefault(); }}
        onEscapeKeyDown={(event) => { if (busy) event.preventDefault(); }}
      >
        <DialogHeader>
          <DialogTitle>Edit roles</DialogTitle>
          <DialogDescription className="break-words">{target.name || target.email}{target.name && ` · ${target.email}`}</DialogDescription>
        </DialogHeader>
        <form onSubmit={save} className="space-y-4">
          <RoleSelection value={selectedRoles} onChange={setSelectedRoles} disabled={busy} retainAdmin={retainAdmin} />
          <ErrorMessage message={error} />
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={() => changeOpen(false)}>Cancel</Button>
            <Button type="submit" disabled={busy || !selectedRoles.length || unchanged}>{busy ? "Saving…" : "Save roles"}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function InviteUserDialog() {
  const { dateTime } = useTimeZone();
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [selectedRoles, setSelectedRoles] = useState<Role[]>([]);
  const [created, setCreated] = useState<{
    email: string;
    roles: Role[];
    accept_url: string;
    expires_at: string;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const submitting = useRef(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  function changeOpen(value: boolean) {
    if (submitting.current) return;
    setOpen(value);
    setEmail("");
    setSelectedRoles([]);
    setCreated(null);
    setError("");
    setCopied(false);
  }
  async function invite(event: FormEvent) {
    event.preventDefault();
    if (submitting.current || !selectedRoles.length) return;
    submitting.current = true;
    setBusy(true);
    setError("");
    try {
      const result = await api<NonNullable<typeof created>>("users/invites", {
        method: "POST",
        body: JSON.stringify({ email: email.trim(), roles: selectedRoles }),
      });
      if (!result.accept_url) throw new Error("The server did not return an invitation link.");
      setCreated(result);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Unable to create the invitation.");
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }
  async function copyLink() {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.accept_url);
      setCopied(true);
      setError("");
    } catch {
      setError("Clipboard access is unavailable. Select and copy the link directly.");
    }
  }
  return (
    <Dialog open={open} onOpenChange={changeOpen}>
      <DialogTrigger asChild>
        <Button size="sm"><Plus />Invite user</Button>
      </DialogTrigger>
      <DialogContent
        className="max-h-[calc(100dvh-2rem)] overflow-y-auto"
        onInteractOutside={(event) => { if (busy) event.preventDefault(); }}
        onEscapeKeyDown={(event) => { if (busy) event.preventDefault(); }}
      >
        <DialogHeader>
          <DialogTitle>{created ? "Invitation created" : "Invite user"}</DialogTitle>
          <DialogDescription>
            {created
              ? "Copy this link before closing and share it with the invited person."
              : "Choose an email and one or more roles. You’ll get an invitation link to share."}
          </DialogDescription>
        </DialogHeader>
        {created ? (
          <div className="space-y-4">
            <p className="break-words text-sm">
              Invited <strong>{created.email}</strong> with {roleNames(created.roles)}.
              The invitation expires {dateTime(created.expires_at)}.
            </p>
            <div className="space-y-2">
              <Label htmlFor="user-invite-link">Invitation link</Label>
              <Input
                id="user-invite-link"
                value={created.accept_url}
                readOnly
                autoComplete="off"
                spellCheck={false}
                onFocus={(event) => event.target.select()}
              />
            </div>
            <ErrorMessage message={error} />
            <DialogFooter>
              <Button variant="outline" onClick={copyLink}>
                {copied ? <Check /> : <Copy />}{copied ? "Copied" : "Copy link"}
              </Button>
              <Button onClick={() => changeOpen(false)}>Done</Button>
            </DialogFooter>
          </div>
        ) : (
          <form onSubmit={invite} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="invite-email">Email address</Label>
              <Input
                id="invite-email"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="person@company.com"
                autoComplete="email"
                required
                disabled={busy}
              />
            </div>
            <RoleSelection value={selectedRoles} onChange={setSelectedRoles} disabled={busy} />
            <ErrorMessage message={error} />
            <DialogFooter>
              <Button type="button" variant="outline" disabled={busy} onClick={() => changeOpen(false)}>Cancel</Button>
              <Button type="submit" disabled={busy || !selectedRoles.length}>{busy ? "Creating…" : "Create invitation"}</Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

export function ServerPage() {
  const { dateTime, timeZone } = useTimeZone();
  const { user } = useDashboard();
  const resource = useResource<SystemStatus>(user ? "system/status" : null, 30000, false, { sourceCard: "server-status" });
  const status = resource.data;
  const detect = status?.services.find((item) => item.name === "detect");
  const heartbeats = new Map<string, string[]>();
  for (const service of status?.services ?? []) {
    if (!service.last_seen_at) continue;
    const names = heartbeats.get(service.last_seen_at) ?? [];
    names.push(service.name === "api" ? "API" : service.name);
    heartbeats.set(service.last_seen_at, names);
  }
  return (
    <div className="space-y-4">
      <div className="grid items-start gap-3 xl:grid-cols-2 xl:items-stretch xl:[&_[data-slot=card]]:h-full [&_[data-slot=card-header]]:py-2 [&_[data-slot=card-header]>div:first-child]:min-w-0 [&_[data-slot=section-body]]:pb-3">
        <PageSection
          title="API health"
          className="min-w-0"
          action={<Refresh reload={resource.reload} loading={resource.loading} />}
        >
          {resource.error && (
            <ErrorState
              message={`${resource.error}${status ? " Showing stale data from the last successful response." : ""}`}
              onRetry={resource.reload}
            />
          )}
          {!status ? (
            !resource.error && <LoadingState label="Loading server status" />
          ) : (
            <div className="space-y-3">
              <dl className="flex flex-wrap gap-x-5 gap-y-1">
                <div className="flex min-w-0 items-baseline gap-2">
                  <dt className="shrink-0 text-xs text-muted-foreground">Server version</dt>
                  <dd className={status.version ? "break-all font-mono text-sm font-normal" : "font-medium"}>{status.version || "Not reported"}</dd>
                </div>
                <div className="flex items-baseline gap-2">
                  <dt className="text-xs text-muted-foreground">Sensors reporting</dt>
                  <dd className="number text-sm font-semibold">{number(status.ingest.sensors_online)}</dd>
                </div>
              </dl>
              <ul className="grid gap-x-4 gap-y-2 border-y py-2 min-[380px]:grid-cols-2">
                {status.services.map((item) => (
                  <li key={item.name} className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
                    <p className="text-sm font-medium capitalize">{item.name === "api" ? "API" : item.name}</p>
                    <Status tone={!item.last_seen_at ? "neutral" : item.status === "ok" ? "ok" : item.status === "stale" ? "warning" : "neutral"}>
                      {!item.last_seen_at ? "Not reporting" : item.status === "ok" ? "Reporting" : item.status === "stale" ? "Stale report" : "Unknown"}
                    </Status>
                  </li>
                ))}
              </ul>
              {heartbeats.size > 0 && (
                <dl aria-label="Last heartbeats" className="space-y-1 text-xs text-muted-foreground">
                  {Array.from(heartbeats, ([timestamp, names]) => (
                    <div key={timestamp} className="flex flex-wrap gap-x-2">
                      <dt><span className="capitalize">{names.join(", ")}</span> heartbeat</dt>
                      <dd><time dateTime={timestamp}>{dateTime(timestamp)}</time></dd>
                    </div>
                  ))}
                </dl>
              )}
              {typeof detect?.lag_events === "number" && (
                <div className="text-sm">
                  <p>{number(detect.lag_events)} normalized events pending</p>
                  {detect.last_run_at && <p className="mt-0.5 text-xs text-muted-foreground">Detection last ran {dateTime(detect.last_run_at)}</p>}
                </div>
              )}
              {resource.updated && <p className="text-xs text-muted-foreground">Checked {resource.updated.toLocaleTimeString(undefined, { timeZone })}</p>}
            </div>
          )}
        </PageSection>
        <DatabaseHealthPanel connection={status?.database} connectionStale={Boolean(resource.error)} />
      </div>
      <HostMetricsPanel />
      <DatabaseDiagnosticsPanel />
      <PageNotice title="Reading component status" collapsible>
        <p>
          A missing heartbeat means the component has not reported. It does not
          establish whether that component is running. Dedicated deployments can
          run only the API and ingest components; absent detect or admin reports
          are expected in that setup.
        </p>
        <p>
          Database reachability does not establish available capacity. Pool counts
          describe this API process and show busy or opening connections / pool limit.
          Pool and query diagnostics require an
          explicitly enabled database dedicated to this tenant. Query activity
          covers the application database role, including other processes. The
          health check itself is excluded. Check time includes waiting for a
          diagnostic connection. This card shows current snapshots, not query
          history or per-query CPU and memory measurements.
        </p>
      </PageNotice>
    </div>
  );
}

function tokenStatus(token: EnrollmentToken) {
  if (token.revoked_at) return "Revoked";
  if (token.expires_at && new Date(token.expires_at).getTime() <= Date.now())
    return "Expired";
  if (token.max_uses > 0 && token.uses >= token.max_uses) return "Exhausted";
  return "Active";
}
export function EnrollmentPage() {
  const { dateTime } = useTimeZone();
  const { user } = useDashboard();
  const permitted = hasRole(user, "it_admin");
  const resource = useResource<{ items: EnrollmentToken[] }>(
    permitted ? "sensors/enrollment-tokens" : null,
    30000,
  );
  const { reload } = resource;
  useEffect(() => {
    if (!permitted) return;
    function refreshOnReturn() {
      if (!document.hidden) void reload();
    }
    document.addEventListener("visibilitychange", refreshOnReturn);
    return () => document.removeEventListener("visibilitychange", refreshOnReturn);
  }, [permitted, reload]);
  const [createOpen, setCreateOpen] = useState(false);
  const [installPlatform, setInstallPlatform] = useState<DesktopPlatform | null>(null);
  const [macInstallMode, setMacInstallMode] = useState<"interactive" | "mdm">("interactive");
  const [label, setLabel] = useState("");
  const [hours, setHours] = useState("1");
  const [maxUses, setMaxUses] = useState("100");
  const [created, setCreated] = useState<CreatedToken | null>(null);
  const [revoke, setRevoke] = useState<EnrollmentToken | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const [commandCopied, setCommandCopied] = useState(false);
  const [notice, setNotice] = useState("");
  const [page, setPage] = useState(0);
  const pageSize = 10;
  const tokens = resource.data?.items ?? [];
  const currentPage = Math.min(page, Math.max(0, Math.ceil(tokens.length / pageSize) - 1));
  const pageStart = currentPage * pageSize;
  const mdmInstall = installPlatform === "mac" && macInstallMode === "mdm";
  const installCommand = created && installPlatform ? desktopInstallCommand(created.enrollment_url, window.location.origin, installPlatform, mdmInstall ? "mdm" : "interactive") : null;
  const platformName = installPlatform ? { mac: "Mac", windows: "Windows", linux: "Linux" }[installPlatform] : null;
  const createTitle = platformName ? `Create ${platformName} install script` : "Create enrollment link";
  function changeCreate(open: boolean, platform: DesktopPlatform | null = null) {
    if (busy) return;
    setCreateOpen(open);
    setCreated(null);
    setCopied(false);
    setCommandCopied(false);
    setError("");
    if (open) {
      setInstallPlatform(platform);
      setMacInstallMode("interactive");
      setLabel("");
      setHours("1");
      setMaxUses("100");
    }
  }
  async function createToken(event: FormEvent) {
    event.preventDefault();
    const expiry = Number(hours);
    if (!Number.isSafeInteger(expiry) || expiry < 1 || expiry > 168) {
      setError("Choose an expiration between 1 hour and 7 days.");
      return;
    }
    const uses = Number(maxUses);
    if (!Number.isSafeInteger(uses) || uses < 1 || uses > 2147483647) {
      setError("Max uses must be a whole number between 1 and 2,147,483,647.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      let tokenLabel = label.trim();
      if (!tokenLabel) {
        const now = new Date();
        const timestamp = [now.getMonth() + 1, now.getDate(), now.getHours(), now.getMinutes()]
          .map((part) => String(part).padStart(2, "0"))
          .join("");
        tokenLabel = `${now.getFullYear()}${timestamp}_rollout`;
      }
      const result = await api<CreatedToken>("sensors/enrollment-links", {
        method: "POST",
        body: JSON.stringify({
          label: tokenLabel,
          expires_in_hours: expiry,
          max_uses: uses,
        }),
      });
      if (!result.enrollment_url)
        throw new Error("The server did not return an enrollment link.");
      setCreated(result);
      setPage(0);
      resource.reload();
    } catch (failure) {
      setError(
        failure instanceof Error
          ? failure.message
          : "Unable to create the enrollment link.",
      );
    } finally {
      setBusy(false);
    }
  }
  async function revokeToken() {
    if (!revoke) return;
    setBusy(true);
    setError("");
    try {
      await api(`sensors/enrollment-tokens/${encodeURIComponent(revoke.id)}`, {
        method: "DELETE",
      });
      setRevoke(null);
      setNotice(
        "Enrollment token revoked. Existing sensor credentials are unchanged.",
      );
      resource.reload();
    } catch (failure) {
      setError(
        failure instanceof Error
          ? failure.message
          : "Unable to revoke the enrollment token.",
      );
    } finally {
      setBusy(false);
    }
  }
  async function copyToken() {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.enrollment_url);
      setCopied(true);
      setError("");
    } catch {
      setError(
        "Clipboard access is unavailable. Select and copy the link directly.",
      );
    }
  }
  async function copyInstallCommand() {
    if (!installCommand) return;
    try {
      await navigator.clipboard.writeText(installCommand);
      setCommandCopied(true);
      setError("");
    } catch {
      setError("Clipboard access is unavailable. Open View install script to select and copy it.");
    }
  }
  if (!user) return <LoadingState label="Loading account permissions" />;
  if (!permitted)
    return (
      <PageNotice title="Administrator access required">
        An IT Admin can view and manage enrollment tokens for this
        tenant. Your current roles are {roleNames(user.roles)}.
      </PageNotice>
    );
  return (
    <div className="space-y-4">
      <PageSection
        title="Enrollment tokens"
        description="Create a link to connect devices and apply your organization’s configuration."
        action={
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={() => changeCreate(true)}>
              <Plus />
              Create enrollment link
            </Button>
            <Button variant="outline" size="sm" onClick={() => changeCreate(true, "mac")}>
              <Terminal />
              Mac install script
            </Button>
            <Button variant="outline" size="sm" onClick={() => changeCreate(true, "windows")}>
              <Terminal />
              Win install script
            </Button>
            <Button variant="outline" size="sm" onClick={() => changeCreate(true, "linux")}>
              <Terminal />
              Lin install script
            </Button>
          </div>
        }
      >
        {notice && (
          <p
            role="status"
            className="mb-4 rounded-md border-l-4 border-status-info/50 bg-status-info/5 px-4 py-3 text-sm"
          >
            {notice}
          </p>
        )}
        {resource.error && (
          <ErrorState
            message={`${resource.error}${resource.data ? " Showing stale data from the last successful response." : ""}`}
            onRetry={resource.reload}
          />
        )}
        {!resource.data ? (
          !resource.error && <LoadingState label="Loading enrollment tokens" />
        ) : !resource.data.items.length ? (
          <EmptyState
            icon={KeyRound}
            title="No enrollment tokens"
            description="Create an enrollment link for a workstation or server."
            action={
              <Button onClick={() => changeCreate(true)}>
                <Plus />
                Create enrollment link
              </Button>
            }
          />
        ) : (
          <TableLayout
            footer={
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p>
                    {number(pageStart + 1)}–{number(Math.min(pageStart + pageSize, tokens.length))} of {number(tokens.length)} tokens
                  </p>
                  <p>Secret values are not included in this inventory</p>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="responsive"
                    aria-label="Previous enrollment page"
                    disabled={currentPage === 0}
                    onClick={() => setPage(currentPage - 1)}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="responsive"
                    aria-label="Next enrollment page"
                    disabled={pageStart + pageSize >= tokens.length}
                    onClick={() => setPage(currentPage + 1)}
                  >
                    Next
                  </Button>
                </div>
              </div>
            }
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Label</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Uses</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tokens.slice(pageStart, pageStart + pageSize).map((item) => (
                  <TableRow key={item.id}>
                    <TableCell>
                      <div className="font-medium">
                        {item.label || "Untitled token"}
                      </div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        ID {item.id.slice(0, 8)}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Status
                        tone={tokenStatus(item) === "Active" ? "ok" : "neutral"}
                      >
                        {tokenStatus(item)}
                      </Status>
                    </TableCell>
                    <TableCell className="number">
                      {number(item.uses)} /{" "}
                      {item.max_uses ? number(item.max_uses) : "Unlimited"}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {item.expires_at
                        ? dateTime(item.expires_at)
                        : "No expiration"}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {dateTime(item.created_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="xs"
                        disabled={!!item.revoked_at}
                        aria-label={`Revoke ${item.label || "untitled token"}`}
                        onClick={() => {
                          setRevoke(item);
                          setError("");
                        }}
                      >
                        Revoke
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableLayout>
        )}
      </PageSection>
      <PageNotice title="Separate enrollment and sensor credentials" collapsible>
        Enrollment tokens register devices. Each enrolled sensor receives its
        own credential, so revoking an enrollment token does not disconnect
        devices already registered.
      </PageNotice>
      <Dialog open={createOpen} onOpenChange={changeCreate}>
        <DialogContent
          className="max-h-[calc(100dvh-2rem)] overflow-y-auto"
          onInteractOutside={(event) => {
            if (busy) event.preventDefault();
          }}
          onEscapeKeyDown={(event) => {
            if (busy) event.preventDefault();
          }}
        >
          <DialogHeader>
            <DialogTitle>
              {created ? (platformName ? `${platformName} install script created` : "Enrollment link created") : createTitle}
            </DialogTitle>
            <DialogDescription>
              {created
                ? (installPlatform ? "Copy the link or install script now. They cannot be retrieved after this window closes." : "Copy this link now. It cannot be retrieved after this window closes.")
                : installPlatform
                  ? "Create a command to install OpenAIDR and connect devices up to the maximum uses. Leave the label blank to generate one automatically."
                  : "Choose how many devices can enroll with this link. Leave the label blank to generate one automatically."}
            </DialogDescription>
          </DialogHeader>
          {created ? (
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="issued-link">Enrollment link</Label>
                <Input
                  id="issued-link"
                  value={created.enrollment_url}
                  readOnly
                  autoComplete="off"
                  spellCheck={false}
                  className="text-xs"
                  onFocus={(event) => event.target.select()}
                />
              </div>
              <p className="text-sm text-muted-foreground">
                Paste this link into OpenAIDR. The app shows the organization
                before connecting and sets up the device automatically. The link expires
                {created.expires_at ? ` ${dateTime(created.expires_at)}` : ""} and allows up to{" "}
                {number(created.max_uses)} {created.max_uses === 1 ? "enrollment" : "enrollments"}.
              </p>
              {installCommand && (
                <div className="space-y-3 rounded-md border p-3">
                  <p className="text-sm font-medium">{mdmInstall ? "Silent MDM installation" : "Install and connect this device"}</p>
                  <p className="text-sm text-muted-foreground">
                    {mdmInstall
                      ? "Run through MDM as root or as the logged-in user on a Mac with macOS 12 or later, Apple Silicon or Intel. A new install needs write access to /Applications. Installs and connects without confirmation dialogs or opening the app. MDM manages app updates."
                      : installPlatform === "mac"
                      ? "Paste into Terminal on a Mac with macOS 12 or later, Apple Silicon or Intel."
                      : installPlatform === "windows"
                        ? "Paste into 64-bit PowerShell on Windows x64, without Run as administrator."
                        : "Paste into Terminal on Ubuntu or Debian x64. Requires Python 3, curl, GnuPG, and sudo access for package installation."}
                    {" "}Downloads and verifies OpenAIDR from releases.opensecura.ai.
                    {!mdmInstall && " Asks you to confirm the organization before connecting."}
                  </p>
                  <Button variant="outline" className="w-full" onClick={copyInstallCommand}>
                    {commandCopied ? <Check /> : <Copy />}
                    {commandCopied ? `${platformName} script copied` : `Copy ${platformName} install script`}
                  </Button>
                  <p className="text-xs text-muted-foreground">
                    Contains the same enrollment link and shares its use limit. Share only with
                    intended recipients. Your shell may save the command in history.
                  </p>
                  <details className="text-sm">
                    <summary className="cursor-pointer text-muted-foreground">View install script</summary>
                    <Textarea
                      aria-label={`${platformName} install script`}
                      value={installCommand}
                      readOnly
                      rows={6}
                      autoComplete="off"
                      spellCheck={false}
                      className="mt-2 max-h-48 font-mono text-xs"
                      onFocus={(event) => event.target.select()}
                    />
                  </details>
                </div>
              )}
              <ErrorMessage message={error} />
              <DialogFooter>
                <Button variant="outline" onClick={copyToken}>
                  {copied ? <Check /> : <Copy />}
                  {copied ? "Copied" : "Copy link"}
                </Button>
                <Button onClick={() => changeCreate(false)}>Done</Button>
              </DialogFooter>
            </div>
          ) : (
            <form onSubmit={createToken} className="space-y-4">
              {installPlatform === "mac" && (
                <div className="space-y-2">
                  <Label htmlFor="mac-install-mode">Install mode</Label>
                  <Select value={macInstallMode} onValueChange={(value) => setMacInstallMode(value as "interactive" | "mdm")} disabled={busy}>
                    <SelectTrigger id="mac-install-mode" className="w-full" aria-describedby="mac-install-mode-help">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="interactive">Interactive</SelectItem>
                      <SelectItem value="mdm">Silent MDM</SelectItem>
                    </SelectContent>
                  </Select>
                  <p id="mac-install-mode-help" className="text-sm text-muted-foreground">
                    {mdmInstall
                      ? "Run as root or as the logged-in user. A new install needs write access to /Applications. No confirmation dialogs or app window. Deploy any required macOS privacy and background-item profiles first."
                      : "Run in the user's Terminal and confirm the organization before connecting."}
                  </p>
                </div>
              )}
              <div className="space-y-2">
                <Label htmlFor="token-label">Label (optional)</Label>
                <Input
                  id="token-label"
                  value={label}
                  onChange={(event) => setLabel(event.target.value)}
                  placeholder="For example, engineering workstations"
                  maxLength={200}
                  autoComplete="off"
                  disabled={busy}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="token-max-uses">Max uses</Label>
                <Input
                  id="token-max-uses"
                  type="number"
                  min={1}
                  max={2147483647}
                  step={1}
                  required
                  value={maxUses}
                  onChange={(event) => setMaxUses(event.target.value)}
                  aria-describedby="token-max-uses-help"
                  disabled={busy}
                />
                <p id="token-max-uses-help" className="text-sm text-muted-foreground">
                  Each successful device enrollment uses one. Set to 1 for a single-use link.
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="token-expiry">Expires after</Label>
                <Select
                  value={hours}
                  onValueChange={setHours}
                  disabled={busy}
                >
                  <SelectTrigger id="token-expiry" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1">1 hour</SelectItem>
                    <SelectItem value="24">24 hours</SelectItem>
                    <SelectItem value="168">7 days</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <ErrorMessage message={error} />
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => changeCreate(false)}
                  disabled={busy}
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={busy}>
                  {busy ? "Creating…" : createTitle}
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>
      <Dialog
        open={!!revoke}
        onOpenChange={(open) => {
          if (!open && !busy) {
            setRevoke(null);
            setError("");
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke enrollment token?</DialogTitle>
            <DialogDescription>
              New enrollments using{" "}
              {revoke?.label ? `“${revoke.label}”` : "this token"} will be
              rejected. Already-enrolled sensors keep their device credentials.
            </DialogDescription>
          </DialogHeader>
          <ErrorMessage message={error} />
          <DialogFooter>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => setRevoke(null)}
            >
              Cancel
            </Button>
            <Button variant="destructive" onClick={revokeToken} disabled={busy}>
              {busy ? "Revoking…" : "Revoke token"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export function IntegrationsPage() {
  return <div className="space-y-6"><SlackNotifications /><MCPConnections /></div>;
}

function TenantNameForm({ name }: { name: string }) {
  const { refreshUser } = useDashboard();
  const [draft, setDraft] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const value = draft ?? name;

  async function save(event: FormEvent) {
    event.preventDefault();
    if (saving || !value.trim() || value.trim() === name) return;
    setSaving(true); setError(""); setNotice("");
    try {
      await api("settings/tenant", { method: "PATCH", body: JSON.stringify({ name: value.trim() }) });
      await refreshUser();
      setDraft(null);
      setNotice("Tenant name saved.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to save the tenant name.");
    } finally { setSaving(false); }
  }

  return <form className="mb-4 space-y-3" onSubmit={(event) => void save(event)}>
    <label className="block space-y-1 text-sm">
      <span>Name</span>
      <Input value={value} required maxLength={200} disabled={saving}
        onChange={(event) => { setDraft(event.target.value); setError(""); setNotice(""); }} />
    </label>
    <Button type="submit" disabled={saving || !value.trim() || value.trim() === name}>
      {saving ? "Saving…" : "Save name"}
    </Button>
    {notice && <p role="status" className="text-sm">{notice}</p>}
    <ErrorMessage message={error} />
  </form>;
}

export function SettingsPage() {
  const { user } = useDashboard();
  if (!user) return <LoadingState label="Loading tenant context" />;
  return (
    <div className="space-y-4">
      <SettingsLayout>
        <PageSection
          title="Tenant"
          description="The workspace associated with your current session."
          className="self-stretch [&>[data-slot=card]]:h-full"
        >
          {hasRole(user, "it_admin") && <TenantNameForm key={user.tenant.id} name={user.tenant.name} />}
          <dl>
            {!hasRole(user, "it_admin") && <Detail label="Name">{user.tenant.name}</Detail>}
            <Detail label="Slug">{user.tenant.slug}</Detail>
            <Detail label="Tenant ID">
              <span className="text-xs">{user.tenant.id}</span>
            </Detail>
          </dl>
        </PageSection>
        <PageSection
          title="Current session"
          titleAction={
            <Link
              href="/administration/users"
              className="ml-auto inline-flex items-center gap-1 text-sm font-medium underline underline-offset-4"
            >
              View users and role permissions
              <ArrowUpRight className="size-4" aria-hidden="true" />
            </Link>
          }
          description="Your account and assigned tenant roles."
          className="self-stretch [&>[data-slot=card]]:h-full [&_[data-slot=card-header]>div>div]:flex-wrap"
        >
          <dl>
            <Detail label="Name">{user.name || "Not provided"}</Detail>
            <Detail label="Email">{user.email}</Detail>
            <Detail label="Roles">
              <RoleTags roles={user.roles} />
            </Detail>
          </dl>
        </PageSection>
      </SettingsLayout>
      <SupportSettings />
      <SessionDetectionToggle />
      <ModelApiKeys />
      <TelemetryRetention />
      <SummaryReportSharing />
    </div>
  );
}
