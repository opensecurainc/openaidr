import { ApiError, type MockHandler } from "../api/client";
import type { AdminMe, EnrollmentToken, Invite, PlatformAdmin, Role, Tenant } from "../api/types";
import { Rand } from "./rand";
import { badRequest, body, createRouter, notFound, paginate, unauthorized, type Route } from "./router";
import { createWorld, type TenantWorld, type World } from "./data";

const HOUR = 3600_000;
const DAY = 24 * HOUR;

export interface AdminMockOptions { world?: World; startLoggedInAs?: string }

/** In-memory implementation of docs/api.md `/admin/v1`. */
export function createAdminMock(opts: AdminMockOptions = {}): MockHandler {
  const world = opts.world ?? createWorld();
  const r = new Rand(4242);
  let current: PlatformAdmin | null = opts.startLoggedInAs ? world.admins.find((a) => a.email === opts.startLoggedInAs) ?? null : null;
  const consoleOrigin = typeof location !== "undefined" ? location.origin : "https://console.example";

  const me = (): AdminMe => { if (!current) unauthorized(); return { id: current.id, email: current.email, name: current.name }; };
  const tenantOf = (id: string): TenantWorld => world.tenants.find((t) => t.tenant.id === id) ?? notFound("Tenant");
  const refresh = (t: TenantWorld): Tenant => {
    t.tenant.users_total = t.users.length;
    t.tenant.sensors_total = t.sensors.length;
    t.tenant.sensors_online = t.sensors.filter((s) => s.status === "online").length;
    t.tenant.findings_open = t.findings.filter((f) => f.status === "open").length;
    return t.tenant;
  };
  const visible = () => world.tenants.filter((t) => t.tenant.status !== "deleted");

  const routes: Route[] = [
    ["GET", "/auth/config", () => ({ version: 1, mode: "local", password_login: true })],
    ["POST", "/auth/login", (req) => {
      const { email, password } = body<{ email: string; password: string }>(req);
      const a = world.admins.find((x) => x.email.toLowerCase() === (email ?? "").toLowerCase());
      if (!a || !password) throw new ApiError(401, "unauthorized", "Unknown email or password");
      a.last_login_at = new Date().toISOString();
      current = a;
      return { admin: me() };
    }],
    ["POST", "/auth/logout", () => { current = null; return undefined; }],
    ["GET", "/auth/me", () => ({ admin: me() })],
    ["GET", "/audit", (req) => { me(); return paginate([], req.query); }],
    ["GET", "/overview", () => {
      me();
      const ts = visible().map(refresh);
      return {
        tenants: { total: ts.length, active: ts.filter((t) => t.status === "active").length, suspended: ts.filter((t) => t.status === "suspended").length },
        sensors: { total: ts.reduce((n, t) => n + t.sensors_total, 0), online: ts.reduce((n, t) => n + t.sensors_online, 0) },
        events_24h: ts.reduce((n, t) => n + t.events_24h, 0),
        findings_open: ts.reduce((n, t) => n + t.findings_open, 0),
        recent_tenants: ts.slice().sort((a, b) => (a.created_at < b.created_at ? 1 : -1)).slice(0, 5),
      };
    }],
    ["GET", "/tenants", (req) => {
      me();
      let items = visible().map(refresh).sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
      if (req.query.status) items = items.filter((t) => t.status === req.query.status);
      if (req.query.q) { const s = req.query.q.toLowerCase(); items = items.filter((t) => t.name.toLowerCase().includes(s) || t.slug.includes(s) || t.owner_email.includes(s)); }
      return paginate(items, req.query);
    }],
    ["POST", "/tenants", (req) => {
      me();
      const { name, slug, plan, owner_email, owner_name } = body<{ name: string; slug: string; plan?: string; owner_email: string; owner_name?: string }>(req);
      if (!name?.trim()) badRequest("name is required");
      if (!/^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])?$/.test(slug ?? "")) badRequest("slug must be 2 to 40 lowercase letters, digits, or hyphens");
      if (world.tenants.some((t) => t.tenant.slug === slug && t.tenant.status !== "deleted")) throw new ApiError(409, "conflict", "A tenant with this slug already exists");
      if (!owner_email?.includes("@")) badRequest("owner_email is required");
      const now = new Date().toISOString();
      const tenant: Tenant = { id: r.uuid(), name: name.trim(), slug, status: "active", plan: plan || "trial", created_at: now, owner_email, users_total: 0, sensors_total: 0, sensors_online: 0, events_24h: 0, findings_open: 0 };
      const invite: Invite = { id: r.uuid(), email: owner_email, role: "owner", expires_at: new Date(Date.now() + 7 * DAY).toISOString(), created_at: now, accept_url: `${consoleOrigin}/accept-invite?token=${r.token("", 32)}` };
      const token: EnrollmentToken = { id: r.uuid(), label: "initial", token: r.token("oaet_", 40), created_at: now, expires_at: null, uses: 0, max_uses: 0, revoked_at: null };
      const base = world.tenants[0]!;
      world.tenants.push({
        tenant, users: [], invites: [{ ...invite, accept_url: undefined }], tokens: [{ ...token, token: undefined }], sensors: [], agents: [], sessions: [], events: [], findings: [], notes: [], actions: [],
        policy: { version: 1, updated_at: now, rules: base.policy.rules.filter((x) => x.source === "builtin") }, rules: base.rules.map((x) => ({ ...x, findings_30d: 0 })), audit: [],
        system: { ...base.system, ingest: { events_last_hour: 0, sensors_online: 0 } },
      });
      void owner_name;
      return { tenant, invite, enrollment_token: token };
    }],
    ["GET", "/tenants/:id", (_req, p) => {
      me();
      const t = tenantOf(p.id);
      return { tenant: refresh(t), users: t.users, invites: t.invites, sensors: t.sensors, enrollment_tokens: t.tokens };
    }],
    ["PATCH", "/tenants/:id", (req, p) => {
      me();
      const t = tenantOf(p.id);
      const patch = body<{ name?: string; plan?: string; status?: "active" | "suspended" }>(req);
      if (patch.name !== undefined) { if (!patch.name.trim()) badRequest("name is required"); t.tenant.name = patch.name.trim(); }
      if (patch.plan !== undefined) t.tenant.plan = patch.plan;
      if (patch.status) t.tenant.status = patch.status;
      return refresh(t);
    }],
    ["DELETE", "/tenants/:id", (_req, p) => { me(); tenantOf(p.id).tenant.status = "deleted"; return undefined; }],
    ["POST", "/tenants/:id/invites", (req, p) => {
      me();
      const t = tenantOf(p.id);
      const { email, role } = body<{ email: string; role: Role }>(req);
      if (!email?.includes("@")) badRequest("email is required");
      const inv: Invite = { id: r.uuid(), email, role: role ?? "viewer", expires_at: new Date(Date.now() + 7 * DAY).toISOString(), created_at: new Date().toISOString() };
      t.invites.push(inv);
      return { ...inv, accept_url: `${consoleOrigin}/accept-invite?token=${r.token("", 32)}` };
    }],
    ["POST", "/tenants/:id/enrollment-tokens", (req, p) => {
      me();
      const t = tenantOf(p.id);
      const { label, expires_in_hours, max_uses } = body<{ label: string; expires_in_hours?: number; max_uses?: number }>(req);
      if (!label) badRequest("label is required");
      const tok: EnrollmentToken = { id: r.uuid(), label, created_at: new Date().toISOString(), expires_at: expires_in_hours ? new Date(Date.now() + expires_in_hours * HOUR).toISOString() : null, uses: 0, max_uses: max_uses ?? 0, revoked_at: null };
      t.tokens.push(tok);
      return { ...tok, token: r.token("oaet_", 40) };
    }],
    ["GET", "/admins", () => { me(); return { items: world.admins }; }],
    ["POST", "/admins", (req) => {
      me();
      const { email, name, password } = body<{ email: string; name: string; password: string }>(req);
      if (!email?.includes("@") || !name?.trim()) badRequest("email and name are required");
      if (!password || password.length < 8) badRequest("password must be at least 8 characters");
      const a: PlatformAdmin = { id: r.uuid(), email, name: name.trim(), created_at: new Date().toISOString(), last_login_at: null };
      world.admins.push(a);
      return a;
    }],
    ["DELETE", "/admins/:id", (_req, p) => {
      me();
      if (p.id === current?.id) badRequest("You cannot remove yourself");
      const idx = world.admins.findIndex((a) => a.id === p.id);
      if (idx < 0) notFound("Admin");
      world.admins.splice(idx, 1);
      return undefined;
    }],
  ];
  return createRouter(routes);
}
