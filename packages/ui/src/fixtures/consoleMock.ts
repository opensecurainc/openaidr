import { ApiError, type MockHandler } from "../api/client";
import type {
  Agent, ApiEvent, Category, EnrollmentToken, Finding, FindingStatus, Invite, Me, Overview, PolicyRule, Product, Range,
  ResponseAction, ResponseActionType, Role, Sensor, Severity, User,
} from "../api/types";
import { SEVERITIES } from "../api/types";
import { Rand } from "./rand";
import { badRequest, body, createRouter, forbidden, notFound, paginate, unauthorized, type Route } from "./router";
import { createWorld, type TenantWorld, type World } from "./data";

const HOUR = 3600_000;
const DAY = 24 * HOUR;

export interface ConsoleMockOptions { world?: World; tenantSlug?: string; startLoggedInAs?: string }

/** In-memory implementation of docs/api.md `/api/v1` for one tenant. */
export function createConsoleMock(opts: ConsoleMockOptions = {}): MockHandler {
  const world = opts.world ?? createWorld();
  const t: TenantWorld = world.tenants.find((x) => x.tenant.slug === (opts.tenantSlug ?? "acme")) ?? world.tenants[0]!;
  const r = new Rand(99);
  let current: User | null = opts.startLoggedInAs ? t.users.find((u) => u.email === opts.startLoggedInAs) ?? null : null;
  const origin = typeof location !== "undefined" ? location.origin : "https://console.example";

  const me = (): Me => {
    if (!current) unauthorized();
    return { id: current.id, email: current.email, name: current.name, role: current.role, tenant: { id: t.tenant.id, name: t.tenant.name, slug: t.tenant.slug } };
  };
  const requireRole = (...roles: Role[]) => { const u = me(); if (!roles.includes(u.role)) forbidden(); return u; };
  const analyst = () => requireRole("owner", "admin", "analyst");
  const admin = () => requireRole("owner", "admin");
  const sensorStatus = (s: Sensor) => s;
  const audit = (action: string, target_type: string, target_id: string, details: Record<string, unknown> = {}) => {
    const u = me();
    t.audit.unshift({ id: r.uuid(), at: new Date().toISOString(), actor: { id: u.id, name: u.name }, action, target_type, target_id, details });
  };
  const bumpPolicy = () => { t.policy = { ...t.policy, version: t.policy.version + 1, updated_at: new Date().toISOString() }; return t.policy; };

  function overview(range: Range): Overview {
    const now = Date.now();
    const span = range === "24h" ? DAY : range === "7d" ? 7 * DAY : 30 * DAY;
    const since = now - span;
    const evs = t.events.filter((e) => new Date(e.time).getTime() >= since);
    const fs = t.findings.filter((f) => new Date(f.created_at).getTime() >= since);
    const open = t.findings.filter((f) => f.status === "open");
    const findings_open = Object.fromEntries(SEVERITIES.map((s) => [s, open.filter((f) => f.severity === s).length])) as Record<Severity, number>;
    const bucketMs = range === "24h" ? HOUR : DAY;
    const buckets = new Map<number, { events: number; findings: number }>();
    const first = Math.floor(since / bucketMs) * bucketMs;
    for (let b = first; b <= now; b += bucketMs) buckets.set(b, { events: 0, findings: 0 });
    for (const e of evs) { const b = Math.floor(new Date(e.time).getTime() / bucketMs) * bucketMs; const v = buckets.get(b); if (v) v.events++; }
    for (const f of fs) { const b = Math.floor(new Date(f.created_at).getTime() / bucketMs) * bucketMs; const v = buckets.get(b); if (v) v.findings++; }
    const byCat = new Map<Category, number>();
    for (const f of fs) byCat.set(f.category, (byCat.get(f.category) ?? 0) + 1);
    const byProd = new Map<Product, { agents: number; events: number }>();
    for (const a of t.agents) { const v = byProd.get(a.product) ?? { agents: 0, events: 0 }; v.agents++; byProd.set(a.product, v); }
    for (const e of evs) { const v = byProd.get(e.agent.product); if (v) v.events++; }
    const perAgent = new Map<string, number>();
    for (const e of evs) perAgent.set(e.agent_id, (perAgent.get(e.agent_id) ?? 0) + 1);
    const activeAgents = new Set(evs.map((e) => e.agent_id));
    return {
      range,
      agents: { total: t.agents.length, active: activeAgents.size },
      sessions: new Set(evs.map((e) => e.session_id)).size,
      events: evs.length,
      sensors: {
        total: t.sensors.length, online: t.sensors.filter((s) => s.status === "online").length,
        offline: t.sensors.filter((s) => s.status === "offline").length, disabled: t.sensors.filter((s) => s.status === "disabled").length,
      },
      findings_open,
      by_category: [...byCat.entries()].map(([category, count]) => ({ category, count })).sort((a, b) => b.count - a.count),
      by_product: [...byProd.entries()].map(([product, v]) => ({ product, ...v })).sort((a, b) => b.events - a.events),
      timeline: [...buckets.entries()].map(([b, v]) => ({ bucket: new Date(b).toISOString(), ...v })),
      top_agents: [...perAgent.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([id, events]) => {
        const a = t.agents.find((x) => x.id === id)!;
        return { agent_id: id, product: a.product, hostname: a.host.hostname, user: a.host.user, events };
      }),
      recent_findings: t.findings.slice(0, 6),
    };
  }

  const matchQ = (e: ApiEvent, q: string) => {
    const s = q.toLowerCase();
    return (e.command?.text ?? "").toLowerCase().includes(s) || (e.file?.path ?? "").toLowerCase().includes(s)
      || (e.network?.host ?? "").toLowerCase().includes(s) || (e.tool?.name ?? "").toLowerCase().includes(s);
  };

  const routes: Route[] = [
    // Auth
    ["GET", "/auth/config", () => ({ version: 1, mode: "local", password_login: true })],
    ["POST", "/auth/login", (req) => {
      const { email, password } = body<{ email: string; password: string }>(req);
      const u = t.users.find((x) => x.email.toLowerCase() === (email ?? "").toLowerCase());
      if (!u || !password) throw unauthorizedLogin();
      if (u.status === "disabled") forbidden();
      u.last_login_at = new Date().toISOString();
      current = u;
      return { user: me() };
    }],
    ["POST", "/auth/logout", () => { current = null; return undefined; }],
    ["GET", "/auth/me", () => ({ user: me() })],
    ["GET", "/auth/invite", (req) => {
      const inv = t.invites.find((i) => i.id.startsWith(req.query.token ?? "") || req.query.token === "demo");
      if (!inv) notFound("Invite");
      return { email: inv.email, tenant_name: t.tenant.name, role: inv.role, expires_at: inv.expires_at };
    }],
    ["POST", "/auth/accept-invite", (req) => {
      const { token, name, password } = body<{ token: string; name: string; password: string }>(req);
      const idx = t.invites.findIndex((i) => i.id.startsWith(token ?? "") || token === "demo");
      if (idx < 0) notFound("Invite");
      if (!name || !password || password.length < 8) badRequest("Name and a password of at least 8 characters are required");
      const inv = t.invites[idx]!;
      const u: User = { id: r.uuid(), email: inv.email, name, role: inv.role, status: "active", created_at: new Date().toISOString(), last_login_at: new Date().toISOString() };
      t.users.push(u);
      t.invites.splice(idx, 1);
      current = u;
      return { user: me() };
    }],

    // Overview
    ["GET", "/overview", (req) => { me(); return overview((req.query.range as Range) || "24h"); }],

    // Inventory
    ["GET", "/agents", (req) => {
      me();
      let items = t.agents.slice().sort((a, b) => (a.last_seen < b.last_seen ? 1 : -1));
      const q = req.query;
      if (q.product) items = items.filter((a) => a.product === q.product);
      if (q.sensor_id) items = items.filter((a) => a.sensor_id === q.sensor_id);
      if (q.status) items = items.filter((a) => a.status === q.status);
      if (q.q) { const s = q.q.toLowerCase(); items = items.filter((a) => a.host.hostname.includes(s) || a.host.user.includes(s) || a.product.includes(s) || a.models.some((m) => m.includes(s))); }
      return paginate(items, q);
    }],
    ["GET", "/agents/:id", (_req, p) => { me(); return t.agents.find((a) => a.id === p.id) ?? notFound("Agent"); }],
    ["GET", "/agents/:id/sessions", (req, p) => {
      me();
      const items = t.sessions.filter((s) => s.agent_id === p.id).sort((a, b) => (a.started_at < b.started_at ? 1 : -1));
      return paginate(items, req.query);
    }],
    ["GET", "/sessions/:id", (_req, p) => { me(); return t.sessions.find((s) => s.id === p.id) ?? notFound("Session"); }],
    ["GET", "/sessions/:id/events", (req, p) => {
      me();
      let items = t.events.filter((e) => e.session_id === p.id);
      if (req.query.kind) items = items.filter((e) => e.kind === req.query.kind);
      return paginate(items, req.query);
    }],
    ["GET", "/events", (req) => {
      me();
      const q = req.query;
      let items = t.events.slice().reverse();
      if (q.kind) items = items.filter((e) => e.kind === q.kind);
      if (q.agent_id) items = items.filter((e) => e.agent_id === q.agent_id);
      if (q.sensor_id) items = items.filter((e) => e.sensor_id === q.sensor_id);
      if (q.session_id) items = items.filter((e) => e.session_id === q.session_id);
      if (q.since) items = items.filter((e) => e.time >= new Date(q.since!).toISOString());
      if (q.until) items = items.filter((e) => e.time <= new Date(q.until!).toISOString());
      if (q.q) items = items.filter((e) => matchQ(e, q.q!));
      return paginate(items, q);
    }],
    ["GET", "/events/:id", (_req, p) => { me(); return t.events.find((e) => e.id === p.id) ?? notFound("Event"); }],

    // Findings
    ["GET", "/findings", (req) => {
      me();
      const q = req.query;
      let items = t.findings.slice();
      if (q.status) items = items.filter((f) => f.status === q.status);
      if (q.severity) items = items.filter((f) => f.severity === q.severity);
      if (q.category) items = items.filter((f) => f.category === q.category);
      if (q.agent_id) items = items.filter((f) => f.agent_id === q.agent_id);
      if (q.sensor_id) items = items.filter((f) => f.sensor_id === q.sensor_id);
      if (q.session_id) items = items.filter((f) => f.session_id === q.session_id);
      if (q.assignee_id) items = items.filter((f) => f.assignee?.id === q.assignee_id);
      if (q.since) items = items.filter((f) => f.created_at >= new Date(q.since!).toISOString());
      return paginate(items, q);
    }],
    ["GET", "/findings/:id", (_req, p) => {
      me();
      const f = t.findings.find((x) => x.id === p.id) ?? notFound("Finding");
      const events = t.events.filter((e) => f.event_ids.includes(e.id));
      return { finding: f, events, notes: t.notes.filter((n) => n.finding_id === f.id), actions: t.actions.filter((a) => a.finding_id === f.id) };
    }],
    ["PATCH", "/findings/:id", (req, p) => {
      analyst();
      const f = t.findings.find((x) => x.id === p.id) ?? notFound("Finding");
      const patch = body<{ status?: FindingStatus; assignee_id?: string | null; resolution?: string }>(req);
      if (patch.status && (patch.status === "resolved" || patch.status === "false_positive") && !(patch.resolution ?? f.resolution)) badRequest("resolution is required");
      if (patch.status) f.status = patch.status;
      if (patch.assignee_id !== undefined) { const u = patch.assignee_id ? t.users.find((x) => x.id === patch.assignee_id) : null; f.assignee = u ? { id: u.id, name: u.name } : null; }
      if (patch.resolution !== undefined) f.resolution = patch.resolution;
      f.updated_at = new Date().toISOString();
      audit("finding.update", "finding", f.id, patch as Record<string, unknown>);
      return f;
    }],
    ["POST", "/findings/:id/notes", (req, p) => {
      const u = analyst();
      const f = t.findings.find((x) => x.id === p.id) ?? notFound("Finding");
      const { body: text } = body<{ body: string }>(req);
      if (!text?.trim()) badRequest("body is required");
      const n = { id: r.uuid(), finding_id: f.id, author: { id: u.id, name: u.name }, body: text.trim(), created_at: new Date().toISOString() };
      t.notes.push(n);
      return n;
    }],
    ["GET", "/detections/rules", () => { me(); return { items: t.rules }; }],
    ["PATCH", "/detections/rules/:id", (req, p) => {
      admin();
      const rule = t.rules.find((x) => x.id === p.id) ?? notFound("Rule");
      rule.enabled = !!body<{ enabled: boolean }>(req).enabled;
      audit("detection_rule.update", "detection_rule", rule.id, { enabled: rule.enabled });
      return rule;
    }],

    // Response
    ["GET", "/response/actions", (req) => {
      me();
      let items = t.actions.slice().sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
      if (req.query.finding_id) items = items.filter((a) => a.finding_id === req.query.finding_id);
      if (req.query.type) items = items.filter((a) => a.type === req.query.type);
      if (req.query.status) items = items.filter((a) => a.status === req.query.status);
      return paginate(items, req.query);
    }],
    ["POST", "/response/actions", (req) => {
      const u = analyst();
      const { finding_id, type, params } = body<{ finding_id?: string; type: ResponseActionType; params: Record<string, string> }>(req);
      if (!type) badRequest("type is required");
      const now = new Date().toISOString();
      const a: ResponseAction = { id: r.uuid(), finding_id: finding_id ?? null, type, params: params ?? {}, status: "pending", created_by: { id: u.id, name: u.name }, created_at: now, applied_at: null };
      const f = finding_id ? t.findings.find((x) => x.id === finding_id) : undefined;
      if (type === "block_command" || type === "block_path" || type === "block_host") {
        const match: PolicyRule["match"] = type === "block_command" ? { kinds: ["command"], command_regex: params.command_regex }
          : type === "block_path" ? { kinds: ["file.write", "file.read"], path_glob: params.path_glob }
          : { kinds: ["network", "command"], host_glob: params.host_glob };
        const value = params.command_regex ?? params.path_glob ?? params.host_glob;
        if (!value) badRequest("a pattern is required");
        t.policy.rules.push({ id: `rule-${a.id.slice(0, 8)}`, name: `Response: ${f?.title ?? value}`, action: "deny", enabled: true, reason: params.reason, match, source: finding_id ? `response:${finding_id}` : "tenant" });
        bumpPolicy();
        a.status = "applied"; a.applied_at = now;
      } else if (type === "disable_sensor" || type === "enable_sensor") {
        const s = t.sensors.find((x) => x.id === params.sensor_id) ?? notFound("Sensor");
        s.disabled = type === "disable_sensor";
        s.status = s.disabled ? "disabled" : "online";
        a.status = "pending";
      } else {
        a.status = "applied"; a.applied_at = now;
      }
      t.actions.unshift(a);
      audit("response_action.create", "response_action", a.id, { type });
      return a;
    }],
    ["GET", "/response/policy", () => { me(); return t.policy; }],
    ["PUT", "/response/policy", (req) => {
      admin();
      const { rules } = body<{ rules: PolicyRule[] }>(req);
      if (!Array.isArray(rules)) badRequest("rules must be an array");
      t.policy.rules = rules.map((x) => ({ ...x, id: x.id || `rule-${r.token("", 8)}` }));
      audit("policy.update", "policy", t.tenant.id, { version: t.policy.version + 1 });
      return bumpPolicy();
    }],
    ["POST", "/response/policy/rules", (req) => {
      admin();
      const rule = body<Omit<PolicyRule, "id">>(req);
      if (!rule.name) badRequest("name is required");
      t.policy.rules.push({ ...rule, id: `rule-${r.token("", 8)}`, source: rule.source ?? "tenant" });
      audit("policy.update", "policy", t.tenant.id, { version: t.policy.version + 1 });
      return bumpPolicy();
    }],
    ["DELETE", "/response/policy/rules/:id", (_req, p) => {
      admin();
      const idx = t.policy.rules.findIndex((x) => x.id === p.id);
      if (idx < 0) notFound("Rule");
      t.policy.rules.splice(idx, 1);
      audit("policy.update", "policy", t.tenant.id, { version: t.policy.version + 1 });
      return bumpPolicy();
    }],

    // Users
    ["GET", "/users", () => { me(); return { items: t.users }; }],
    ["PATCH", "/users/:id", (req, p) => {
      admin();
      const u = t.users.find((x) => x.id === p.id) ?? notFound("User");
      const patch = body<{ role?: Role; status?: "active" | "disabled" }>(req);
      if (patch.role) u.role = patch.role;
      if (patch.status) u.status = patch.status;
      audit("user.update", "user", u.id, patch as Record<string, unknown>);
      return u;
    }],
    ["DELETE", "/users/:id", (_req, p) => {
      admin();
      const idx = t.users.findIndex((x) => x.id === p.id);
      if (idx < 0) notFound("User");
      if (t.users[idx]!.id === current?.id) badRequest("You cannot remove yourself");
      audit("user.delete", "user", p.id);
      t.users.splice(idx, 1);
      return undefined;
    }],
    ["GET", "/users/invites", () => { admin(); return { items: t.invites }; }],
    ["POST", "/users/invites", (req) => {
      admin();
      const { email, role } = body<{ email: string; role: Role }>(req);
      if (!email?.includes("@")) badRequest("email is required");
      const inv: Invite = { id: r.uuid(), email, role: role ?? "viewer", expires_at: new Date(Date.now() + 7 * DAY).toISOString(), created_at: new Date().toISOString() };
      t.invites.push(inv);
      audit("user.invite", "invite", inv.id, { email, role });
      return { ...inv, accept_url: `${origin}/accept-invite?token=${inv.id.slice(0, 8)}${r.token("", 24)}` };
    }],
    ["DELETE", "/users/invites/:id", (_req, p) => {
      admin();
      const idx = t.invites.findIndex((x) => x.id === p.id);
      if (idx < 0) notFound("Invite");
      t.invites.splice(idx, 1);
      audit("invite.revoke", "invite", p.id);
      return undefined;
    }],

    // Sensors
    ["GET", "/sensors/enrollment-tokens", () => { admin(); return { items: t.tokens }; }],
    ["POST", "/sensors/enrollment-tokens", (req) => {
      admin();
      const { label, expires_in_hours, max_uses } = body<{ label: string; expires_in_hours?: number; max_uses?: number }>(req);
      if (!label) badRequest("label is required");
      const tok: EnrollmentToken = { id: r.uuid(), label, created_at: new Date().toISOString(), expires_at: expires_in_hours ? new Date(Date.now() + expires_in_hours * HOUR).toISOString() : null, uses: 0, max_uses: max_uses ?? 0, revoked_at: null };
      t.tokens.push(tok);
      audit("enrollment_token.create", "enrollment_token", tok.id, { label });
      return { ...tok, token: r.token("oaet_", 40) };
    }],
    ["DELETE", "/sensors/enrollment-tokens/:id", (_req, p) => {
      admin();
      const tok = t.tokens.find((x) => x.id === p.id) ?? notFound("Token");
      tok.revoked_at = new Date().toISOString();
      audit("enrollment_token.revoke", "enrollment_token", tok.id);
      return undefined;
    }],
    ["GET", "/sensors", (req) => {
      me();
      const q = req.query;
      let items = t.sensors.map(sensorStatus).sort((a, b) => a.hostname.localeCompare(b.hostname));
      if (q.host_kind) items = items.filter((s) => s.host_kind === q.host_kind);
      if (q.status) items = items.filter((s) => s.status === q.status);
      if (q.q) { const s = q.q.toLowerCase(); items = items.filter((x) => x.hostname.includes(s) || x.label.toLowerCase().includes(s) || x.user.includes(s)); }
      return paginate(items, q);
    }],
    ["GET", "/sensors/:id", (_req, p) => {
      me();
      const s = t.sensors.find((x) => x.id === p.id) ?? notFound("Sensor");
      return { ...s, agents: t.agents.filter((a) => a.sensor_id === s.id) };
    }],
    ["PATCH", "/sensors/:id", (req, p) => {
      admin();
      const s = t.sensors.find((x) => x.id === p.id) ?? notFound("Sensor");
      const patch = body<{ label?: string; host_kind?: Sensor["host_kind"]; disabled?: boolean }>(req);
      if (patch.label !== undefined) s.label = patch.label;
      if (patch.host_kind) s.host_kind = patch.host_kind;
      if (patch.disabled !== undefined) { s.disabled = patch.disabled; s.status = patch.disabled ? "disabled" : "online"; }
      audit(patch.disabled === true ? "sensor.disable" : patch.disabled === false ? "sensor.enable" : "sensor.update", "sensor", s.id, patch as Record<string, unknown>);
      return s;
    }],
    ["DELETE", "/sensors/:id", (_req, p) => {
      admin();
      const idx = t.sensors.findIndex((x) => x.id === p.id);
      if (idx < 0) notFound("Sensor");
      t.sensors.splice(idx, 1);
      audit("sensor.delete", "sensor", p.id);
      return undefined;
    }],

    // System
    ["GET", "/system/status", () => { me(); return { ...t.system, ingest: { ...t.system.ingest, sensors_online: t.sensors.filter((s) => s.status === "online").length } }; }],
    ["GET", "/audit", (req) => { admin(); return paginate(t.audit, req.query); }],
  ];

  return createRouter(routes);
}

function unauthorizedLogin() {
  return new ApiError(401, "unauthorized", "Unknown email or password");
}

export function findingSeverityOrder(f: Finding): number { return SEVERITIES.indexOf(f.severity); }
export type { Agent };
