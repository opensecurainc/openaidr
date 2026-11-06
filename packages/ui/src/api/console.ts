import type { ApiClient, Query } from "./client";
import type {
  Agent, ApiEvent, AuditEntry, DetectionRule, EnrollmentToken, Finding, FindingDetail, FindingStatus,
  HostKind, Invite, InviteInfo, Me, Note, Overview, Page, Policy, PolicyRule, Range, ResponseAction,
  ResponseActionType, Role, Sensor, SensorDetail, Session, SystemStatus, User,
} from "./types";

export function consoleApi(c: ApiClient) {
  return {
    auth: {
      login: (email: string, password: string) => c.post<{ user: Me }>("/auth/login", { email, password }),
      logout: () => c.post<void>("/auth/logout"),
      me: () => c.get<{ user: Me }>("/auth/me"),
      invite: (token: string) => c.get<InviteInfo>("/auth/invite", { token }),
      acceptInvite: (token: string, name: string, password: string) =>
        c.post<{ user: Me }>("/auth/accept-invite", { token, name, password }),
    },
    overview: (range: Range) => c.get<Overview>("/overview", { range }),
    agents: {
      list: (q: Query) => c.get<Page<Agent>>("/agents", q),
      get: (id: string) => c.get<Agent>(`/agents/${id}`),
      sessions: (id: string, q: Query) => c.get<Page<Session>>(`/agents/${id}/sessions`, q),
    },
    sessions: {
      get: (id: string) => c.get<Session>(`/sessions/${id}`),
      events: (id: string, q: Query) => c.get<Page<ApiEvent>>(`/sessions/${id}/events`, q),
    },
    events: {
      list: (q: Query) => c.get<Page<ApiEvent>>("/events", q),
      get: (id: string) => c.get<ApiEvent>(`/events/${id}`),
    },
    findings: {
      list: (q: Query) => c.get<Page<Finding>>("/findings", q),
      get: (id: string) => c.get<FindingDetail>(`/findings/${id}`),
      update: (id: string, patch: { status?: FindingStatus; assignee_id?: string | null; resolution?: string }) =>
        c.patch<Finding>(`/findings/${id}`, patch),
      addNote: (id: string, body: string) => c.post<Note>(`/findings/${id}/notes`, { body }),
    },
    detections: {
      rules: () => c.get<{ items: DetectionRule[] }>("/detections/rules"),
      setRuleEnabled: (id: string, enabled: boolean) => c.patch<DetectionRule>(`/detections/rules/${id}`, { enabled }),
    },
    response: {
      actions: (q: Query) => c.get<Page<ResponseAction>>("/response/actions", q),
      createAction: (body: { finding_id?: string; type: ResponseActionType; params: Record<string, string> }) =>
        c.post<ResponseAction>("/response/actions", body),
      policy: () => c.get<Policy>("/response/policy"),
      putPolicy: (rules: PolicyRule[]) => c.put<Policy>("/response/policy", { rules }),
      addRule: (rule: Omit<PolicyRule, "id">) => c.post<Policy>("/response/policy/rules", rule),
      deleteRule: (id: string) => c.del<Policy>(`/response/policy/rules/${id}`),
    },
    users: {
      assignees: () => c.get<{ items: { id: string; name: string }[] }>("/users/assignees"),
      list: () => c.get<{ items: User[] }>("/users"),
      update: (id: string, patch: { role?: Role; status?: "active" | "disabled" }) => c.patch<User>(`/users/${id}`, patch),
      remove: (id: string) => c.del<void>(`/users/${id}`),
      invites: () => c.get<{ items: Invite[] }>("/users/invites"),
      createInvite: (email: string, role: Role) => c.post<Invite>("/users/invites", { email, role }),
      revokeInvite: (id: string) => c.del<void>(`/users/invites/${id}`),
    },
    sensors: {
      list: (q: Query) => c.get<Page<Sensor>>("/sensors", q),
      get: (id: string) => c.get<SensorDetail>(`/sensors/${id}`),
      update: (id: string, patch: { label?: string; host_kind?: HostKind; disabled?: boolean }) =>
        c.patch<Sensor>(`/sensors/${id}`, patch),
      remove: (id: string) => c.del<void>(`/sensors/${id}`),
      tokens: () => c.get<{ items: EnrollmentToken[] }>("/sensors/enrollment-tokens"),
      createToken: (body: { label: string; expires_in_hours?: number; max_uses?: number }) =>
        c.post<EnrollmentToken>("/sensors/enrollment-tokens", body),
      revokeToken: (id: string) => c.del<void>(`/sensors/enrollment-tokens/${id}`),
    },
    system: {
      status: () => c.get<SystemStatus>("/system/status"),
      audit: (q: Query) => c.get<Page<AuditEntry>>("/audit", q),
    },
  };
}

export type ConsoleApi = ReturnType<typeof consoleApi>;
