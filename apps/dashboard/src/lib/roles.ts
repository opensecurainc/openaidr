export const ROLES = [
  { value: "it_admin", name: "IT Admin", description: "Manage users, role tags, sensors, integrations, and settings. View inventory and costs." },
  { value: "security_analyst", name: "Security Analyst", description: "Investigate findings and evidence. Manage detection rules, guardrails, and company knowledge." },
  { value: "security_leadership", name: "Security Leadership", description: "Review aggregate security metrics, AI inventory, and costs." },
] as const;

export type Role = (typeof ROLES)[number]["value"];
type RoleUser = { roles: readonly Role[] } | null;

export function hasRole(user: RoleUser, role: Role) {
  return user?.roles?.includes(role) === true;
}

export function roleNames(roles: readonly Role[] = []) {
  return ROLES.filter((role) => roles.includes(role.value)).map((role) => role.name).join(", ");
}

export function canAccessPage(user: RoleUser, pathname: string) {
  if (!user?.roles?.length) return false;
  const path = pathname.replace(/\/$/, "") || "/";
  if (path === "/gateways/overview") return true;
  if (path === "/gateways/instances" || /^\/gateways\/instances\/[^/]+$/.test(path)) return hasRole(user, "it_admin") || hasRole(user, "security_analyst");
  if (path === "/gateways/requests" || /^\/gateways\/requests\/[^/]+$/.test(path)) return hasRole(user, "security_analyst");
  if (["/", "/ai-inventory", "/ai-inventory/preview", "/ai-supply-chain", "/ai-supply-chain/preview", "/ai-skills", "/ai-skills/preview"].includes(path)) return true;
  if (path.startsWith("/administration/") || ["/audit-logs", "/devices"].includes(path)) return hasRole(user, "it_admin");
  if (["/costs/agents", "/costs/openaidr", "/costs/detections"].includes(path)) return hasRole(user, "it_admin") || hasRole(user, "security_leadership");
  if (["/activity", "/user-risk", "/user-risk/findings", "/detections", "/detections/preview", "/evidence", "/telemetry", "/detection-rules", "/guardrail/live", "/guardrail/configuration", "/guardrail/history", "/company-knowledge", "/company-knowledge/preview/policy", "/company-knowledge/preview/guardrails", "/security-posture"].includes(path) || /^\/(sessions|detections\/reports)\/[^/]+$/.test(path)) return hasRole(user, "security_analyst");
  return false;
}
