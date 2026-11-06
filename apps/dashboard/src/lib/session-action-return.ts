const KEY = "openaidr.sessionActionReturn";
const APPROVAL_PATH = /^\/approvals\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MCP_PATH = /^\/mcp\/(?:authorize\/[A-Za-z0-9_-]{43}|changes\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|access)$/i;

function permitted(path: string) {
  return path === "/register-session" || APPROVAL_PATH.test(path) || MCP_PATH.test(path);
}

export function rememberSessionActionReturn(path: string) {
  try {
    if (permitted(path)) sessionStorage.setItem(KEY, path);
  } catch {}
}

export function clearSessionActionReturn() {
  try { sessionStorage.removeItem(KEY); } catch {}
}

export function takeSessionActionReturn() {
  try {
    const path = sessionStorage.getItem(KEY) || "";
    sessionStorage.removeItem(KEY);
    return permitted(path) ? path : "";
  } catch {
    return "";
  }
}
