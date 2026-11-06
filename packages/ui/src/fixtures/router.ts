import { ApiError, type MockHandler, type MockRequest } from "../api/client";

export type Params = Record<string, string>;
export type Route = [method: string, pattern: string, handler: (req: MockRequest, params: Params) => unknown];

function compile(pattern: string): { re: RegExp; keys: string[] } {
  const keys: string[] = [];
  const src = pattern.replace(/:([a-zA-Z_]+)/g, (_, k: string) => { keys.push(k); return "([^/]+)"; });
  return { re: new RegExp(`^${src}$`), keys };
}

export function createRouter(routes: Route[]): MockHandler {
  const compiled = routes.map(([m, p, h]) => ({ m, h, ...compile(p) }));
  return (req) => {
    for (const r of compiled) {
      if (r.m !== req.method) continue;
      const m = r.re.exec(req.path);
      if (!m) continue;
      const params: Params = {};
      r.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]!); });
      return r.h(req, params);
    }
    throw new ApiError(404, "not_found", `No mock for ${req.method} ${req.path}`);
  };
}

export function paginate<T>(items: T[], q: Record<string, string>): { items: T[]; next_cursor: string } {
  const limit = Math.min(500, Math.max(1, Number(q.limit ?? 50) || 50));
  const offset = Number(q.cursor ?? 0) || 0;
  const page = items.slice(offset, offset + limit);
  return { items: page, next_cursor: offset + limit < items.length ? String(offset + limit) : "" };
}

export function body<T>(req: MockRequest): T { return (req.body ?? {}) as T; }

export function notFound(what: string): never { throw new ApiError(404, "not_found", `${what} not found`); }
export function badRequest(msg: string): never { throw new ApiError(400, "bad_request", msg); }
export function unauthorized(): never { throw new ApiError(401, "unauthorized", "Sign in required"); }
export function forbidden(): never { throw new ApiError(403, "forbidden", "Not allowed for this role"); }
