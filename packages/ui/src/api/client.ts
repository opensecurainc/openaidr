export type Query = Record<string, string | number | boolean | undefined | null>;

export interface RequestOptions { query?: Query; body?: unknown; signal?: AbortSignal; idempotencyKey?: string }

export interface MockRequest { method: string; path: string; query: Record<string, string>; body: unknown; idempotencyKey?: string }
export type MockHandler = (req: MockRequest) => unknown | Promise<unknown>;

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export interface ApiClient {
  request<T>(method: string, path: string, opts?: RequestOptions): Promise<T>;
  get<T>(path: string, query?: Query, signal?: AbortSignal): Promise<T>;
  post<T>(path: string, body?: unknown): Promise<T>;
  patch<T>(path: string, body?: unknown): Promise<T>;
  put<T>(path: string, body?: unknown): Promise<T>;
  del<T>(path: string): Promise<T>;
  base: string;
  mock: boolean;
}

export interface ClientConfig {
  base: string;
  mock?: MockHandler;
  /** Called on 401 for any path not under /auth/. */
  onUnauthorized?: () => void;
}

function toQueryString(query?: Query): string {
  if (!query) return "";
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === "") continue;
    p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

export function createClient(cfg: ClientConfig): ApiClient {
  const base = cfg.base.replace(/\/$/, "");

  async function request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    if (cfg.mock) {
      await new Promise((r) => setTimeout(r, 120 + Math.random() * 180));
      const q: Record<string, string> = {};
      for (const [k, v] of Object.entries(opts.query ?? {})) {
        if (v !== undefined && v !== null && v !== "") q[k] = String(v);
      }
      try {
        return (await cfg.mock({ method, path, query: q, body: opts.body, idempotencyKey: opts.idempotencyKey })) as T;
      } catch (e) {
        if (e instanceof ApiError && e.status === 401 && !path.startsWith("/auth/")) cfg.onUnauthorized?.();
        throw e;
      }
    }
    const headers: Record<string, string> = { Accept: "application/json" };
    if (opts.idempotencyKey) headers["Idempotency-Key"] = opts.idempotencyKey;
    if (["POST", "PUT", "PATCH", "DELETE"].includes(method.toUpperCase())) {
      headers["X-OpenAIDR-CSRF"] = "1";
    }
    const init: RequestInit = { method, credentials: "include", headers, signal: opts.signal };
    if (opts.body !== undefined || method !== "GET") {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body ?? {});
    }
    let res: Response;
    try {
      res = await fetch(base + path + toQueryString(opts.query), init);
    } catch (e) {
      throw new ApiError(0, "network", e instanceof Error ? e.message : "Network error");
    }
    if (res.status === 204) return undefined as T;
    const text = await res.text();
    let data: unknown = null;
    if (text) {
      try { data = JSON.parse(text); } catch { data = null; }
    }
    if (!res.ok) {
      const err = (data as { error?: { code?: string; message?: string } } | null)?.error;
      const apiErr = new ApiError(res.status, err?.code ?? httpCode(res.status), err?.message ?? res.statusText);
      if (res.status === 401 && !path.startsWith("/auth/")) cfg.onUnauthorized?.();
      throw apiErr;
    }
    return data as T;
  }

  return {
    base,
    mock: !!cfg.mock,
    request,
    get: (path, query, signal) => request("GET", path, { query, signal }),
    post: (path, body) => request("POST", path, { body }),
    patch: (path, body) => request("PATCH", path, { body }),
    put: (path, body) => request("PUT", path, { body }),
    del: (path) => request("DELETE", path),
  };
}

function httpCode(status: number): string {
  switch (status) {
    case 400: return "bad_request";
    case 401: return "unauthorized";
    case 403: return "forbidden";
    case 404: return "not_found";
    case 409: return "conflict";
    case 429: return "rate_limited";
    default: return "internal";
  }
}

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message || e.code;
  if (e instanceof Error) return e.message;
  return String(e);
}
