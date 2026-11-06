"use client";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { usePathname, useRouter } from "next/navigation";
import { api, APIError, type Overview, type User } from "@/lib/api";
import { clearSessionActionReturn, takeSessionActionReturn } from "@/lib/session-action-return";
import { canAccessPage } from "@/lib/roles";
import { ResourceCache, ResourceCacheContext } from "@/lib/resource-cache";
type Context = {
  user: User | null;
  data: Overview | null;
  range: string;
  service: string;
  setRange: (value: string) => void;
  setService: (value: string) => void;
  loading: boolean;
  authLoading: boolean;
  error: string;
  refresh: () => void;
  refreshUser: () => Promise<void>;
  logout: () => Promise<void>;
  updated: Date | null;
};
const DashboardContext = createContext<Context | null>(null);
export function DashboardProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [user, setUser] = useState<User | null>(null);
  const needsOverview = canAccessPage(user, pathname) && pathname === "/administration/app";
  const roleKey = user?.roles?.join(",");
  const resourceCache = useMemo(() => new ResourceCache(), [user?.id, user?.tenant.id, roleKey]);
  useEffect(() => () => resourceCache.clear(), [resourceCache]);
  const [sessionRenewal, setSessionRenewal] = useState(false);
  const [authLoading, setAuthLoading] = useState(true);
  const [data, setData] = useState<Overview | null>(null);
  const [range, setRange] = useState("24h");
  const [service, setService] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [updated, setUpdated] = useState<Date | null>(null);
  const active = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const identityGeneration = useRef(0);
  useEffect(() => {
    const controller = new AbortController();
    api<{ user: User; session_renewal?: boolean }>("auth/me", { signal: controller.signal })
      .then((result) => {
        setSessionRenewal(result.session_renewal === true);
        const destination = window.location.pathname === "/" ? takeSessionActionReturn() : "";
        if (destination) router.replace(destination);
        else setUser(result.user);
      })
      .catch((error) => {
        if (error.name === "AbortError") return;
        resourceCache.clear();
        if (error instanceof APIError && error.status === 401)
          router.replace("/login");
        else setError(error.message || "Cannot reach the server.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setAuthLoading(false);
      });
    return () => controller.abort();
  }, [router]);
  const refreshUser = useCallback(async () => {
    const currentGeneration = ++identityGeneration.current;
    try {
      const result = await api<{ user: User }>("auth/me", { signal: AbortSignal.timeout(10_000) });
      if (currentGeneration !== identityGeneration.current) return;
      setUser((current) => JSON.stringify(current) === JSON.stringify(result.user) ? current : result.user);
    } catch (failure) {
      if (currentGeneration !== identityGeneration.current) return;
      if (failure instanceof APIError && [401, 403].includes(failure.status)) {
        resourceCache.clear();
        setUser(null);
        setData(null);
        router.replace("/login");
      }
      throw failure;
    }
  }, [resourceCache, router]);
  useEffect(() => {
    if (!user) return;
    let pending = false;
    const check = () => {
      if (document.hidden || pending) return;
      pending = true;
      void refreshUser().catch(() => {}).finally(() => { pending = false; });
    };
    const timer = setInterval(check, 60_000);
    window.addEventListener("focus", check);
    window.addEventListener("dashboard-access-denied", check);
    return () => {
      clearInterval(timer);
      window.removeEventListener("focus", check);
      window.removeEventListener("dashboard-access-denied", check);
    };
  }, [user, refreshUser]);
  useEffect(() => {
    if (!user || !sessionRenewal) return;
    let active: AbortController | null = null;
    let lastRenewed = 0;
    const interval = 15 * 60 * 1000;
    function renew() {
      if (document.hidden || active || Date.now() - lastRenewed < interval) return;
      const controller = new AbortController();
      const startedAt = Date.now();
      active = controller;
      api("auth/renew", { method: "POST", body: "{}", signal: controller.signal })
        .then(() => { lastRenewed = startedAt; })
        .catch((error) => {
          if (controller.signal.aborted) return;
          if (error instanceof APIError && [401, 403].includes(error.status)) {
            identityGeneration.current++;
            resourceCache.clear();
            setUser(null);
            setData(null);
            router.replace("/login");
          }
        })
        .finally(() => { active = null; });
    }
    const timer = setInterval(renew, interval);
    document.addEventListener("visibilitychange", renew);
    renew();
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", renew);
      active?.abort();
    };
  }, [user, sessionRenewal, router, resourceCache]);
  const refresh = useCallback(() => {
    if (!user || !needsOverview || active.current) return;
    const controller = new AbortController();
    active.current = controller;
    const current = ++generation.current;
    setLoading(true);
    const query = new URLSearchParams({ range });
    if (service) query.set("service", service);
    api<Overview>(`telemetry/overview?${query}`, { signal: controller.signal })
      .then((result) => {
        if (current !== generation.current) return;
        setData(result);
        setUpdated(new Date(result.generated_at));
        setError("");
      })
      .catch((error) => {
        if (error.name === "AbortError" || current !== generation.current)
          return;
        if (error instanceof APIError && [401, 403].includes(error.status)) { resourceCache.clear(); setData(null); }
        if (error instanceof APIError && error.status === 401) {
          identityGeneration.current++;
          setUser(null);
          setData(null);
          router.replace("/login");
        } else setError(error.message || "Unable to load telemetry.");
      })
      .finally(() => {
        if (current === generation.current) {
          active.current = null;
          setLoading(false);
        }
      });
  }, [user, range, service, router, needsOverview, resourceCache]);
  useEffect(() => {
    setData(null);
    setUpdated(null);
    setLoading(false);
    refresh();
    const timer = setInterval(() => {
      if (!document.hidden) refresh();
    }, 30000);
    return () => {
      clearInterval(timer);
      generation.current++;
      active.current?.abort();
      active.current = null;
    };
  }, [refresh]);
  async function logout() {
    try {
      await api("auth/logout", { method: "POST", body: "{}" });
      identityGeneration.current++;
      resourceCache.clear();
      clearSessionActionReturn();
      setUser(null);
      setData(null);
      router.replace("/login");
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : "Sign out failed. Please retry.",
      );
    }
  }
  return (
    <DashboardContext.Provider
      value={{
        user,
        data,
        range,
        service,
        setRange,
        setService,
        loading,
        authLoading,
        error,
        refresh,
        refreshUser,
        logout,
        updated,
      }}
    >
      <ResourceCacheContext.Provider value={resourceCache}>
        {children}
      </ResourceCacheContext.Provider>
    </DashboardContext.Provider>
  );
}
export function useDashboard() {
  const context = useContext(DashboardContext);
  if (!context) throw new Error("Dashboard context missing");
  return context;
}
