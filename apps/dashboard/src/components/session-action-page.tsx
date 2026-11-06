"use client";

import { useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { api, APIError, type User } from "@/lib/api";
import { rememberSessionActionReturn } from "@/lib/session-action-return";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/page-layout";

export function SessionActionPage({ title, description, path, children, allowAccountSwitch = true }: {
  title: string;
  description: string;
  path: string;
  children: (user: User) => ReactNode;
  allowAccountSwitch?: boolean;
}) {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [leaving, setLeaving] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    setUser(null);
    setError("");
    api<{ user: User }>("auth/me", { signal: controller.signal })
      .then(({ user }) => { if (!controller.signal.aborted) setUser(user); })
      .catch((failure) => {
        if (controller.signal.aborted) return;
        if (failure instanceof APIError && failure.status === 401) {
          rememberSessionActionReturn(path);
          router.replace("/login");
        } else setError(failure instanceof Error ? failure.message : "Unable to check your account.");
      });
    return () => controller.abort();
  }, [path, router, attempt]);

  async function switchAccount() {
    setLeaving(true);
    setError("");
    try {
      await api("auth/logout", { method: "POST", body: "{}" });
      setUser(null);
      rememberSessionActionReturn(path);
      router.replace("/login");
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Unable to sign out.");
    } finally {
      setLeaving(false);
    }
  }

  return (
    <main className="mx-auto min-h-screen max-w-3xl space-y-6 px-4 py-8 text-sm sm:px-6">
      <header className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <img src="/icon.svg" alt="" width={28} height={28} />
            <span className="text-base font-semibold">OpenAIDR</span>
          </div>
          {user && allowAccountSwitch && <Button variant="outline" size="lg" disabled={leaving} onClick={() => void switchAccount()}>Switch account</Button>}
        </div>
        <div>
          <h1 className="text-display font-semibold">{title}</h1>
          <p className="mt-2 text-muted-foreground">{description}</p>
          {user && <p className="mt-2 break-words">{user.email} · {user.tenant.name}</p>}
        </div>
      </header>
      {error && <ErrorState message={error} onRetry={() => setAttempt((value) => value + 1)} />}
      {!user && !error && <LoadingState label="Checking your account…" />}
      {user && children(user)}
    </main>
  );
}
