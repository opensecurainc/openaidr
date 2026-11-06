"use client";

import { roleNames, type Role } from "@/lib/roles";
import { useEffect, useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck, LoaderCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { takeSessionActionReturn } from "@/lib/session-action-return";
export default function Login() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [mode, setMode] = useState<"local" | "cloud_google" | null>(null);
  const [invitation, setInvitation] = useState<{ email: string; roles: Role[]; tenant_name: string } | null>(null);
  useEffect(() => {
    let active = true;
    async function discover() {
      try {
        const config = await api<{ mode: string; password_login: boolean }>("auth/config");
        if (config.mode !== "local" && config.mode !== "cloud_google") throw new Error("Sign-in configuration is unavailable.");
        if (!active) return;
        setMode(config.mode);
        const query = new URLSearchParams(window.location.search);
        if (query.has("auth_error")) setError("Google sign-in was not completed. Use an invited account or contact your administrator.");
        if (config.mode === "cloud_google" && query.has("invitation")) {
          const pending = await api<{ email: string; roles: Role[]; tenant_name: string }>("auth/oidc/invite");
          if (active) setInvitation(pending);
        }
      } catch (error) {
        if (active) setError(error instanceof Error ? error.message : "Unable to load sign-in settings.");
      }
    }
    void discover();
    return () => { active = false; };
  }, []);
  async function google(accept = false) {
    setBusy(true);
    setError("");
    try {
      if (accept) {
        await api("auth/oidc/accept", { method: "POST", body: "{}" });
        router.replace(takeSessionActionReturn() || "/");
      } else {
        const result = await api<{ authorization_url: string }>("auth/oidc/start", { method: "POST", body: "{}" });
        window.location.assign(result.authorization_url);
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to sign in. Try again.");
    } finally {
      setBusy(false);
    }
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setBusy(true);
    const form = event.currentTarget;
    const fields = new FormData(form);
    try {
      await api("auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: fields.get("email"),
          password: fields.get("password"),
        }),
      });
      form.reset();
      router.replace(takeSessionActionReturn() || "/");
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : "Unable to sign in. Try again.",
      );
      const password = form.elements.namedItem("password") as HTMLInputElement;
      password.value = "";
      password.focus();
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="grid min-h-screen lg:grid-cols-[2fr_3fr]">
      <section className="hidden flex-col justify-between bg-sidebar p-12 text-white lg:flex">
        <div className="flex items-center gap-3">
          <img src="/icon-dark.svg" alt="" width={32} height={32} />
          <span className="text-base font-semibold">OpenAIDR</span>
        </div>
        <div className="max-w-md">
          <p className="text-display font-semibold">
            Know what your AI agents are doing.
          </p>
          <p className="mt-3 text-sm text-sidebar-foreground">
            Agent activity, connected devices, and telemetry across your
            organization.
          </p>
        </div>
        <p className="flex items-center gap-2 text-xs text-sidebar-foreground">
          <ShieldCheck aria-hidden="true" className="size-4 opacity-70" />
          Hosted in your environment. Controlled by you.
        </p>
      </section>
      <section className="flex items-center justify-center px-6 py-16">
        <div className="w-full max-w-sm">
          <div className="mb-10 flex items-center gap-3 lg:hidden">
            <img src="/icon.svg" alt="" width={32} height={32} />
            <span className="text-base font-semibold">OpenAIDR</span>
          </div>
          <h1 className="text-display font-semibold">Sign in</h1>
          <p className="mt-1 mb-8 text-sm text-muted-foreground">
            Use your OpenAIDR workspace account.
          </p>
          {!mode && !error && <p role="status" className="text-sm text-muted-foreground">Loading sign-in options…</p>}
          {mode === "cloud_google" && (
            <div className="space-y-4">
              {invitation && <p className="text-sm">Accept your invitation to <strong>{invitation.tenant_name}</strong> as {roleNames(invitation.roles)}, signed in as {invitation.email}.</p>}
              <Button className="w-full" size="lg" disabled={busy} onClick={() => void google(!!invitation)}>
                {busy && <LoaderCircle className="animate-spin" />}
                {invitation ? "Accept invitation" : "Continue with Google"}
              </Button>
              {invitation && <Button variant="outline" className="w-full" disabled={busy} onClick={() => { setInvitation(null); void google(); }}>Restart Google sign-in</Button>}
            </div>
          )}
          {mode === "local" && <form onSubmit={submit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email address</Label>
              <Input
                id="email"
                name="email"
                type="email"
                autoComplete="username"
                required
                placeholder="you@company.com"
                size="lg"
                disabled={busy}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                size="lg"
                disabled={busy}
              />
            </div>
            <Button
              type="submit"
              size="lg"
              disabled={busy}
              className="mt-2 w-full"
            >
              {busy && <LoaderCircle className="animate-spin" />}
              {busy ? "Signing in…" : "Sign in"}
            </Button>
          </form>}
          {error && <p role="alert" className="mt-4 rounded-md border-l-4 border-status-critical bg-status-critical/10 px-3 py-2 text-sm text-foreground">{error}</p>}
          {!mode && error && <Button className="mt-4 w-full" onClick={() => window.location.reload()}>Retry</Button>}
          <p className="mt-6 text-xs text-muted-foreground">
            Need access? Ask your organization’s administrator for an account.
          </p>
        </div>
      </section>
    </main>
  );
}
