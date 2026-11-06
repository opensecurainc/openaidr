"use client";

import { roleNames, type Role } from "@/lib/roles";

import { useEffect, useRef, useState, type FormEvent } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useTimeZone } from "@/components/time-zone-context";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, APIError } from "@/lib/api";

type Invitation = { email: string; tenant_name: string; roles: Role[]; expires_at: string };

export default function AcceptInvitation() {
  const router = useRouter();
  const { dateTime } = useTimeZone();
  const [invitation, setInvitation] = useState<Invitation | null>(null);
  const [loading, setLoading] = useState(true);
  const [google, setGoogle] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submitting = useRef(false);
  const token = useRef("");

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      try {
        token.current = new URLSearchParams(window.location.search).get("token") || "";
        const config = await api<{ mode: string }>("auth/config", { signal: controller.signal });
        if (config.mode === "cloud_google") {
          if (!controller.signal.aborted) setGoogle(true);
          return;
        }
        if (config.mode !== "local") throw new Error("Sign-in configuration is unavailable.");
        if (!token.current) throw new Error("This invitation link is incomplete. Ask your administrator for a new link.");
        const info = await api<Invitation>(`auth/invite?token=${encodeURIComponent(token.current)}`, { signal: controller.signal });
        if (!controller.signal.aborted) setInvitation(info);
      } catch (failure) {
        if (!controller.signal.aborted) {
          setError(failure instanceof APIError && [401, 404].includes(failure.status)
            ? "This invitation is invalid, expired, or already used. Ask your administrator for a new link."
            : failure instanceof Error ? failure.message : "Unable to load the invitation.");
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    void load();
    return () => controller.abort();
  }, []);

  async function accept(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting.current || !invitation) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    const name = String(fields.get("name") || "").trim();
    const password = String(fields.get("password") || "");
    if (!name) { setError("Enter your name."); return; }
    if (password !== fields.get("confirm")) { setError("Passwords do not match."); return; }
    submitting.current = true;
    setBusy(true);
    setError("");
    try {
      await api("auth/accept-invite", {
        method: "POST",
        body: JSON.stringify({ token: token.current, name, password }),
      });
      form.reset();
      token.current = "";
      router.replace("/");
    } catch (failure) {
      for (const field of ["password", "confirm"]) (form.elements.namedItem(field) as HTMLInputElement).value = "";
      if (failure instanceof APIError && [401, 404].includes(failure.status)) setInvitation(null);
      setError(failure instanceof APIError && [401, 404].includes(failure.status)
        ? "This invitation is no longer valid. Ask your administrator for a new link."
        : failure instanceof Error ? failure.message : "Unable to create your account.");
      submitting.current = false;
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <section className="w-full max-w-md space-y-4 rounded-lg border bg-card p-6">
        <div className="flex items-center gap-3">
          <img src="/icon.svg" alt="" width={28} height={28} />
          <span className="text-base font-semibold">OpenAIDR</span>
        </div>
        <h1 className="text-display font-semibold">Accept invitation</h1>
        {loading && <p role="status" className="text-sm text-muted-foreground">Loading invitation…</p>}
        {google && <p className="text-sm">This workspace uses Google sign-in. Sign in with the email address your administrator invited.</p>}
        {invitation && (
          <form onSubmit={accept} className="space-y-4">
            <p className="break-words text-sm">
              Join <strong>{invitation.tenant_name}</strong> as <span className="capitalize">{roleNames(invitation.roles)}</span>,
              using <strong>{invitation.email}</strong>.
            </p>
            <p className="text-xs text-muted-foreground">Invitation expires {dateTime(invitation.expires_at)}.</p>
            <div className="space-y-2">
              <Label htmlFor="invite-name">Your name</Label>
              <Input id="invite-name" name="name" autoComplete="name" required disabled={busy} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="invite-password">Password</Label>
              <Input id="invite-password" name="password" type="password" autoComplete="new-password" minLength={10} aria-describedby="password-requirement" required disabled={busy} />
              <p id="password-requirement" className="text-xs text-muted-foreground">Use at least 10 characters.</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="invite-confirm">Confirm password</Label>
              <Input id="invite-confirm" name="confirm" type="password" autoComplete="new-password" minLength={10} required disabled={busy} />
            </div>
            <Button type="submit" className="w-full" disabled={busy}>{busy ? "Creating account…" : "Create account"}</Button>
          </form>
        )}
        {error && <p role="alert" className="rounded-md border-l-4 border-status-critical bg-status-critical/10 px-3 py-2 text-sm">{error}</p>}
        {!loading && !busy && <Link href="/login" className="text-sm text-primary underline">{google ? "Continue to sign in" : "Back to sign in"}</Link>}
        {!loading && !invitation && !google && error && <Button variant="outline" onClick={() => window.location.reload()}>Retry</Button>}
      </section>
    </main>
  );
}
