"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { api, APIError, productLabel } from "@/lib/api";
import { rememberSessionActionReturn } from "@/lib/session-action-return";
import { SessionActionPage } from "@/components/session-action-page";
import { PageSection, ErrorState } from "@/components/page-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { CodeBlock } from "@/components/ui/code-block";
import { Status } from "@/components/ui/status";

type Registration = { id: string; product: string; external_id: string; status: string };

export default function RegisterSession() {
  return (
    <SessionActionPage title="Register your agent session" description="Connect the session waiting in your managed client to your signed-in account." path="/register-session">
      {(user) => <RegistrationForm key={user.id} />}
    </SessionActionPage>
  );
}

function RegistrationForm() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [registration, setRegistration] = useState<Registration | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    const code = String(new FormData(form).get("code") || "").trim();
    setBusy(true);
    setError("");
    try {
      const result = await api<Registration>("session-registrations/confirm", {
        method: "POST", body: JSON.stringify({ token: code }),
      });
      form.reset();
      setRegistration(result);
    } catch (failure) {
      form.reset();
      if (failure instanceof APIError && failure.status === 401) {
        rememberSessionActionReturn("/register-session");
        router.replace("/login");
      } else setError(failure instanceof APIError && failure.status === 404
        ? "This code is expired, already used, or unavailable for your account. Get a current code from your client."
        : failure instanceof Error ? failure.message : "Unable to register the session.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <PageSection title={registration ? "Session registered" : "Confirmation code"}>
      {registration ? (
        <div className="space-y-3">
          <Status tone="ok">Registered to your account</Status>
          <p>{productLabel(registration.product)}</p>
          <CodeBlock aria-label="Native session ID">{registration.external_id}</CodeBlock>
          <p>Return to your managed client to continue.</p>
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="session-code">Code from your client</Label>
            <Input id="session-code" name="code" type="password" size="lg" autoComplete="off" spellCheck={false} required maxLength={48} pattern="oasr_[A-Za-z0-9_-]{43}" disabled={busy} aria-describedby="code-help" />
            <p id="code-help" className="text-muted-foreground">Paste the code shown by the managed session you started. Registration associates its captured activity with your account.</p>
          </div>
          {error && <ErrorState message={error} />}
          <Button type="submit" size="lg" disabled={busy}>{busy ? "Registering…" : "Register session"}</Button>
        </form>
      )}
    </PageSection>
  );
}
