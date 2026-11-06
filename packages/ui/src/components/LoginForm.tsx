import { useState, type FormEvent, type ReactNode } from "react";
import { errorMessage } from "../api/client";
import { Button, Field, Input } from "./Form";
import { Mark } from "./Mark";

export function AuthLayout({ title, subtitle, children }: { title: string; subtitle: string; children: ReactNode }) {
  return (
    <div className="auth">
      <div className="auth__card">
        <div className="auth__brand"><Mark size={32} /><div><strong>OpenAIDR</strong><span>{subtitle}</span></div></div>
        <h1>{title}</h1>
        {children}
      </div>
    </div>
  );
}

export function LoginForm({ onSubmit, hint }: { onSubmit: (email: string, password: string) => Promise<void>; hint?: ReactNode }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true); setError(null);
    try { await onSubmit(email.trim(), password); } catch (err) { setError(errorMessage(err)); } finally { setBusy(false); }
  };
  return (
    <form className="form" onSubmit={(e) => void submit(e)}>
      <Field label="Email">{(id) => <Input id={id} type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />}</Field>
      <Field label="Password">{(id) => <Input id={id} type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />}</Field>
      {error && <div className="form__error" role="alert">{error}</div>}
      <Button type="submit" variant="primary" loading={busy}>Sign in</Button>
      {hint && <div className="small muted">{hint}</div>}
    </form>
  );
}
