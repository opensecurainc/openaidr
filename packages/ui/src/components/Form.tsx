import { forwardRef, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";
import { Link } from "react-router";

type Variant = "default" | "primary" | "danger" | "ghost";
export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> { variant?: Variant; size?: "sm" | "md"; icon?: ReactNode; loading?: boolean }

export function Button({ variant = "default", size = "md", icon, loading, className, children, disabled, type = "button", ...rest }: ButtonProps) {
  const cls = ["btn", variant !== "default" ? `btn--${variant}` : "", size === "sm" ? "btn--sm" : "", !children ? "btn--icon" : "", className ?? ""].filter(Boolean).join(" ");
  return <button type={type} className={cls} disabled={disabled || loading} aria-busy={loading || undefined} {...rest}>{icon}{loading ? "Working" : children}</button>;
}

export function LinkButton({ to, variant = "default", size = "md", children, icon }: { to: string; variant?: Variant; size?: "sm" | "md"; children: ReactNode; icon?: ReactNode }) {
  const cls = ["btn", variant !== "default" ? `btn--${variant}` : "", size === "sm" ? "btn--sm" : ""].filter(Boolean).join(" ");
  return <Link to={to} className={cls}>{icon}{children}</Link>;
}

let idSeq = 0;
function useId(prefix: string, id?: string) { return id ?? `${prefix}-${++idSeq}`; }

export function Field({ label, hint, error, children, id, className, grow }: { label: string; hint?: ReactNode; error?: string; children: (id: string) => ReactNode; id?: string; className?: string; grow?: boolean }) {
  const fid = useId("f", id);
  return (
    <div className={["field", grow ? "field--grow" : "", className ?? ""].filter(Boolean).join(" ")}>
      <label className="field__label" htmlFor={fid}>{label}</label>
      {children(fid)}
      {hint && !error && <span className="field__hint">{hint}</span>}
      {error && <span className="field__error" role="alert">{error}</span>}
    </div>
  );
}

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }>(function Input({ className, mono, ...rest }, ref) {
  return <input ref={ref} className={["input", mono ? "input--mono" : "", className ?? ""].filter(Boolean).join(" ")} {...rest} />;
});

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select({ className, ...rest }, ref) {
  return <select ref={ref} className={["select", className ?? ""].filter(Boolean).join(" ")} {...rest} />;
});

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(function Textarea({ className, ...rest }, ref) {
  return <textarea ref={ref} className={["textarea", className ?? ""].filter(Boolean).join(" ")} {...rest} />;
});

export function Checkbox({ label, ...rest }: InputHTMLAttributes<HTMLInputElement> & { label: ReactNode }) {
  return <label className="checkbox"><input type="checkbox" {...rest} />{label}</label>;
}

export function Toggle({ label, checked, onChange, disabled, ariaLabel }: { label?: ReactNode; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; ariaLabel?: string }) {
  return (
    <label className="toggle">
      <input type="checkbox" role="switch" aria-checked={checked} aria-label={ariaLabel} checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span className="toggle__track" aria-hidden="true" />
      {label}
    </label>
  );
}

export function Segmented<T extends string>({ value, options, onChange, ariaLabel }: { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void; ariaLabel: string }) {
  return (
    <div className="segmented" role="group" aria-label={ariaLabel}>
      {options.map((o) => <button key={o.value} type="button" aria-pressed={o.value === value} onClick={() => onChange(o.value)}>{o.label}</button>)}
    </div>
  );
}

export function FormError({ error }: { error: unknown }) {
  if (!error) return null;
  const msg = error instanceof Error ? error.message : String(error);
  return <div className="form__error" role="alert">{msg}</div>;
}
