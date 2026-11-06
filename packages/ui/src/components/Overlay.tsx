import { useEffect, useRef, type ReactNode } from "react";
import { Button } from "./Form";
import { IconX } from "./icons";

function useEscape(onClose: () => void) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", h);
    return () => document.removeEventListener("keydown", h);
  }, [onClose]);
}

function useInitialFocus() {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const prev = document.activeElement as HTMLElement | null;
    const first = el.querySelector<HTMLElement>("input, select, textarea, button, [tabindex]:not([tabindex='-1'])");
    (first ?? el).focus();
    return () => prev?.focus?.();
  }, []);
  return ref;
}

export function Modal({ title, onClose, children, footer, size }: { title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; size?: "lg" }) {
  useEscape(onClose);
  const ref = useInitialFocus();
  return (
    <div className="overlay" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className={`modal${size === "lg" ? " modal--lg" : ""}`} role="dialog" aria-modal="true" aria-label={title} ref={ref} tabIndex={-1}>
        <div className="modal__header"><h2>{title}</h2><Button variant="ghost" size="sm" aria-label="Close" onClick={onClose} icon={<IconX />} /></div>
        <div className="modal__body">{children}</div>
        {footer && <div className="modal__footer">{footer}</div>}
      </div>
    </div>
  );
}

export function Drawer({ title, onClose, children, actions }: { title: ReactNode; onClose: () => void; children: ReactNode; actions?: ReactNode }) {
  useEscape(onClose);
  const ref = useInitialFocus();
  return (
    <div className="overlay overlay--drawer" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="drawer" role="dialog" aria-modal="true" ref={ref} tabIndex={-1}>
        <div className="drawer__header"><h2>{title}</h2><div className="row">{actions}<Button variant="ghost" size="sm" aria-label="Close" onClick={onClose} icon={<IconX />} /></div></div>
        <div className="drawer__body">{children}</div>
      </div>
    </div>
  );
}

export function ConfirmDialog({ title, message, confirmLabel = "Confirm", danger, onConfirm, onCancel, busy }: {
  title: string; message: ReactNode; confirmLabel?: string; danger?: boolean; onConfirm: () => void; onCancel: () => void; busy?: boolean;
}) {
  return (
    <Modal title={title} onClose={onCancel} footer={<>
      <Button onClick={onCancel} disabled={busy}>Cancel</Button>
      <Button variant={danger ? "danger" : "primary"} onClick={onConfirm} loading={busy}>{confirmLabel}</Button>
    </>}>
      <div>{message}</div>
    </Modal>
  );
}
