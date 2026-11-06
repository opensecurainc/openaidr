import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

type Kind = "info" | "success" | "error";
interface Toast { id: number; kind: Kind; text: string }
interface Ctx { push: (text: string, kind?: Kind) => void; success: (text: string) => void; error: (text: string) => void }

const ToastCtx = createContext<Ctx | null>(null);
let seq = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const push = useCallback((text: string, kind: Kind = "info") => {
    const id = ++seq;
    setItems((xs) => [...xs, { id, kind, text }]);
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), kind === "error" ? 6000 : 3500);
  }, []);
  const ctx = useMemo<Ctx>(() => ({ push, success: (t) => push(t, "success"), error: (t) => push(t, "error") }), [push]);
  return (
    <ToastCtx.Provider value={ctx}>
      {children}
      <div className="toasts" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={`toast${t.kind !== "info" ? ` toast--${t.kind}` : ""}`} role={t.kind === "error" ? "alert" : "status"}>
            <span>{t.text}</span>
            <button type="button" aria-label="Dismiss" onClick={() => setItems((xs) => xs.filter((x) => x.id !== t.id))}>x</button>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export function useToast(): Ctx {
  const c = useContext(ToastCtx);
  if (!c) throw new Error("useToast requires ToastProvider");
  return c;
}
