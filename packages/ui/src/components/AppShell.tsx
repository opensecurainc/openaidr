import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link, NavLink, useLocation } from "react-router";
import { useTheme, type Theme } from "../hooks/useTheme";
import { initials } from "../utils/format";
import { Mark } from "./Mark";
import { IconLogout, IconMenu, IconMonitor, IconMoon, IconSun } from "./icons";

export interface NavItem { to: string; label: string; icon?: ReactNode; end?: boolean }
export interface NavSection { title?: string; items: NavItem[] }

export interface AppShellProps {
  subtitle: string;
  context?: ReactNode;
  sections: NavSection[];
  user: { name: string; role?: string; email?: string };
  onLogout: () => void;
  title?: ReactNode;
  topbar?: ReactNode;
  footer?: ReactNode;
  children: ReactNode;
  home?: string;
}

export function AppShell({ subtitle, context, sections, user, onLogout, title, topbar, footer, children, home = "/" }: AppShellProps) {
  const [navOpen, setNavOpen] = useState(false);
  const loc = useLocation();
  useEffect(() => { setNavOpen(false); }, [loc.pathname]);

  return (
    <div className={`shell${navOpen ? " shell--nav-open" : ""}`}>
      <div className="shell__scrim" onClick={() => setNavOpen(false)} aria-hidden="true" />
      <aside className="shell__sidebar" aria-label="Main navigation">
        <Link to={home} className="sidebar__brand"><Mark onDark size={28} /><span><span className="sidebar__brand-name">OpenAIDR</span><span className="sidebar__brand-sub">{subtitle}</span></span></Link>
        {context && <div className="sidebar__tenant" title={typeof context === "string" ? context : undefined}>{context}</div>}
        <nav className="sidebar__nav">
          {sections.map((s, i) => (
            <div key={i}>
              {s.title && <div className="nav__section">{s.title}</div>}
              {s.items.map((it) => (
                <NavLink key={it.to} to={it.to} end={it.end} className="nav__item">{it.icon}<span>{it.label}</span></NavLink>
              ))}
            </div>
          ))}
        </nav>
        {footer && <div className="sidebar__footer">{footer}</div>}
      </aside>
      <div className="shell__main">
        <header className="shell__topbar">
          <button type="button" className="btn btn--ghost shell__menu-btn" aria-label="Open navigation" onClick={() => setNavOpen(true)}><IconMenu /></button>
          <h1 className="shell__topbar-title">{title}</h1>
          {topbar}
          <div className="topbar__spacer" />
          <UserMenu user={user} onLogout={onLogout} />
        </header>
        <main className="shell__content">{children}</main>
      </div>
    </div>
  );
}

function UserMenu({ user, onLogout }: { user: AppShellProps["user"]; onLogout: () => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const [theme, setTheme] = useTheme();
  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    const k = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", h); document.addEventListener("keydown", k);
    return () => { document.removeEventListener("mousedown", h); document.removeEventListener("keydown", k); };
  }, [open]);
  const themes: { value: Theme; label: string; icon: ReactNode }[] = [
    { value: "system", label: "System theme", icon: <IconMonitor /> },
    { value: "light", label: "Light theme", icon: <IconSun /> },
    { value: "dark", label: "Dark theme", icon: <IconMoon /> },
  ];
  return (
    <div className="topbar__user" ref={ref}>
      <button type="button" className="topbar__user-btn" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <span className="topbar__avatar" aria-hidden="true">{initials(user.name)}</span>
        <span className="topbar__user-text"><span className="topbar__user-name">{user.name}</span>{user.role && <span className="topbar__user-role">{user.role}</span>}</span>
      </button>
      {open && (
        <div className="menu" role="menu">
          {user.email && <div className="menu__label" style={{ textTransform: "none", letterSpacing: 0 }}>{user.email}</div>}
          <div className="menu__label">Theme</div>
          {themes.map((t) => (
            <button key={t.value} type="button" role="menuitemradio" aria-checked={theme === t.value} className="menu__item" onClick={() => setTheme(t.value)}>
              {t.icon}{t.label}{theme === t.value && <span className="muted" style={{ marginLeft: "auto" }}>on</span>}
            </button>
          ))}
          <div className="menu__sep" />
          <button type="button" role="menuitem" className="menu__item" onClick={onLogout}><IconLogout />Sign out</button>
        </div>
      )}
    </div>
  );
}
