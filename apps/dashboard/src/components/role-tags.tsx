"use client";

import { useId } from "react";
import { Badge } from "@/components/ui/badge";
import { ROLES, type Role } from "@/lib/roles";

export function RoleTags({ roles }: { roles: readonly Role[] }) {
  return <div className="flex flex-wrap gap-1">{ROLES.filter((role) => roles.includes(role.value)).map((role) => <Badge key={role.value}>{role.name}</Badge>)}</div>;
}

export function RoleSelection({ value, onChange, disabled, retainAdmin = false }: {
  value: Role[];
  onChange: (roles: Role[]) => void;
  disabled?: boolean;
  retainAdmin?: boolean;
}) {
  const id = useId();
  return (
    <fieldset disabled={disabled} aria-describedby={`${id}-help`}>
      <legend className="text-sm font-medium">Roles</legend>
      <p id={`${id}-help`} className="mt-1 text-xs text-muted-foreground">Select one or more roles. Access combines across selected roles.</p>
      <div className="mt-2 divide-y">
        {ROLES.map((role) => (
          <label key={role.value} className="flex cursor-pointer items-start gap-3 py-3">
            <input
              type="checkbox"
              className="mt-1 size-4 shrink-0 accent-primary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
              checked={value.includes(role.value)}
              disabled={disabled || (retainAdmin && role.value === "it_admin")}
              aria-label={role.name}
              onChange={(event) => onChange(ROLES.filter((item) => item.value === role.value ? event.target.checked : value.includes(item.value)).map((item) => item.value))}
            />
            <span className="min-w-0">
              <span className="block text-sm font-medium">{role.name}</span>
              <span className="mt-1 block text-sm text-muted-foreground">{role.description}</span>
            </span>
          </label>
        ))}
      </div>
      {retainAdmin && <p className="text-xs text-muted-foreground">This is the last active IT Admin. Assign another IT Admin before removing this role.</p>}
    </fieldset>
  );
}
