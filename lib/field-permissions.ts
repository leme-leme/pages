import type { Permission, Role } from "@/lib/permissions";
import { ROLE_RANKS } from "@/lib/permissions";

type FieldPermissions = {
  read?: Role | Role[];
  write?: Role | Role[];
};

type Field = {
  name: string;
  fields?: Field[];
  permissions?: FieldPermissions;
};

const toRoleList = (value: Role | Role[] | undefined): Role[] | null => {
  if (!value) return null;
  if (Array.isArray(value)) return value;
  return [value];
};

const meetsRoleRequirement = (role: Role, allowed: Role[]): boolean => {
  const minRank = Math.min(...allowed.map((r) => ROLE_RANKS[r] ?? 99));
  return (ROLE_RANKS[role] ?? 0) >= minRank;
};

export function canSeeField(field: Field, role: Role): boolean {
  const allowed = toRoleList(field.permissions?.read);
  if (!allowed) return true;
  return meetsRoleRequirement(role, allowed);
}

export function canWriteField(field: Field, role: Role): boolean {
  const allowed = toRoleList(field.permissions?.write);
  if (!allowed) {
    // Default to read inheritance: if read is restricted, write is too.
    const readAllowed = toRoleList(field.permissions?.read);
    if (!readAllowed) return true;
    return meetsRoleRequirement(role, readAllowed);
  }
  return meetsRoleRequirement(role, allowed);
}

// Strip values from `data` for fields the user can't write (used to drop
// unwriteable submissions before persisting), and for fields the user
// can't even read (so writes can't be exfiltrated either).
export function stripUnwritableFields<T extends Record<string, any>>(
  data: T,
  fields: Field[],
  role: Role,
  permission: Permission = "write",
): T {
  if (!data || typeof data !== "object") return data;
  const out: Record<string, any> = Array.isArray(data) ? [] : {};
  for (const [key, value] of Object.entries(data)) {
    const field = fields.find((f) => f.name === key);
    if (!field) {
      out[key] = value;
      continue;
    }
    const allowed = permission === "read"
      ? canSeeField(field, role)
      : canWriteField(field, role) && canSeeField(field, role);
    if (!allowed) continue;
    if (Array.isArray(value) && field.fields) {
      out[key] = value.map((item) =>
        item && typeof item === "object"
          ? stripUnwritableFields(item, field.fields!, role, permission)
          : item,
      );
    } else if (value && typeof value === "object" && field.fields) {
      out[key] = stripUnwritableFields(value, field.fields, role, permission);
    } else {
      out[key] = value;
    }
  }
  return out as T;
}

export function filterReadableFields(
  fields: Field[],
  role: Role,
): Field[] {
  return fields
    .filter((f) => canSeeField(f, role))
    .map((f) => f.fields
      ? { ...f, fields: filterReadableFields(f.fields, role) }
      : f,
    );
}
