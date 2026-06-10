import { z } from "zod";
import type { Field } from "@/types/field";
import { EditComponent } from "./edit-component";

// Renamed from "i18n (multilingual)" to avoid confusion with the config-level
// `i18n` structure model. This inline field is an escape hatch for localizing a
// single field's value in an otherwise non-i18n entry (spec §10).
const label = "Localized string";

const schema = (field: Field) => {
  const languages: string[] = ((field.options as any)?.languages as string[]) ?? ["en", "nl"];
  const shape: Record<string, z.ZodTypeAny> = {};
  for (const lang of languages) {
    shape[lang] = z.string().optional();
  }
  return z.object(shape).default({});
};

const defaultValue = () => ({});

const read = (value: any) => {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) return value;
  return {};
};

const write = (value: any) => value ?? {};

export { label, schema, defaultValue, read, write, EditComponent };
