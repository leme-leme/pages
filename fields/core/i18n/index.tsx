import { EditComponent } from "./edit-component";
import { z } from "zod";
import { Field } from "@/types/field";

const label = "i18n (multilingual)";

const schema = (field: Field) => {
  const languages: string[] = (field.options?.languages as string[]) ?? ["en", "nl"];
  // Object with optional string values per locale
  const shape: Record<string, z.ZodString> = {};
  for (const lang of languages) {
    shape[lang] = z.string().optional() as unknown as z.ZodString;
  }
  let s = z.object(shape).default({});
  return s as z.ZodTypeAny;
};

const defaultValue = () => ({});

// Read: stored as object { en: "...", nl: "..." } — pass through as-is
const read = (value: any) => {
  if (typeof value === "object" && value !== null) return value;
  return {};
};

// Write: pass through as-is
const write = (value: any) => value ?? {};

export { label, schema, defaultValue, read, write, EditComponent };
