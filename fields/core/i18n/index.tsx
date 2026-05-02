import { z } from "zod";
import type { Field } from "@/types/field";
import { EditComponent } from "./edit-component";

const label = "i18n (multilingual)";

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
