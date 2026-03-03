import { z } from "zod";
import { Field } from "@/types/field";
import { EditComponent } from "./edit-component";

const schema = (field: Field) => {
  const isMultiple = !!(field.options?.multiple ?? (field as any).multiple);
  let zodSchema: z.ZodTypeAny = z.coerce.string();

  if (isMultiple) {
    zodSchema = z.preprocess(
      (val) => {
        if (val === null || val === undefined || val === "") return [];
        if (Array.isArray(val)) return val;
        if (typeof val === "string") return val.split(",").map((s) => s.trim()).filter(Boolean);
        return val;
      },
      z.array(zodSchema)
    );
  }

  if (!field.required) zodSchema = zodSchema.optional();

  return zodSchema;
};

const label = "Reference";

export { label, schema, EditComponent };