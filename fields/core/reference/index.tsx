import { z } from "zod";
import { Field } from "@/types/field";
import { EditComponent } from "./edit-component";

const schema = (field: Field) => {
  let zodSchema: z.ZodTypeAny = z.coerce.string();

  const isMultiple = !!(field.options?.multiple ?? (field as any).multiple);
  if (isMultiple) zodSchema = z.array(zodSchema);

  if (!field.required) zodSchema = zodSchema.optional();

  return zodSchema;
};

const label = "Reference";

export { label, schema, EditComponent };