"use client";

import { forwardRef } from "react";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useLocale } from "@/contexts/locale-context";

export const EditComponent = forwardRef<HTMLDivElement, {
  field: any;
  value: Record<string, string> | null;
  onChange: (value: Record<string, string>) => void;
  disabled?: boolean;
}>(({ field, value, onChange, disabled }, ref) => {
  const locale = useLocale();
  const languages: string[] = field.options?.languages ?? ["en", "nl"];
  const multiline = field.options?.multiline ?? false;

  // Active locale: from context if available, else default to first language
  const activeLocale = locale?.activeLocale ?? languages[0];

  const current = value ?? {};

  const handleChange = (text: string) => {
    onChange({ ...current, [activeLocale]: text });
  };

  return (
    <div ref={ref}>
      {multiline ? (
        <Textarea
          value={current[activeLocale] ?? ""}
          onChange={(e) => handleChange(e.target.value)}
          disabled={disabled}
          className="min-h-[80px]"
        />
      ) : (
        <Input
          value={current[activeLocale] ?? ""}
          onChange={(e) => handleChange(e.target.value)}
          disabled={disabled}
        />
      )}
    </div>
  );
});

EditComponent.displayName = "I18nEditComponent";
