"use client";

import { forwardRef, useState } from "react";
import { useFormContext } from "react-hook-form";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";

const DEFAULT_LANGUAGES = ["en", "nl"];

const LANGUAGE_LABELS: Record<string, string> = {
  en: "EN",
  nl: "NL",
  de: "DE",
  fr: "FR",
  es: "ES",
  it: "IT",
  pt: "PT",
  pl: "PL",
};

export const EditComponent = forwardRef<HTMLDivElement, {
  field: any;
  fieldName: string;
  value: Record<string, string> | null;
  onChange: (value: Record<string, string>) => void;
  disabled?: boolean;
}>(({ field, fieldName, value, onChange, disabled }, ref) => {
  const languages: string[] = field.options?.languages ?? DEFAULT_LANGUAGES;
  const multiline = field.options?.multiline ?? false;

  const [activeLocale, setActiveLocale] = useState<string>(languages[0]);

  const current = value ?? {};

  const handleChange = (locale: string, text: string) => {
    onChange({ ...current, [locale]: text });
  };

  return (
    <div ref={ref} className="space-y-2">
      {/* Language tabs */}
      <div className="flex border-b border-border">
        {languages.map((locale) => {
          const filled = !!current[locale]?.trim();
          return (
            <button
              key={locale}
              type="button"
              onClick={() => setActiveLocale(locale)}
              className={cn(
                "px-3 py-1.5 text-xs font-medium border-b-2 -mb-px transition-colors",
                activeLocale === locale
                  ? "border-primary text-primary"
                  : "border-transparent text-muted-foreground hover:text-foreground",
                filled && activeLocale !== locale && "text-foreground"
              )}
            >
              {LANGUAGE_LABELS[locale] ?? locale.toUpperCase()}
              {filled && activeLocale !== locale && (
                <span className="ml-1 inline-block w-1.5 h-1.5 rounded-full bg-emerald-500 align-middle" />
              )}
            </button>
          );
        })}
      </div>

      {/* Active locale input */}
      {languages.map((locale) => (
        <div key={locale} className={locale === activeLocale ? "block" : "hidden"}>
          {multiline ? (
            <Textarea
              value={current[locale] ?? ""}
              onChange={(e) => handleChange(locale, e.target.value)}
              disabled={disabled}
              placeholder={`${LANGUAGE_LABELS[locale] ?? locale.toUpperCase()} value…`}
              className="min-h-[80px]"
            />
          ) : (
            <Input
              value={current[locale] ?? ""}
              onChange={(e) => handleChange(locale, e.target.value)}
              disabled={disabled}
              placeholder={`${LANGUAGE_LABELS[locale] ?? locale.toUpperCase()} value…`}
            />
          )}
        </div>
      ))}
    </div>
  );
});

EditComponent.displayName = "I18nEditComponent";
