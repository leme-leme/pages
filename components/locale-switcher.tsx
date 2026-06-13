"use client";

import { useLocale } from "@/contexts/locale-context";
import { cn } from "@/lib/utils";

export function LocaleSwitcher() {
  const locale = useLocale();
  if (!locale || locale.locales.length <= 1) return null;

  return (
    <div className="flex items-center gap-0.5 rounded-md border p-0.5" role="group" aria-label="Locale">
      {locale.locales.map((code) => {
        const active = code === locale.activeLocale;
        return (
          <button
            key={code}
            type="button"
            onClick={() => locale.setActiveLocale(code)}
            aria-pressed={active}
            title={locale.languageName(code)}
            className={cn(
              "rounded px-1.5 py-0.5 text-xs font-medium transition-colors",
              active ? "bg-muted text-foreground" : "text-muted-foreground hover:text-foreground",
            )}
          >
            {code.toUpperCase()}
          </button>
        );
      })}
    </div>
  );
}
