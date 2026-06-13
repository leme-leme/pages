"use client";

import { useLocale } from "@/contexts/locale-context";

export function LocaleSwitcher() {
  const locale = useLocale();
  if (!locale || locale.locales.length <= 1) return null;

  return (
    <select
      aria-label="Locale"
      value={locale.activeLocale}
      onChange={(event) => locale.setActiveLocale(event.target.value)}
      className="h-8 cursor-pointer rounded-md border bg-transparent px-2 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      {locale.locales.map((code) => (
        <option key={code} value={code}>
          {code.toUpperCase()}
        </option>
      ))}
    </select>
  );
}
