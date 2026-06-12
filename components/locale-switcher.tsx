"use client";

import { useLocale } from "@/contexts/locale-context";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
} from "@/components/ui/select";

export function LocaleSwitcher() {
  const locale = useLocale();
  if (!locale || locale.locales.length <= 1) return null;

  return (
    <Select value={locale.activeLocale} onValueChange={locale.setActiveLocale}>
      <SelectTrigger
        size="sm"
        aria-label="Locale"
        className="h-8 w-auto gap-1 border-none bg-transparent px-2 font-medium text-muted-foreground shadow-none hover:text-foreground"
      >
        {locale.activeLocale.toUpperCase()}
      </SelectTrigger>
      <SelectContent align="end">
        {locale.locales.map((code) => (
          <SelectItem key={code} value={code}>
            {code.toUpperCase()}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
