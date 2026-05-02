"use client";

import { useLocale } from "@/contexts/locale-context";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Globe } from "lucide-react";

export function LocaleSwitcher() {
  const locale = useLocale();
  if (!locale || locale.locales.length <= 1) return null;

  return (
    <Select value={locale.activeLocale} onValueChange={locale.setActiveLocale}>
      <SelectTrigger size="sm" className="h-8 gap-1.5">
        <Globe className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
        <SelectValue placeholder="Locale" />
      </SelectTrigger>
      <SelectContent>
        {locale.locales.map((code) => (
          <SelectItem key={code} value={code}>
            <span className="font-medium">{code.toUpperCase()}</span>
            <span className="text-muted-foreground ml-2">{locale.languageName(code)}</span>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
