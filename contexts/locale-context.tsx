"use client";

import { createContext, useContext, useState } from "react";

function getLanguageName(locale: string): string {
  try {
    const display = new Intl.DisplayNames([locale], { type: "language" });
    const name = display.of(locale);
    if (name && name !== locale) return name.charAt(0).toUpperCase() + name.slice(1);
  } catch {}
  return locale.toUpperCase();
}

type LocaleContextValue = {
  locales: string[];
  activeLocale: string;
  setActiveLocale: (locale: string) => void;
  languageName: (locale: string) => string;
};

const LocaleContext = createContext<LocaleContextValue | null>(null);

export function LocaleProvider({
  locales,
  children,
}: {
  locales: string[];
  children: React.ReactNode;
}) {
  const [activeLocale, setActiveLocale] = useState(locales[0] ?? "en");

  return (
    <LocaleContext.Provider
      value={{
        locales,
        activeLocale,
        setActiveLocale,
        languageName: getLanguageName,
      }}
    >
      {children}
    </LocaleContext.Provider>
  );
}

export function useLocale() {
  return useContext(LocaleContext);
}
