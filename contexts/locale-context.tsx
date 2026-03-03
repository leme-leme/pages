"use client";

import { createContext, useContext, useState } from "react";

const LANGUAGE_NAMES: Record<string, string> = {
  nl: "Nederlands",
  en: "English",
  de: "Deutsch",
  fr: "Français",
  es: "Español",
  it: "Italiano",
  pt: "Português",
  pl: "Polski",
};

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
        languageName: (l) => LANGUAGE_NAMES[l] ?? l.toUpperCase(),
      }}
    >
      {children}
    </LocaleContext.Provider>
  );
}

export function useLocale() {
  return useContext(LocaleContext);
}
