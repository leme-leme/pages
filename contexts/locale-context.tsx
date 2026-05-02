"use client";

import { createContext, useContext, useState, type Dispatch, type SetStateAction } from "react";

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
  activeLocale: controlledLocale,
  onActiveLocaleChange,
}: {
  locales: string[];
  children: React.ReactNode;
  activeLocale?: string;
  onActiveLocaleChange?: Dispatch<SetStateAction<string>>;
}) {
  const [internalLocale, setInternalLocale] = useState(locales[0] ?? "en");
  const isControlled = controlledLocale !== undefined && onActiveLocaleChange !== undefined;
  const activeLocale = isControlled ? controlledLocale : internalLocale;
  const setActiveLocale = (next: string) => {
    if (isControlled) {
      onActiveLocaleChange(next);
    } else {
      setInternalLocale(next);
    }
  };

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
