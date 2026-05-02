import type { Config } from "@/types/config";

export interface I18nConfig {
  structure: "multiple_files" | "multiple_folders" | "single_file";
  locales: string[];
  default_locale: string;
}

export const getI18nConfig = (config: Config): I18nConfig | null => {
  return (config.object as any)?.i18n ?? null;
};

export const getCollectionI18n = (collection: any, config: Config): boolean => {
  if (!collection) return false;
  if (collection.i18n === true) return true;
  if (collection.i18n === false) return false;
  return !!(config.object as any)?.i18n;
};

/**
 * Translate a default-locale path into the equivalent path for `locale`,
 * matching common static-site i18n conventions:
 *
 * - multiple_files:    posts/hello.md           → posts/hello.fr.md
 * - multiple_folders:  posts/hello.md           → posts/fr/hello.md
 * - single_file:       posts/hello.md           → posts/hello.md  (one file, value is keyed inside)
 */
export const getLocalizedPath = (
  originalPath: string,
  locale: string,
  config: Config,
): string => {
  const i18nConfig = getI18nConfig(config);
  if (!i18nConfig || locale === i18nConfig.default_locale) {
    return originalPath;
  }

  const pathParts = originalPath.split("/");
  const filename = pathParts.pop() || "";
  const dotIdx = filename.lastIndexOf(".");
  const extension = dotIdx >= 0 ? filename.slice(dotIdx + 1) : "";
  const nameWithoutExtension = dotIdx >= 0 ? filename.slice(0, dotIdx) : filename;
  const dir = pathParts.join("/");

  switch (i18nConfig.structure) {
    case "multiple_files":
      return `${dir ? dir + "/" : ""}${nameWithoutExtension}.${locale}${extension ? "." + extension : ""}`;
    case "multiple_folders":
      return `${dir ? dir + "/" : ""}${locale}/${filename}`;
    case "single_file":
    default:
      return originalPath;
  }
};
