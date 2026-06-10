import type { Config } from "@/types/config";
import type { Field } from "@/types/field";

export type I18nStructure = "multiple_files" | "multiple_folders" | "single_file";

export interface I18nConfig {
  structure: I18nStructure;
  locales: string[];
  default_locale: string;
}

/** Normalized per-field localization mode (see spec §5.3). */
export type FieldI18nMode = "translate" | "duplicate" | "none";

export const getI18nConfig = (config: Config): I18nConfig | null => {
  const i18n = (config.object as any)?.i18n;
  if (!i18n || typeof i18n !== "object" || !Array.isArray(i18n.locales) || i18n.locales.length === 0) {
    return null;
  }
  return {
    structure: i18n.structure as I18nStructure,
    locales: i18n.locales as string[],
    default_locale: i18n.default_locale ?? i18n.locales[0],
  };
};

/** True when the repo i18n structure stores every locale in one file. */
export const isSingleFile = (config: Config): boolean =>
  getI18nConfig(config)?.structure === "single_file";

/**
 * Normalize a field's `i18n` key to a localization mode. Aliases:
 * `true → translate`, `false / null / undefined → none`. When the collection
 * is not i18n-enabled, every field is `none` (spec §5.3, §13).
 */
export const getFieldI18nMode = (
  field: Pick<Field, "i18n">,
  collectionI18nEnabled: boolean,
): FieldI18nMode => {
  if (!collectionI18nEnabled) return "none";
  const raw = field?.i18n;
  if (raw === true || raw === "translate") return "translate";
  if (raw === "duplicate") return "duplicate";
  return "none";
};

export const getCollectionI18n = (collection: any, config: Config): boolean => {
  if (!collection) return false;
  if (collection.i18n === true) return true;
  if (collection.i18n === false) return false;
  return !!(config.object as any)?.i18n;
};

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
      // One file holds every locale; the path is locale-independent.
      return originalPath;
  }
};

/**
 * Map every configured locale to its on-disk path for a canonical entry path.
 * For `single_file` all locales resolve to the same path. Returns an empty map
 * when i18n is not configured.
 */
export const getLocalePaths = (
  canonicalPath: string,
  config: Config,
): Record<string, string> => {
  const i18nConfig = getI18nConfig(config);
  if (!i18nConfig) return {};
  const paths: Record<string, string> = {};
  for (const locale of i18nConfig.locales) {
    paths[locale] = getLocalizedPath(canonicalPath, locale, config);
  }
  return paths;
};

/**
 * If `filePath` is a non-default locale variant, return its locale; otherwise
 * null (it is the canonical/default-locale path or not localized).
 */
export const getLocaleFromPath = (filePath: string, config: Config): string | null => {
  const i18nConfig = getI18nConfig(config);
  if (!i18nConfig) return null;
  for (const locale of i18nConfig.locales) {
    if (locale === i18nConfig.default_locale) continue;
    if (getLocalizedPath(filePath, locale, config) === filePath) continue; // would not change → not this locale
    // Reconstruct: does treating filePath as this locale's variant of some canonical hold?
    if (i18nConfig.structure === "multiple_files") {
      const m = filePath.match(/^(.*)\.([^./]+)\.([^./]+)$/);
      if (m && m[2] === locale) return locale;
    } else if (i18nConfig.structure === "multiple_folders") {
      const parts = filePath.split("/");
      if (parts.length >= 2 && parts[parts.length - 2] === locale) return locale;
    }
  }
  return null;
};

/**
 * Translation status for an entry: which locales have an existing file among
 * `existingPaths`. For `single_file` only the default is path-derivable
 * (per-locale presence needs the file body — see i18n docs).
 */
export const getTranslationStatus = (
  canonicalPath: string,
  existingPaths: Iterable<string>,
  config: Config,
): Record<string, boolean> => {
  const i18nConfig = getI18nConfig(config);
  if (!i18nConfig) return {};
  const present = existingPaths instanceof Set ? existingPaths : new Set(existingPaths);
  const status: Record<string, boolean> = {};
  for (const locale of i18nConfig.locales) {
    if (i18nConfig.structure === "single_file" && locale !== i18nConfig.default_locale) {
      status[locale] = present.has(canonicalPath); // best-effort; body holds the truth
    } else {
      status[locale] = present.has(getLocalizedPath(canonicalPath, locale, config));
    }
  }
  return status;
};
