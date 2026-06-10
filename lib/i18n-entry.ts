/**
 * Localized entry model (spec §7).
 *
 * Bridges the per-locale editor state (`Record<locale, contentObject>`) and the
 * on-disk representation for each i18n structure:
 *
 *  - `multiple_files` / `multiple_folders`: one file per locale. `translate`
 *    fields differ per file, `duplicate` fields carry the default value into
 *    every file, `none` fields live only in the default-locale file.
 *  - `single_file`: one file with a locale-keyed object. `translate` fields live
 *    inside each locale block; `duplicate`/`none` fields live once at the root.
 *
 * The markdown `body` is always treated as translatable. Unknown content keys
 * (not declared as fields) are kept per-locale so no data is silently dropped.
 */

import type { Config } from "@/types/config";
import type { Field } from "@/types/field";
import { parse, stringify } from "@/lib/serialization";
import {
  getFieldI18nMode,
  getI18nConfig,
  getLocalizedPath,
  type FieldI18nMode,
} from "@/lib/i18n";

type ContentObject = Record<string, any>;

/** Editor-facing value model: every locale's full content object. */
export type ValuesByLocale = Record<string, ContentObject>;

export type LocaleFile = {
  locale: string;
  path: string;
  contentObject: ContentObject;
};

export type SerializedFile = {
  locale: string | null; // null = the single merged file in `single_file`
  path: string;
  content: string;
};

type FormatOptions = { format?: any; delimiters?: any };

/**
 * Partition a collection's top-level field names by localization mode. `body`
 * is reported separately and always treated as translatable.
 */
export const partitionTopLevelModes = (
  fields: Field[] | undefined,
  i18nEnabled: boolean,
): { translate: Set<string>; duplicate: Set<string>; none: Set<string> } => {
  const translate = new Set<string>();
  const duplicate = new Set<string>();
  const none = new Set<string>();
  for (const field of fields ?? []) {
    if (!field?.name) continue;
    const mode: FieldI18nMode = getFieldI18nMode(field, i18nEnabled);
    if (mode === "translate") translate.add(field.name);
    else if (mode === "duplicate") duplicate.add(field.name);
    else none.add(field.name);
  }
  return { translate, duplicate, none };
};

const cloneValue = <T>(value: T): T =>
  value === undefined ? value : JSON.parse(JSON.stringify(value));

/**
 * Build the canonical per-locale content objects for a `multiple_*` structure
 * from the editor's per-locale values, applying field modes. `none` fields are
 * omitted from non-default locales; `duplicate` fields take the default value.
 */
export const buildLocaleContentObjects = ({
  fields,
  valuesByLocale,
  config,
  i18nEnabled = true,
}: {
  fields: Field[] | undefined;
  valuesByLocale: ValuesByLocale;
  config: Config;
  i18nEnabled?: boolean;
}): Record<string, ContentObject> => {
  const i18nConfig = getI18nConfig(config);
  if (!i18nConfig) return { ...valuesByLocale };
  const { locales, default_locale: defaultLocale } = i18nConfig;
  const { duplicate, none } = partitionTopLevelModes(fields, i18nEnabled);
  const defaultObject = valuesByLocale[defaultLocale] ?? {};

  const result: Record<string, ContentObject> = {};
  for (const locale of locales) {
    const source = valuesByLocale[locale] ?? {};
    const out: ContentObject = { ...source };
    for (const key of duplicate) {
      out[key] = cloneValue(defaultObject[key]);
    }
    if (locale !== defaultLocale) {
      for (const key of none) delete out[key];
    }
    result[locale] = out;
  }
  return result;
};

/**
 * Produce the file writes for an entry across all locales. Returns one entry per
 * locale for `multiple_*`, or a single merged file for `single_file`.
 */
export const serializeLocalizedEntry = ({
  fields,
  valuesByLocale,
  canonicalPath,
  config,
  format,
  delimiters,
  i18nEnabled = true,
}: {
  fields: Field[] | undefined;
  valuesByLocale: ValuesByLocale;
  canonicalPath: string;
  config: Config;
  i18nEnabled?: boolean;
} & FormatOptions): SerializedFile[] => {
  const i18nConfig = getI18nConfig(config);
  if (!i18nConfig) {
    return [
      {
        locale: null,
        path: canonicalPath,
        content: stringify(valuesByLocale[Object.keys(valuesByLocale)[0]] ?? {}, { format, delimiters }),
      },
    ];
  }

  const { locales, default_locale: defaultLocale } = i18nConfig;
  const perLocale = buildLocaleContentObjects({ fields, valuesByLocale, config, i18nEnabled });

  if (i18nConfig.structure === "single_file") {
    const { duplicate, none } = partitionTopLevelModes(fields, i18nEnabled);
    const shared = new Set<string>([...duplicate, ...none]);
    const merged: ContentObject = {};
    // Shared (duplicate/none) fields live at the root, taken from the default locale.
    const defaultObject = perLocale[defaultLocale] ?? {};
    for (const key of shared) {
      if (defaultObject[key] !== undefined) merged[key] = cloneValue(defaultObject[key]);
    }
    // Each locale block holds the translatable fields + body.
    for (const locale of locales) {
      const localeObject = perLocale[locale] ?? {};
      const block: ContentObject = {};
      for (const [key, value] of Object.entries(localeObject)) {
        if (!shared.has(key)) block[key] = value;
      }
      merged[locale] = block;
    }
    return [
      { locale: null, path: canonicalPath, content: stringify(merged, { format, delimiters }) },
    ];
  }

  // multiple_files / multiple_folders
  return locales.map((locale) => ({
    locale,
    path: getLocalizedPath(canonicalPath, locale, config),
    content: stringify(perLocale[locale] ?? {}, { format, delimiters }),
  }));
};

/**
 * Reconstruct the editor's per-locale values from the parsed content objects of
 * each locale file. `duplicate`/`none` fields are hydrated from the default
 * locale so they display (and stay in sync) in every pane.
 */
export const mergeLocaleContentObjects = ({
  fields,
  objectsByLocale,
  config,
  i18nEnabled = true,
}: {
  fields: Field[] | undefined;
  objectsByLocale: Record<string, ContentObject | undefined>;
  config: Config;
  i18nEnabled?: boolean;
}): ValuesByLocale => {
  const i18nConfig = getI18nConfig(config);
  if (!i18nConfig) return { ...(objectsByLocale as ValuesByLocale) };
  const { locales, default_locale: defaultLocale } = i18nConfig;
  const { duplicate, none } = partitionTopLevelModes(fields, i18nEnabled);
  const defaultObject = objectsByLocale[defaultLocale] ?? {};

  const values: ValuesByLocale = {};
  for (const locale of locales) {
    const source = objectsByLocale[locale] ?? {};
    const out: ContentObject = { ...source };
    for (const key of duplicate) out[key] = cloneValue(defaultObject[key]);
    if (locale !== defaultLocale) {
      for (const key of none) out[key] = cloneValue(defaultObject[key]);
    }
    values[locale] = out;
  }
  return values;
};

/**
 * Inverse of `serializeLocalizedEntry`. `filesByLocale` maps each locale to its
 * raw file content; for `single_file`, pass the one file under any key (it is
 * parsed and split by locale).
 */
export const deserializeLocalizedEntry = ({
  fields,
  filesByLocale,
  config,
  format,
  delimiters,
  i18nEnabled = true,
}: {
  fields: Field[] | undefined;
  filesByLocale: Record<string, string | undefined>;
  config: Config;
  i18nEnabled?: boolean;
} & FormatOptions): ValuesByLocale => {
  const i18nConfig = getI18nConfig(config);
  if (!i18nConfig) {
    const only = Object.values(filesByLocale)[0] ?? "";
    return { default: parse(only, { format, delimiters }) };
  }
  const { locales, default_locale: defaultLocale } = i18nConfig;

  if (i18nConfig.structure === "single_file") {
    const raw = Object.values(filesByLocale).find((c) => c != null) ?? "";
    const merged = parse(raw, { format, delimiters }) as ContentObject;
    const { duplicate, none } = partitionTopLevelModes(fields, i18nEnabled);
    const shared = new Set<string>([...duplicate, ...none]);
    const sharedValues: ContentObject = {};
    for (const key of shared) {
      if (merged[key] !== undefined) sharedValues[key] = merged[key];
    }
    const values: ValuesByLocale = {};
    for (const locale of locales) {
      const block = (merged[locale] as ContentObject) ?? {};
      values[locale] = { ...cloneValue(sharedValues), ...block };
    }
    return values;
  }

  const objectsByLocale: Record<string, ContentObject> = {};
  for (const locale of locales) {
    const raw = filesByLocale[locale];
    objectsByLocale[locale] = raw != null ? (parse(raw, { format, delimiters }) as ContentObject) : {};
  }
  void defaultLocale;
  return mergeLocaleContentObjects({ fields, objectsByLocale, config, i18nEnabled });
};
