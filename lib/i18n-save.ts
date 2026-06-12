/** Loads and saves an i18n entry across its locale files via `/files-batch`. */

import type { Config } from "@/types/config";
import type { Field } from "@/types/field";
import {
  getI18nConfig,
  getLocalePaths,
  getLocalizedPath,
  isSingleFile,
} from "@/lib/i18n";
import {
  buildLocaleContentObjects,
  deserializeLocalizedEntry,
  mergeLocaleContentObjects,
  serializeLocalizedEntry,
  type ValuesByLocale,
} from "@/lib/i18n-entry";

export type LoadedLocalizedEntry = {
  valuesByLocale: ValuesByLocale;
  /** Sha per locale path (single_file shares one sha across locales). */
  shaByLocale: Record<string, string | undefined>;
  /** Locales whose file does not exist yet (untranslated). */
  missingLocales: string[];
};

export type BatchUpdate = { path: string; content?: any; rawText?: string };
export type BatchSaveRequest = {
  name: string;
  message?: string;
  updates: BatchUpdate[];
  deletions?: string[];
  strictPaths?: string[];
};

const apiBase = (config: Config) =>
  `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}`;

const fetchEntry = async (
  config: Config,
  path: string,
  name?: string,
): Promise<{ contentObject?: Record<string, any>; body?: string; sha?: string; missing: boolean }> => {
  const url = `${apiBase(config)}/entries/${encodeURIComponent(path)}${name ? `?name=${encodeURIComponent(name)}` : ""}`;
  const response = await fetch(url);
  if (response.status === 404) return { missing: true };
  const json: any = await response.json();
  if (json?.status !== "success") {
    if (typeof json?.message === "string" && json.message === "Not found") return { missing: true };
    throw new Error(json?.message || "Failed to load entry locale.");
  }
  return {
    contentObject: json.data?.contentObject,
    body: (json.data?.contentObject as any)?.body,
    sha: json.data?.sha,
    missing: false,
  };
};

/** Load every locale of an entry into the editor's per-locale value model. */
export const loadLocalizedEntry = async ({
  config,
  schema,
  canonicalPath,
}: {
  config: Config;
  schema: { name: string; fields?: Field[]; format?: any; delimiters?: any };
  canonicalPath: string;
}): Promise<LoadedLocalizedEntry | null> => {
  const i18n = getI18nConfig(config);
  if (!i18n) return null;
  const fields = schema.fields;

  if (isSingleFile(config)) {
    const raw = await fetchEntry(config, canonicalPath);
    const valuesByLocale = deserializeLocalizedEntry({
      fields,
      filesByLocale: { single: raw.body ?? "" },
      config,
      format: schema.format,
      delimiters: schema.delimiters,
    });
    const shaByLocale: Record<string, string | undefined> = {};
    for (const locale of i18n.locales) shaByLocale[locale] = raw.sha;
    return {
      valuesByLocale,
      shaByLocale,
      missingLocales: raw.missing ? [...i18n.locales] : [],
    };
  }

  const paths = getLocalePaths(canonicalPath, config);
  const objectsByLocale: Record<string, Record<string, any> | undefined> = {};
  const shaByLocale: Record<string, string | undefined> = {};
  const missingLocales: string[] = [];
  await Promise.all(
    i18n.locales.map(async (locale) => {
      const res = await fetchEntry(config, paths[locale], schema.name);
      if (res.missing) {
        missingLocales.push(locale);
        objectsByLocale[locale] = undefined;
      } else {
        objectsByLocale[locale] = res.contentObject ?? {};
        shaByLocale[locale] = res.sha;
      }
    }),
  );
  const valuesByLocale = mergeLocaleContentObjects({ fields, objectsByLocale, config });
  return { valuesByLocale, shaByLocale, missingLocales };
};

/**
 * Build the `/files-batch` body to persist an entry across all locales. A
 * changed `previousCanonicalPath` deletes the old locale files (rename/move).
 */
export const buildI18nSaveRequest = ({
  config,
  schema,
  valuesByLocale,
  canonicalPath,
  previousCanonicalPath,
  message,
}: {
  config: Config;
  schema: { name: string; fields?: Field[]; format?: any; delimiters?: any };
  valuesByLocale: ValuesByLocale;
  canonicalPath: string;
  previousCanonicalPath?: string;
  message?: string;
}): BatchSaveRequest => {
  const i18n = getI18nConfig(config);
  if (!i18n) throw new Error("buildI18nSaveRequest called without i18n config.");
  const fields = schema.fields;

  let updates: BatchUpdate[];
  let strictPaths: string[] | undefined;

  if (i18n.structure === "single_file") {
    const [file] = serializeLocalizedEntry({
      fields,
      valuesByLocale,
      canonicalPath,
      config,
      format: schema.format,
      delimiters: schema.delimiters,
    });
    // Locale-keyed shape can't be field-validated; write verbatim.
    updates = [{ path: file.path, rawText: file.content }];
    strictPaths = [];
  } else {
    const perLocale = buildLocaleContentObjects({ fields, valuesByLocale, config });
    updates = i18n.locales.map((locale) => ({
      path: getLocalizedPath(canonicalPath, locale, config),
      content: perLocale[locale] ?? {},
    }));
    // Only the default-locale file must fully validate; others may be untranslated.
    strictPaths = [getLocalizedPath(canonicalPath, i18n.default_locale, config)];
  }

  const newPaths = new Set(updates.map((u) => u.path));
  let deletions: string[] | undefined;
  if (previousCanonicalPath && previousCanonicalPath !== canonicalPath) {
    const oldPaths = Object.values(getLocalePaths(previousCanonicalPath, config));
    deletions = Array.from(new Set(oldPaths)).filter((p) => !newPaths.has(p));
  }

  return { name: schema.name, message, updates, deletions, strictPaths };
};

/** Delete every locale file of an entry in one commit. */
export const buildI18nDeleteRequest = ({
  config,
  schema,
  canonicalPath,
  message,
}: {
  config: Config;
  schema: { name: string };
  canonicalPath: string;
  message?: string;
}): BatchSaveRequest => {
  const paths = Object.values(getLocalePaths(canonicalPath, config));
  return {
    name: schema.name,
    message,
    updates: [],
    deletions: Array.from(new Set(paths)),
  };
};

/** POST a batch request to the files-batch endpoint. */
export const postBatch = async (config: Config, body: BatchSaveRequest) => {
  const response = await fetch(`${apiBase(config)}/files-batch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json: any = await response.json();
  if (json?.status !== "success") {
    throw new Error(json?.message || "Failed to save entry.");
  }
  return json.data as { commitSha: string; sha: string };
};
