/**
 * Standalone i18n logic tests (no framework). Run with:
 *   npx tsx tests/i18n.test.ts
 *
 * Exits non-zero on first failure.
 */

import type { Config } from "@/types/config";
import type { Field } from "@/types/field";
import {
  getLocalizedPath,
  getLocalePaths,
  getFieldI18nMode,
  isSingleFile,
  getLocaleFromPath,
  getTranslationStatus,
} from "@/lib/i18n";
import {
  serializeLocalizedEntry,
  deserializeLocalizedEntry,
  buildLocaleContentObjects,
  partitionTopLevelModes,
} from "@/lib/i18n-entry";

let passed = 0;
const failures: string[] = [];

const eq = (name: string, actual: unknown, expected: unknown) => {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a === e) {
    passed++;
  } else {
    failures.push(`✗ ${name}\n    expected: ${e}\n    actual:   ${a}`);
  }
};
const ok = (name: string, cond: boolean) => eq(name, cond, true);

const makeConfig = (i18n: any): Config => ({
  owner: "o",
  repo: "r",
  branch: "main",
  sha: "x",
  version: "1",
  object: { i18n },
});

const FIELDS: Field[] = [
  { name: "title", type: "string", i18n: true },
  { name: "body", type: "text", i18n: "translate" },
  { name: "date", type: "date", i18n: "duplicate" },
  { name: "slug", type: "string", i18n: "duplicate" },
  { name: "id", type: "string", i18n: "none" },
  { name: "summary", type: "text" }, // omitted => none
];

// ── getLocalizedPath ─────────────────────────────────────────────
{
  const mf = makeConfig({ structure: "multiple_files", locales: ["en", "nl"], default_locale: "en" });
  eq("multiple_files default = bare path", getLocalizedPath("content/posts/hello.md", "en", mf), "content/posts/hello.md");
  eq("multiple_files nl infix", getLocalizedPath("content/posts/hello.md", "nl", mf), "content/posts/hello.nl.md");

  const fo = makeConfig({ structure: "multiple_folders", locales: ["en", "nl"], default_locale: "en" });
  eq("multiple_folders default = bare path", getLocalizedPath("content/posts/hello.md", "en", fo), "content/posts/hello.md");
  eq("multiple_folders nl dir", getLocalizedPath("content/posts/hello.md", "nl", fo), "content/posts/nl/hello.md");

  const sf = makeConfig({ structure: "single_file", locales: ["en", "nl"], default_locale: "en" });
  eq("single_file same path for nl", getLocalizedPath("content/posts/hello.md", "nl", sf), "content/posts/hello.md");
  ok("isSingleFile true", isSingleFile(sf));
  ok("isSingleFile false", !isSingleFile(mf));

  eq("getLocalePaths multiple_files", getLocalePaths("content/posts/hello.md", mf), {
    en: "content/posts/hello.md",
    nl: "content/posts/hello.nl.md",
  });
  eq("getLocalePaths single_file", getLocalePaths("content/posts/hello.md", sf), {
    en: "content/posts/hello.md",
    nl: "content/posts/hello.md",
  });
  eq("getLocalePaths no-i18n", getLocalePaths("x.md", makeConfig(null)), {});
}

// ── getLocaleFromPath + getTranslationStatus ─────────────────────
{
  const mf = makeConfig({ structure: "multiple_files", locales: ["en", "nl", "de"], default_locale: "en" });
  eq("locale from nl infix", getLocaleFromPath("content/posts/hello.nl.md", mf), "nl");
  eq("locale from de infix", getLocaleFromPath("content/posts/hello.de.md", mf), "de");
  eq("canonical (default) path => null", getLocaleFromPath("content/posts/hello.md", mf), null);

  const fo = makeConfig({ structure: "multiple_folders", locales: ["en", "nl"], default_locale: "en" });
  eq("locale from folder", getLocaleFromPath("content/posts/nl/hello.md", fo), "nl");
  eq("default folder path => null", getLocaleFromPath("content/posts/hello.md", fo), null);

  const present = ["content/posts/hello.md", "content/posts/hello.nl.md"];
  eq("translation status multiple_files", getTranslationStatus("content/posts/hello.md", present, mf), {
    en: true, nl: true, de: false,
  });
}

// ── getFieldI18nMode normalization ───────────────────────────────
{
  eq("true => translate", getFieldI18nMode({ i18n: true }, true), "translate");
  eq("'translate' => translate", getFieldI18nMode({ i18n: "translate" }, true), "translate");
  eq("'duplicate' => duplicate", getFieldI18nMode({ i18n: "duplicate" }, true), "duplicate");
  eq("'none' => none", getFieldI18nMode({ i18n: "none" }, true), "none");
  eq("false => none", getFieldI18nMode({ i18n: false }, true), "none");
  eq("omitted => none", getFieldI18nMode({}, true), "none");
  eq("collection off => none even if translate", getFieldI18nMode({ i18n: true }, false), "none");

  const part = partitionTopLevelModes(FIELDS, true);
  eq("partition translate", [...part.translate].sort(), ["body", "title"]);
  eq("partition duplicate", [...part.duplicate].sort(), ["date", "slug"]);
  eq("partition none", [...part.none].sort(), ["id", "summary"]);
}

// ── buildLocaleContentObjects (multiple_*) ───────────────────────
{
  const cfg = makeConfig({ structure: "multiple_files", locales: ["en", "nl"], default_locale: "en" });
  const values = {
    en: { title: "Hello", body: "Hi", date: "2026-01-01", slug: "hello", id: "uuid-1", summary: "S" },
    nl: { title: "Hallo", body: "Hoi" },
  };
  const built = buildLocaleContentObjects({ fields: FIELDS, valuesByLocale: values, config: cfg });
  eq("en keeps everything", built.en, {
    title: "Hello", body: "Hi", date: "2026-01-01", slug: "hello", id: "uuid-1", summary: "S",
  });
  eq("nl: translate own, duplicate from default, none dropped", built.nl, {
    title: "Hallo", body: "Hoi", date: "2026-01-01", slug: "hello",
  });
  ok("nl has no id (none)", built.nl.id === undefined);
  ok("nl has no summary (none)", built.nl.summary === undefined);
}

// ── serialize/deserialize round-trip: multiple_files ─────────────
{
  const cfg = makeConfig({ structure: "multiple_files", locales: ["en", "nl"], default_locale: "en" });
  const values = {
    en: { title: "Hello", body: "Body EN", date: "2026-01-01", slug: "hello", id: "uuid-1", summary: "only-default" },
    nl: { title: "Hallo", body: "Body NL" },
  };
  const files = serializeLocalizedEntry({ fields: FIELDS, valuesByLocale: values, canonicalPath: "content/posts/hello.md", config: cfg });
  eq("multiple_files produces 2 files", files.length, 2);
  eq("en path bare", files.find((f) => f.locale === "en")!.path, "content/posts/hello.md");
  eq("nl path infix", files.find((f) => f.locale === "nl")!.path, "content/posts/hello.nl.md");

  const filesByLocale = Object.fromEntries(files.map((f) => [f.locale as string, f.content]));
  const round = deserializeLocalizedEntry({ fields: FIELDS, filesByLocale, config: cfg });
  eq("round-trip en title", round.en.title, "Hello");
  eq("round-trip nl title (translate differs)", round.nl.title, "Hallo");
  eq("round-trip nl slug (duplicate from default)", round.nl.slug, "hello");
  eq("round-trip nl date (duplicate)", round.nl.date, "2026-01-01");
  eq("round-trip nl id hydrated from default for display", round.nl.id, "uuid-1");
}

// ── serialize/deserialize round-trip: single_file ────────────────
{
  const cfg = makeConfig({ structure: "single_file", locales: ["en", "nl"], default_locale: "en" });
  const values = {
    en: { title: "Hello", body: "Body EN", date: "2026-01-01", slug: "hello", id: "uuid-1" },
    nl: { title: "Hallo", body: "Body NL" },
  };
  const files = serializeLocalizedEntry({ fields: FIELDS, valuesByLocale: values, canonicalPath: "content/posts/hello.md", config: cfg });
  eq("single_file produces 1 file", files.length, 1);
  eq("single_file path", files[0].path, "content/posts/hello.md");

  const merged = deserializeLocalizedEntry({
    fields: FIELDS,
    filesByLocale: { any: files[0].content },
    config: cfg,
  });
  eq("single_file en title", merged.en.title, "Hello");
  eq("single_file nl title", merged.nl.title, "Hallo");
  eq("single_file nl body", merged.nl.body, "Body NL");
  eq("single_file shared slug on en", merged.en.slug, "hello");
  eq("single_file shared slug on nl (from root)", merged.nl.slug, "hello");
  eq("single_file shared date on nl", merged.nl.date, "2026-01-01");
  eq("single_file none id shared on nl", merged.nl.id, "uuid-1");
}

// ── single_file on-disk shape: shared keys at root, locale blocks ─
{
  const cfg = makeConfig({ structure: "single_file", locales: ["en", "nl"], default_locale: "en" });
  const values = {
    en: { title: "Hello", date: "2026-01-01", slug: "hello", id: "uuid-1" },
    nl: { title: "Hallo" },
  };
  const files = serializeLocalizedEntry({
    fields: FIELDS, valuesByLocale: values, canonicalPath: "x.json", config: cfg, format: "json",
  });
  const onDisk = JSON.parse(files[0].content);
  eq("root has shared slug", onDisk.slug, "hello");
  eq("root has shared date", onDisk.date, "2026-01-01");
  eq("root has shared id (none)", onDisk.id, "uuid-1");
  eq("en block holds translate title", onDisk.en.title, "Hello");
  eq("nl block holds translate title", onDisk.nl.title, "Hallo");
  ok("en block has no slug (shared lives at root)", onDisk.en.slug === undefined);
}

// ── regression: no i18n block ⇒ single unchanged file ────────────
{
  const cfg = makeConfig(null);
  const values = { default: { title: "Plain", body: "B" } };
  const files = serializeLocalizedEntry({ fields: FIELDS, valuesByLocale: values, canonicalPath: "p.md", config: cfg });
  eq("no-i18n: 1 file", files.length, 1);
  eq("no-i18n: bare path", files[0].path, "p.md");
  const back = deserializeLocalizedEntry({ fields: FIELDS, filesByLocale: { default: files[0].content }, config: cfg });
  eq("no-i18n: round-trips title", back.default.title, "Plain");
}

// ── report ───────────────────────────────────────────────────────
if (failures.length) {
  console.error(`\n${failures.length} FAILED, ${passed} passed\n`);
  console.error(failures.join("\n\n"));
  process.exit(1);
} else {
  console.log(`\n✓ all ${passed} i18n assertions passed\n`);
}
