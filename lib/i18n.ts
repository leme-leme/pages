import { Config } from "@/types/config";

export interface I18nConfig {
  structure: "multiple_files" | "multiple_folders" | "single_file";
  locales: string[];
  default_locale: string;
}

export const getI18nConfig = (config: Config): I18nConfig | null => {
  return config.object.i18n || null;
};

export const getCollectionI18n = (collection: any, config: Config): boolean => {
  if (!collection) return false;
  if (collection.i18n === true) return true;
  if (collection.i18n === false) return false;
  // If collection.i18n is undefined, fall back to global config
  return !!config.object.i18n;
};

export const getLocalizedPath = (
  originalPath: string,
  locale: string,
  config: Config,
  collection: any
): string => {
  const i18nConfig = getI18nConfig(config);
  if (!i18nConfig || locale === i18nConfig.default_locale) {
    return originalPath;
  }

  const structure = i18nConfig.structure;
  const pathParts = originalPath.split("/");
  const filename = pathParts.pop() || "";
  const extension = filename.split(".").pop() || "";
  const nameWithoutExtension = filename.replace(`.${extension}`, "");
  const dir = pathParts.join("/");

  switch (structure) {
    case "multiple_files":
      // e.g. content/posts/hello.fr.md
      return `${dir ? dir + "/" : ""}${nameWithoutExtension}.${locale}.${extension}`;
    case "multiple_folders":
      // e.g. content/fr/posts/hello.md
      // This is tricky because we need to know where the "content root" is.
      // Assuming simple replacement or prefix for now based on common patterns.
      // If original is `content/posts/hello.md`, and we want `content/fr/posts/hello.md`?
      // Or `fr/content/posts/hello.md`?
      // Netlify CMS usually does `content/posts/fr/hello.md` or similar depending on config.
      // Sveltia/Decap logic:
      // if `path` is `content/posts/{{slug}}.md`
      // multiple_folders usually implies `content/posts/{{locale}}/{{slug}}.md` or `{{locale}}/content/posts/{{slug}}.md`
      // For now, let's assume a simple prefix at the collection folder level if possible,
      // or just prepend the locale to the filename's parent directory if it's a file path.
      
      // Let's implement a safe default: `locale/path` relative to the collection folder? 
      // Actually, standard practice for "multiple_folders" often involves configuring the collection path with {{locale}}.
      // If the user hasn't configured {{locale}} in the path, we might need a convention.
      // Let's stick to: `content/posts/{{locale}}/filename.md` if the collection path doesn't have it.
      
      // However, a robust implementation requires parsing the collection's defined path pattern.
      // Since we don't have the full path pattern parser here yet, let's assume:
      // content/posts/hello.md -> content/posts/{locale}/hello.md
      return `${dir ? dir + "/" : ""}${locale}/${filename}`;
      
    case "single_file":
      // The file path is the same, content is inside.
      return originalPath;
    default:
      return originalPath;
  }
};
