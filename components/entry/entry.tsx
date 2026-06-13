"use client";

import { Fragment, useEffect, useState, useMemo, useCallback, useRef } from "react";
import type { ReactNode } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useConfig } from "@/contexts/config-context";
import { parseAndValidateConfig } from "@/lib/config";
import { resolveContentOperations } from "@/lib/operations";
import { requireApiSuccess } from "@/lib/api-client";
import { getSchemaActions } from "@/lib/actions";
import {
  generateFilename,
  getPrimaryField,
  getSchemaByName,
  safeAccess,
} from "@/lib/schema";
import {
  getFileExtension,
  getFileName,
  getParentPath,
  getRelativePath,
  joinPathSegments,
  normalizePath
} from "@/lib/utils/file";
import type { ApiSuccess, EntryData, EntryHistoryItem } from "@/types/api";
import { EntryForm } from "./entry-form";
import { EntryHistoryDropdown } from "./entry-history";
import { EmptyCreate } from "@/components/empty-create";
import { FileOptions } from "@/components/file/file-options";
import { RepoActionButtons } from "@/components/repo/repo-action-buttons";
import { Button } from "@/components/ui/button";
import { ButtonGroup } from "@/components/ui/button-group";
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from "@/components/ui/input-group";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyTitle,
} from "@/components/ui/empty";
import { useRepoHeader } from "@/components/repo/repo-header-context";
import { LocaleProvider } from "@/contexts/locale-context";
import { LocaleSwitcher } from "@/components/locale-switcher";
import { getCollectionI18n, getI18nConfig, getLocalizedPath } from "@/lib/i18n";
import {
  loadLocalizedEntry,
  buildI18nSaveRequest,
  buildI18nDeleteRequest,
  postBatch,
  type LoadedLocalizedEntry,
} from "@/lib/i18n-save";
import type { ValuesByLocale } from "@/lib/i18n-entry";
import {
  Breadcrumb,
  BreadcrumbEllipsis,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton"
import { toast } from "sonner";
import { EllipsisVertical, History, Lock, LockOpen, Save } from "lucide-react";
import useSWR, { useSWRConfig } from "swr";

type LintView = {
  state: {
    doc: {
      toString(): string;
    };
  };
};

type GroupTrailItem = {
  name: string;
  label?: string | null;
};

export function Entry({
  name = "",
  path: initialPath,
  parent,
  title,
  headerMeta,
  onSave,
}: {
  name?: string;
  path?: string;
  parent?: string;
  title?: string;
  headerMeta?: ReactNode;
  onSave?: (data: Record<string, unknown>) => void;
}) {
  const [path, setPath] = useState<string | undefined>(initialPath);
  const [entry, setEntry] = useState<EntryData | null>();
  const [sha, setSha] = useState<string | undefined>();
  const [displayTitle, setDisplayTitle] = useState<string>(() => {
    if (title) return title;
    if (initialPath && initialPath !== ".pages.yml") {
      return `Editing "${getFileName(normalizePath(initialPath))}"`;
    }
    return "Edit";
  });
  const [isLoading, setIsLoading] = useState(path ? true : false);
  const [isSaving, setIsSaving] = useState(false);
  const [isFormDirty, setIsFormDirty] = useState(false);
  const [hasRegisteredChanges, setHasRegisteredChanges] = useState(false);
  const [error, setError] = useState<string | undefined | null>(null);
  const changeVersionRef = useRef(0);
  const { mutate } = useSWRConfig();

  const router = useRouter();
  
  const { config } = useConfig();
  if (!config) throw new Error(`Configuration not found.`);
  
  const schema = useMemo(() => {
    if (!name) return;
    return getSchemaByName(config?.object, name)
  }, [config, name]);
  const schemaType = schema?.type;

  const i18nConfig = useMemo(() => getI18nConfig(config), [config]);
  const i18nEnabled = schema ? getCollectionI18n(schema, config) : false;
  // Structure-mode locales (root `i18n:` block): one file per locale; drives the
  // localized load/save below.
  const localeList = i18nEnabled && i18nConfig?.locales?.length ? i18nConfig.locales : null;
  // Inline-mode locales: an entry's own `locales` with inline i18n fields stored
  // in one file. Drives only the switcher — no per-locale paths, no batch save.
  const inlineLocaleList = useMemo(() => {
    if (localeList) return null;
    const entryLocales = (schema as any)?.locales;
    return Array.isArray(entryLocales) && entryLocales.length > 1
      ? (entryLocales as string[])
      : null;
  }, [localeList, schema]);
  const switcherLocaleList = localeList ?? inlineLocaleList;
  const defaultLocale = i18nConfig?.default_locale ?? switcherLocaleList?.[0] ?? "";
  const [activeLocale, setActiveLocale] = useState<string>(defaultLocale);
  const effectivePath = useMemo(() => {
    if (!path || !localeList || activeLocale === defaultLocale) return path;
    return getLocalizedPath(path, activeLocale, config);
  }, [activeLocale, config, defaultLocale, localeList, path]);

  // i18n entries load/save every locale via the batch endpoint, not the
  // single-file path used for non-i18n content.
  const i18nActive = useMemo(
    () => !!localeList && schemaType === "collection" && path !== ".pages.yml" && initialPath !== ".pages.yml",
    [initialPath, localeList, path, schemaType],
  );
  const [valuesByLocale, setValuesByLocale] = useState<ValuesByLocale | null>(null);
  const shaByLocaleRef = useRef<Record<string, string | undefined>>({});
  const operations = useMemo(
    () =>
      resolveContentOperations({
        schema,
        scope:
          path === ".pages.yml" || initialPath === ".pages.yml"
            ? "settings"
            : undefined,
      }),
    [initialPath, path, schema],
  );
  const canCreate = operations.create;
  const canRename = operations.rename;
  const canDelete = operations.delete;
  const isFileEditorMode = !schema?.fields || schema.fields.length === 0;
  const filenameFieldMode = useMemo(() => {
    if (!schema || schema.type !== "collection") return "hidden";
    if (schema.filenameField === true) return "enabled";
    if (schema.filenameField === "create") return "create";
    if (schema.filenameField === false) return "hidden";
    return isFileEditorMode ? "enabled" : "hidden";
  }, [isFileEditorMode, schema]);
  const showFilenameField = useMemo(() => {
    if (schemaType !== "collection") return false;
    if (filenameFieldMode === "enabled") return true;
    if (filenameFieldMode === "create") return !path;
    return false;
  }, [filenameFieldMode, path, schemaType]);
  const [filenameValue, setFilenameValue] = useState("");
  const [isFilenameUnlocked, setIsFilenameUnlocked] = useState(false);
  
  const entryFields = useMemo(() => {
    return !schema?.fields || schema.fields.length === 0
      ? [{
          name: "body",
          type: "code",
          label: showFilenameField ? "Content" : false,
          options: {
            format: schema?.extension || (entry?.name && getFileExtension(entry.name)) || "markdown",
            lintFn: path === ".pages.yml"
              ? (view: LintView) => {
                  const {parseErrors, validationErrors} = parseAndValidateConfig(view.state.doc.toString());
                  return [...parseErrors, ...validationErrors];
                }
              : undefined
          }
        }]
      : schema?.list === true
        ? [{
            name: "listWrapper",
            label: false,
            type: "object",
            list: true,
            fields: schema.fields
          }]
        : schema.fields;
  }, [schema, entry, path, showFilenameField]);

  const loadedContentObject = i18nActive
    ? valuesByLocale?.[activeLocale]
    : entry?.contentObject;
  const entryContentObject = useMemo(() => {
    return path
      ? schema?.list === true
        ? { listWrapper: loadedContentObject }
        : loadedContentObject
      : schema?.list === true
        ? { listWrapper: [] }
        : {};
  }, [schema, loadedContentObject, path]);

  useEffect(() => {
    if (!showFilenameField || schemaType !== "collection" || !schema) return;

    if (path) {
      setFilenameValue(getFileName(normalizePath(path)));
      setIsFilenameUnlocked(false);
      return;
    }

    const generated = generateFilename(schema.filename, schema, entryContentObject as Record<string, unknown>);
    setFilenameValue(generated || "untitled");
    setIsFilenameUnlocked(true);
  }, [entryContentObject, path, schema, schemaType, showFilenameField]);

  const entryApiUrl = useMemo(() => (
    effectivePath && !i18nActive
      ? `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/entries/${encodeURIComponent(effectivePath)}?name=${encodeURIComponent(name)}`
      : null
  ), [config.branch, config.owner, config.repo, name, effectivePath, i18nActive]);

  const fetchEntryByUrl = useCallback(async (apiUrl: string): Promise<EntryData> => {
    const response = await fetch(apiUrl);
    const data = await requireApiSuccess<any>(
      response,
      "Failed to fetch entry",
    );
    return data.data as EntryData;
  }, []);

  const {
    data: swrEntryData,
    error: swrEntryError,
    isLoading: swrEntryLoading,
    mutate: mutateEntry,
  } = useSWR<EntryData>(
    entryApiUrl,
    fetchEntryByUrl,
    {
      revalidateOnFocus: true,
      revalidateOnReconnect: true,
      dedupingInterval: 2000,
    },
  );

  useEffect(() => {
    if (!path || i18nActive) return;
    setIsLoading(swrEntryLoading);
  }, [path, swrEntryLoading, i18nActive]);

  // Localized load: fetch every locale of the entry into valuesByLocale.
  const i18nLoadKey = i18nActive && path
    ? (["i18n-entry", config.owner, config.repo, config.branch, name, path, (localeList ?? []).join(",")] as const)
    : null;
  const loadI18n = useCallback(async (): Promise<LoadedLocalizedEntry | null> => {
    if (!path || !schema) return null;
    return loadLocalizedEntry({
      config,
      schema: {
        name,
        fields: schema.fields,
        format: (schema as any).format,
        delimiters: (schema as any).delimiters,
      },
      canonicalPath: path,
    });
  }, [config, name, path, schema]);
  const {
    data: i18nData,
    error: i18nError,
    isLoading: i18nLoading,
  } = useSWR<LoadedLocalizedEntry | null>(i18nLoadKey, loadI18n, {
    revalidateOnFocus: false,
    dedupingInterval: 2000,
  });

  useEffect(() => {
    if (!i18nActive) return;
    setIsLoading(i18nLoading);
  }, [i18nActive, i18nLoading]);

  useEffect(() => {
    if (!i18nActive || !i18nData || !path) return;
    setValuesByLocale(i18nData.valuesByLocale);
    shaByLocaleRef.current = i18nData.shaByLocale;
    setHasRegisteredChanges(false);
    setIsLoading(false);
    setError(null);
    const def = i18nData.valuesByLocale[defaultLocale] ?? {};
    setEntry({
      sha: i18nData.shaByLocale[defaultLocale] ?? "",
      name: getFileName(normalizePath(path)),
      path,
      contentObject: def,
    });
    if (schema && schema.type === "collection") {
      const primaryField = getPrimaryField(schema);
      const primaryValue = primaryField ? safeAccess(def, primaryField) : undefined;
      const hasPrimary = typeof primaryValue === "string" ? primaryValue !== "" : primaryValue != null;
      setDisplayTitle(`Editing "${hasPrimary ? String(primaryValue) : getFileName(normalizePath(path))}"`);
    }
  }, [i18nActive, i18nData, defaultLocale, path, schema]);

  useEffect(() => {
    if (!i18nActive || !valuesByLocale) return;
    setSha(shaByLocaleRef.current[activeLocale] ?? shaByLocaleRef.current[defaultLocale]);
  }, [activeLocale, defaultLocale, i18nActive, valuesByLocale]);

  useEffect(() => {
    if (!i18nActive || !i18nError) return;
    setError(i18nError instanceof Error ? i18nError.message : "Failed to fetch entry.");
    setIsLoading(false);
  }, [i18nActive, i18nError]);

  useEffect(() => {
    if (!swrEntryData || !path) return;
    setEntry(swrEntryData);
    setSha(swrEntryData.sha);
    setHasRegisteredChanges(false);
    setIsLoading(false);
    setError(null);

    if (initialPath && schema && schema.type === "collection") {
      const primaryField = getPrimaryField(schema);
      const primaryValue = primaryField
        ? safeAccess(swrEntryData.contentObject ?? {}, primaryField)
        : undefined;
      const hasPrimaryValue = typeof primaryValue === "string"
        ? primaryValue !== ""
        : primaryValue != null;
      const titleValue = hasPrimaryValue
        ? String(primaryValue)
        : getFileName(normalizePath(path));
      setDisplayTitle(`Editing "${titleValue}"`);
    } else if (!title && path && path !== ".pages.yml") {
      setDisplayTitle(`Editing "${getFileName(normalizePath(path))}"`);
    }
  }, [initialPath, path, schema, swrEntryData, title]);

  useEffect(() => {
    if (!swrEntryError) return;
    const message = swrEntryError instanceof Error ? swrEntryError.message : "Failed to fetch entry.";
    setError(message);
    setIsLoading(false);
  }, [swrEntryError]);

  const historyApiUrl = useMemo(() => (
    path
      ? `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/entries/${encodeURIComponent(path)}/history?name=${encodeURIComponent(name)}`
      : null
  ), [config.branch, config.owner, config.repo, name, path]);

  const historyKey = useMemo(
    () => historyApiUrl ? [historyApiUrl, sha ?? ""] as const : null,
    [historyApiUrl, sha],
  );

  const fetchEntryHistory = useCallback(async ([apiUrl]: readonly [string, string]): Promise<EntryHistoryItem[]> => {
    const response = await fetch(apiUrl);
    const data = await requireApiSuccess<any>(
      response,
      "Failed to fetch entry's history",
    );
    return data.data as EntryHistoryItem[];
  }, []);

  const { data: historyData } = useSWR<EntryHistoryItem[]>(
    historyKey,
    fetchEntryHistory,
    {
      revalidateOnFocus: true,
      revalidateOnReconnect: true,
      dedupingInterval: 2000,
    },
  );

  const currentFilename = useMemo(
    () => path ? getFileName(normalizePath(path)) : "",
    [path],
  );
  const filenameChanged = showFilenameField
    && filenameValue.trim().length > 0
    && filenameValue.trim() !== currentFilename;

  const onSubmit = async (contentObject: Record<string, unknown>) => {
    setIsSaving(true);
    const submitStartChangeVersion = changeVersionRef.current;

    const savePromise = new Promise<ApiSuccess<EntryData>>(async (resolve, reject) => {
      try {
        if (i18nActive) {
          const formObject = (schema?.list === true
            ? (contentObject as any).listWrapper
            : contentObject) as Record<string, any>;
          const trimmedFilename = filenameValue.trim();
          const normalizedFilename = normalizePath(trimmedFilename).split("/").pop() || "";
          if (showFilenameField && !normalizedFilename) throw new Error("Filename is required.");

          let targetCanonical = path;
          let previousCanonical: string | undefined;
          if (!targetCanonical) {
            if (!schema) throw new Error("Cannot create entry without schema.");
            if (!canCreate) throw new Error("Creating entries in this content item isn't allowed.");
            const basePath = parent ?? schema.path;
            if (basePath == null) throw new Error("Cannot create entry without a target path.");
            const generatedFilename = showFilenameField
              ? normalizedFilename
              : generateFilename(schema.filename, schema, formObject);
            targetCanonical = joinPathSegments([basePath, generatedFilename]);
          } else if (filenameChanged) {
            if (activeLocale !== defaultLocale) throw new Error("Switch to the default locale to rename this entry.");
            if (!canRename) throw new Error("Renaming this entry isn't allowed.");
            previousCanonical = path;
            targetCanonical = joinPathSegments([getParentPath(path), normalizedFilename]);
          }

          const mergedValues: ValuesByLocale = { ...(valuesByLocale ?? {}), [activeLocale]: formObject };
          if (!mergedValues[defaultLocale]) mergedValues[defaultLocale] = mergedValues[activeLocale];

          const result = await postBatch(
            config,
            buildI18nSaveRequest({
              config,
              schema: {
                name,
                fields: schema?.fields,
                format: (schema as any)?.format,
                delimiters: (schema as any)?.delimiters,
              },
              valuesByLocale: mergedValues,
              canonicalPath: targetCanonical!,
              previousCanonicalPath: previousCanonical,
            }),
          );

          setValuesByLocale(mergedValues);
          if (result.sha) setSha(result.sha);
          if (submitStartChangeVersion === changeVersionRef.current) setHasRegisteredChanges(false);

          const collectionKeyPrefix = `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collections/${encodeURIComponent(name)}?`;
          void mutate((key) => typeof key === "string" && key.startsWith(collectionKeyPrefix));

          if (!path) {
            setPath(targetCanonical!);
            router.push(`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}/edit/${encodeURIComponent(targetCanonical!)}`);
          } else if (previousCanonical) {
            setPath(targetCanonical!);
            setIsFilenameUnlocked(false);
            router.replace(`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}/edit/${encodeURIComponent(targetCanonical!)}`);
          }

          resolve({
            status: "success",
            message: "File saved successfully.",
            data: {
              sha: result.sha,
              path: targetCanonical!,
              name: getFileName(normalizePath(targetCanonical!)),
              contentObject: formObject,
            },
          } as ApiSuccess<EntryData>);
          return;
        }

        let savePath = effectivePath ?? path;
        const trimmedFilename = filenameValue.trim();
        const normalizedFilename = normalizePath(trimmedFilename).split("/").pop() || "";

        if (showFilenameField && !normalizedFilename) {
          throw new Error("Filename is required.");
        }

        if (!savePath) {
          if (!schema) throw new Error("Cannot create entry without schema.");
          if (!canCreate) throw new Error("Creating entries in this content item isn't allowed.");
          const basePath = parent ?? schema.path;
          if (basePath == null) throw new Error("Cannot create entry without a target path.");
          const generatedFilename = showFilenameField
            ? normalizedFilename
            : generateFilename(schema.filename, schema, contentObject);
          const defaultPath = joinPathSegments([basePath, generatedFilename]);
          savePath = localeList && activeLocale !== defaultLocale
            ? getLocalizedPath(defaultPath, activeLocale, config)
            : defaultPath;
        } else if (filenameChanged && !canRename && schemaType === "collection") {
          throw new Error("Renaming this entry isn't allowed.");
        } else if (filenameChanged && localeList && activeLocale !== defaultLocale) {
          throw new Error("Switch to the default locale to rename this entry.");
        } else if (
          showFilenameField
          && filenameFieldMode === "enabled"
          && isFilenameUnlocked
          && filenameChanged
          && schemaType === "collection"
        ) {
          const newPath = joinPathSegments([getParentPath(savePath), normalizedFilename]);
          const renameResponse = await fetch(
            `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/files/${encodeURIComponent(savePath)}/rename`,
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                type: "content",
                name,
                newPath,
              }),
            },
          );
          await requireApiSuccess<any>(renameResponse, "Failed to rename file");
          savePath = newPath;
          setPath(newPath);
          setIsFilenameUnlocked(false);
          router.replace(`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}/edit/${encodeURIComponent(newPath)}`);

          const collectionKeyPrefix = `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collections/${encodeURIComponent(name)}?`;
          void mutate((key) => typeof key === "string" && key.startsWith(collectionKeyPrefix));
        }

        const response = await fetch(`/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/files/${encodeURIComponent(savePath)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            type: path === ".pages.yml" ? "settings" : "content",
            name,
            content: schema?.list === true
              ? contentObject.listWrapper
              : contentObject,
            sha: sha
          }),
        });
        const data = await requireApiSuccess<any>(
          response,
          "Failed to save file",
        );
        
        if (data.data.sha !== sha) setSha(data.data.sha);
        if (submitStartChangeVersion === changeVersionRef.current) {
          setHasRegisteredChanges(false);
        }

        if (!path && schemaType === "collection") router.push(`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}/edit/${encodeURIComponent(data.data.path)}`);
        if (schemaType === "collection") {
          const collectionKeyPrefix = `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collections/${encodeURIComponent(name)}?`;
          void mutate((key) => typeof key === "string" && key.startsWith(collectionKeyPrefix));
        }

        resolve(data);
      } catch (error) {
        reject(error);
      }
    });

    toast.promise(savePromise, {
      loading: "Saving your file",
      success: (response: ApiSuccess<EntryData>) => {
        if (onSave) onSave(response.data);
        return response.message;
      },
      error: (error: unknown) => error instanceof Error ? error.message : "Failed to save file.",
    });

    try {
      await savePromise;
      if (submitStartChangeVersion === changeVersionRef.current) {
        setHasRegisteredChanges(false);
      }
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error(error.message);
      } else {
        console.error(error);
      }
    } finally {
      setIsSaving(false);
    }
  };

  const isBusy = isLoading || isSaving;

  useEffect(() => {
    const handleSaveShortcut = (event: KeyboardEvent) => {
      if (event.key.toLowerCase() !== "s") return;
      if (!event.metaKey && !event.ctrlKey) return;
      if (event.altKey) return;

      event.preventDefault();
      if (isBusy) return;

      const form = document.getElementById("entry-form");
      if (form instanceof HTMLFormElement) {
        form.requestSubmit();
      }
    };

    window.addEventListener("keydown", handleSaveShortcut);
    return () => window.removeEventListener("keydown", handleSaveShortcut);
  }, [isBusy]);

  const i18nDeleteOverride = useCallback(async () => {
    if (!path) return { message: "" };
    await postBatch(
      config,
      buildI18nDeleteRequest({ config, schema: { name }, canonicalPath: path }),
    );
    return { message: "Entry deleted across all locales." };
  }, [config, name, path]);

  const handleDelete = useCallback((path: string) => {
    // TODO: disable save button or freeze form while deleting?
    if (schemaType === "collection") {
      const collectionKeyPrefix = `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collections/${encodeURIComponent(name)}?`;
      void mutate((key) => typeof key === "string" && key.startsWith(collectionKeyPrefix));
    }
    if (schemaType === "collection") {
      router.push(`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}`);
    } else {
      if (entryApiUrl) {
        void mutate(entryApiUrl, undefined, { revalidate: true });
      }
      void mutateEntry();
    }
  }, [config.branch, config.owner, config.repo, entryApiUrl, mutate, mutateEntry, name, router, schemaType]);

  const handleRename = useCallback((oldPath: string, newPath: string) => {
    if (schemaType === "collection") {
      const collectionKeyPrefix = `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collections/${encodeURIComponent(name)}?`;
      void mutate((key) => typeof key === "string" && key.startsWith(collectionKeyPrefix));
    }
    if (entryApiUrl) {
      void mutate(entryApiUrl, undefined, { revalidate: false });
    }
    setPath(newPath);
    router.replace(`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}/edit/${encodeURIComponent(newPath)}`);
  }, [config.branch, config.owner, config.repo, entryApiUrl, mutate, name, router, schemaType]);

  const breadcrumbNode = useMemo(() => {
    if (!schema) {
      return <BreadcrumbPage className="font-semibold truncate">{displayTitle}</BreadcrumbPage>;
    }

    const groupTrail: GroupTrailItem[] = Array.isArray(schema.groupTrail)
      ? schema.groupTrail
      : [];

    if (schemaType !== "collection") {
      return (
        <>
          {groupTrail.map((group) => (
            <Fragment key={`group-${group.name}`}>
              <BreadcrumbItem>
                <span>{group.label || group.name}</span>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
            </Fragment>
          ))}
          <BreadcrumbItem className="truncate">
            <BreadcrumbPage className="font-semibold truncate">{displayTitle}</BreadcrumbPage>
          </BreadcrumbItem>
        </>
      );
    }

    const rootLabel = schema.label || schema.name || name;

    if (!path) {
      return (
        <>
          {groupTrail.map((group) => (
            <Fragment key={`group-${group.name}`}>
              <BreadcrumbItem>
                <span>{group.label || group.name}</span>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
            </Fragment>
          ))}
          <BreadcrumbItem>
            <BreadcrumbLink asChild>
              <Link href={`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}`}>
                {rootLabel}
              </Link>
            </BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem className="truncate">
            <BreadcrumbPage className="font-semibold truncate">{displayTitle}</BreadcrumbPage>
          </BreadcrumbItem>
        </>
      );
    }

    const rootPath = normalizePath(schema.path);
    const parentPath = normalizePath(getParentPath(path));
    const relativePath = getRelativePath(parentPath, rootPath);
    const segments = relativePath ? relativePath.split("/").filter(Boolean) : [];

    const parentEntries = segments.map((segment, index) => ({
      name: segment,
      path: joinPathSegments([rootPath, segments.slice(0, index + 1).join("/")]),
    }));

    const immediateParent = parentEntries.length > 0 ? parentEntries[parentEntries.length - 1] : null;
    const middleEntries = parentEntries.length > 1 ? parentEntries.slice(0, -1) : [];

    return (
      <>
        {groupTrail.map((group) => (
          <Fragment key={`group-${group.name}`}>
            <BreadcrumbItem>
              <span>{group.label || group.name}</span>
            </BreadcrumbItem>
            <BreadcrumbSeparator />
          </Fragment>
        ))}
        <BreadcrumbItem>
          <BreadcrumbLink asChild>
            <Link href={`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}`}>
              {rootLabel}
            </Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />

        {middleEntries.length > 0 && (
          <>
            <BreadcrumbItem>
              <DropdownMenu>
                <DropdownMenuTrigger className="flex items-center">
                  <BreadcrumbEllipsis className="h-4 w-4" />
                  <span className="sr-only">Show hidden segments</span>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start">
                  {middleEntries.map((entry) => (
                    <DropdownMenuItem key={entry.path} asChild>
                      <Link href={`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}?path=${encodeURIComponent(entry.path)}`}>
                        {entry.name}
                      </Link>
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
            </BreadcrumbItem>
            <BreadcrumbSeparator />
          </>
        )}

        {immediateParent && (
          <>
            <BreadcrumbItem>
              <BreadcrumbLink asChild>
                <Link href={`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}?path=${encodeURIComponent(immediateParent.path)}`}>
                  {immediateParent.name}
                </Link>
              </BreadcrumbLink>
            </BreadcrumbItem>
            <BreadcrumbSeparator />
          </>
        )}

        <BreadcrumbItem className="truncate">
          <BreadcrumbPage className="font-semibold truncate">{displayTitle}</BreadcrumbPage>
        </BreadcrumbItem>
      </>
    );
  }, [config.branch, config.owner, config.repo, displayTitle, name, path, schema, schemaType]);
  const isCreationBlocked = !path && schemaType === "collection" && !canCreate;
  const showHeaderActions = error !== "Not found" && !isCreationBlocked;
  const headerActionsNode = useMemo(() => {
    if (!schema || !path) return null;

    if (schemaType === "file") {
      const fileActions = getSchemaActions(schema);
      if (fileActions.length === 0) return null;

      return (
        <RepoActionButtons
          actions={fileActions}
          owner={config.owner}
          repo={config.repo}
          refName={config.branch}
          contextType="file"
          contextName={schema.name}
          contextPath={path}
          contextData={{
            label: schema.label || schema.name,
            sha: sha ?? null,
            content: entry?.contentObject ?? null,
          }}
        />
      );
    }

    if (schemaType === "collection" && entry) {
      const entryActions = getSchemaActions(schema, "entry");
      if (entryActions.length === 0) return null;

      return (
        <RepoActionButtons
          actions={entryActions}
          owner={config.owner}
          repo={config.repo}
          refName={config.branch}
          contextType="entry"
          contextName={schema.name}
          contextPath={path}
          contextData={{
            label: schema.label || schema.name,
            entryName: entry.name ?? null,
            sha: sha ?? null,
            content: entry.contentObject ?? null,
          }}
        />
      );
    }

    return null;
  }, [config.branch, config.owner, config.repo, entry, path, schema, schemaType, sha]);

  const headerNode = useMemo(() => (
    <div className="flex min-w-0 items-center gap-2">
      <div className="flex min-w-0 flex-1 items-center gap-2 overflow-hidden">
        <Breadcrumb className="min-w-0 overflow-hidden">
          <BreadcrumbList className="min-w-0 flex-nowrap font-semibold text-lg">
            {breadcrumbNode}
          </BreadcrumbList>
        </Breadcrumb>
        {headerMeta}
      </div>
      {showHeaderActions && (
        <div className="flex shrink-0 items-center gap-x-2">
          {/* The header renders outside the form's LocaleProvider, so give the
              switcher its own provider bound to the same activeLocale state. */}
          {switcherLocaleList && (
            <LocaleProvider
              locales={switcherLocaleList}
              activeLocale={activeLocale}
              onActiveLocaleChange={setActiveLocale}
              defaultLocale={defaultLocale}
              i18nEnabled={i18nEnabled}
            >
              <LocaleSwitcher />
            </LocaleProvider>
          )}
          {headerActionsNode}
          {path && (
            historyData && historyData.length > 0 && !isLoading
              ? (
                <EntryHistoryDropdown
                  history={historyData}
                  path={path}
                  triggerVariant="outline"
                  triggerSize="icon"
                />
              )
              : <Button variant="outline" size="icon" className="shrink-0" disabled><History /></Button>
          )}
          <Button
            type="submit"
            form="entry-form"
            disabled={
              isBusy ||
              (showFilenameField && filenameValue.trim().length === 0) ||
              (
                Boolean(path) &&
                !(
                  isFormDirty
                  || hasRegisteredChanges
                  || (
                    showFilenameField
                    && filenameFieldMode === "enabled"
                    && isFilenameUnlocked
                    && filenameChanged
                  )
                )
              )
            }
            aria-label="Save"
          >
            <Save className="size-4 sm:hidden" />
            <span className="hidden sm:inline">Save</span>
          </Button>
          {path && (
            <ButtonGroup>
              {sha
                ? (
                  <FileOptions
                    path={path}
                    sha={sha}
                    type={path === ".pages.yml" ? "settings" : (schemaType ?? "content")}
                    name={name}
                    canDelete={canDelete}
                    canRename={canRename}
                    onDelete={handleDelete}
                    onRename={handleRename}
                    deleteOverride={i18nActive ? i18nDeleteOverride : undefined}
                  >
                    <Button variant="outline" size="icon" disabled={isBusy}>
                      <EllipsisVertical />
                    </Button>
                  </FileOptions>
                )
                : <Button variant="outline" size="icon" disabled><EllipsisVertical /></Button>
              }
            </ButtonGroup>
          )}
        </div>
      )}
    </div>
  ), [breadcrumbNode, canDelete, canRename, filenameChanged, filenameFieldMode, filenameValue, handleDelete, handleRename, hasRegisteredChanges, headerActionsNode, headerMeta, historyData, isBusy, isFilenameUnlocked, isFormDirty, isLoading, name, path, schemaType, sha, showFilenameField, showHeaderActions, switcherLocaleList, activeLocale, setActiveLocale, defaultLocale, i18nEnabled, inlineLocaleList]);

  useRepoHeader({ header: headerNode });

  const loadingSkeleton = useMemo(() => (
    <div className="w-full max-w-screen-md mx-auto grid items-start gap-6">
      {path !== ".pages.yml"
        ? 
          <>
            <div className="space-y-2">
              <Skeleton className="w-24 h-5 rounded" />
              <Skeleton className="w-full h-10 rounded-md" />
            </div>
            <div className="space-y-2">
              <Skeleton className="w-24 h-5 rounded" />
              <Skeleton className="w-full h-10 rounded-md" />
            </div>
            <div className="space-y-2">
              <Skeleton className="w-24 h-5 rounded" />
              <div className="grid grid-flow-col auto-cols-max gap-4">
                <Skeleton className="w-28 h-28 rounded-md" />
                <Skeleton className="w-28 h-28 rounded-md" />
                <Skeleton className="w-28 h-28 rounded-md" />
              </div>
            </div>
            <div className="space-y-2">
              <Skeleton className="w-24 h-5 rounded" />
              <Skeleton className="w-full h-60 rounded-md" />
            </div>
          </>
        : <Skeleton className="w-full h-96 rounded-md" />
      }
    </div>
  ), [path]);

  
  if (error) {
    // TODO: should we use a custom error class with code?
    // TODO: errors show no header (unlike collection and media). Consider standardizing templates.
    if (error === "Not found") {
      const isSettingsPage = path === ".pages.yml";
      return (
        <div className="absolute inset-0 p-4 md:p-6 flex items-center justify-center">
          <Empty className="max-w-[420px] flex-none">
            <EmptyHeader>
              <EmptyTitle>{isSettingsPage ? "Configuration not found" : "File not found"}</EmptyTitle>
              <EmptyDescription>
                {isSettingsPage
                  ? "The configuration file \".pages.yml\" does not exist yet."
                  : `The file "${path ?? schema?.path ?? "unknown"}" does not exist yet.`}
              </EmptyDescription>
            </EmptyHeader>
            <EmptyContent>
              {isSettingsPage ? (
                <EmptyCreate type="settings">Create configuration file</EmptyCreate>
              ) : canCreate ? (
                <EmptyCreate type="content" name={schema?.name ?? name}>Create file</EmptyCreate>
              ) : null}
            </EmptyContent>
          </Empty>
        </div>
      );
    } else {
      return (
        <div className="absolute inset-0 p-4 md:p-6 flex items-center justify-center">
          <Empty className="max-w-[420px] flex-none">
            <EmptyHeader>
              <EmptyTitle>Something went wrong</EmptyTitle>
              <EmptyDescription>{error}</EmptyDescription>
            </EmptyHeader>
            <EmptyContent>
              <Link
                className="inline-flex items-center justify-center rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground shadow-xs hover:bg-primary/90"
                href={`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/configuration`}
              >
                Go to configuration
              </Link>
            </EmptyContent>
          </Empty>
        </div>
      );
    }
  }

  if (!path && schemaType === "collection" && !canCreate) {
    return (
      <div className="absolute inset-0 p-4 md:p-6 flex items-center justify-center">
        <Empty className="max-w-[420px] flex-none">
          <EmptyHeader>
            <EmptyTitle>Creating entries is disabled</EmptyTitle>
            <EmptyDescription>
              New entries are not allowed for this collection.
            </EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            <Link
              className="inline-flex items-center justify-center rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground shadow-xs hover:bg-primary/90"
              href={`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}`}
            >
              Back to collection
            </Link>
          </EmptyContent>
        </Empty>
      </div>
    );
  }
  
  const formNode = isLoading
    ? loadingSkeleton
    : <EntryForm
        fields={entryFields}
        contentObject={entryContentObject}
        onSubmit={onSubmit}
        filePath={
          showFilenameField
            ? <InputGroup data-disabled={path ? !isFilenameUnlocked : false}>
                <InputGroupInput
                  value={filenameValue}
                  onChange={(event) => setFilenameValue(event.target.value)}
                  placeholder="Filename"
                  disabled={path ? !isFilenameUnlocked : false}
                  aria-label="Filename"
                />
                {path && filenameFieldMode === "enabled" && canRename && (
                  <InputGroupAddon align="inline-end">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <InputGroupButton
                          type="button"
                          variant="ghost"
                          size="icon-xs"
                          onClick={() => setIsFilenameUnlocked((prev) => !prev)}
                          aria-label={isFilenameUnlocked ? "Lock filename" : "Unlock filename"}
                        >
                          {isFilenameUnlocked
                            ? <LockOpen className="size-3.5" />
                            : <Lock className="size-3.5" />}
                        </InputGroupButton>
                      </TooltipTrigger>
                      <TooltipContent>
                        {isFilenameUnlocked ? "Lock filename" : "Unlock to edit"}
                      </TooltipContent>
                    </Tooltip>
                  </InputGroupAddon>
                )}
              </InputGroup>
            : undefined
        }
        onDirtyChange={setIsFormDirty}
        onChangeRegistered={() => {
          changeVersionRef.current += 1;
          setHasRegisteredChanges(true);
        }}
      />;

  return switcherLocaleList
    ? <LocaleProvider
        locales={switcherLocaleList}
        activeLocale={activeLocale}
        onActiveLocaleChange={setActiveLocale}
        defaultLocale={defaultLocale}
        i18nEnabled={i18nEnabled}
      >{formNode}</LocaleProvider>
    : formNode;
};
