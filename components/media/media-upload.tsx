"use client";

import { useRef, cloneElement, useMemo, useCallback, createContext, useContext, useState } from "react";
import useSWR from "swr";
import { useConfig } from "@/contexts/config-context";
import { getUploadFileName, joinPathSegments } from "@/lib/utils/file";
import { toast } from "sonner";
import { getSchemaByName } from "@/lib/schema";
import { cn } from "@/lib/utils";
import { requireApiSuccess } from "@/lib/api-client";
import { transformImage } from "@/lib/image-transform";
import type { FileSaveData } from "@/types/api";

type StorageInfo = {
  configured: boolean;
  thresholdBytes: number;
  maxFileBytes: number;
  visibility: "public" | "private";
};

const DEFAULT_STORAGE_INFO: StorageInfo = {
  configured: false,
  thresholdBytes: 26214400,
  maxFileBytes: -1,
  visibility: "public",
};

const fetchStorageInfo = async (url: string): Promise<StorageInfo> => {
  const response = await fetch(url);
  if (!response.ok) return DEFAULT_STORAGE_INFO;
  const json = await response.json();
  return (json?.data as StorageInfo) ?? DEFAULT_STORAGE_INFO;
};

// A plain File uploads into the current path; the wrapped form carries the
// directory (relative to the current path) it should land in, used for
// folder uploads so the dropped/picked folder structure is preserved.
type UploadItem = File | { file: File; dir: string };

const itemFile = (item: UploadItem): File => (item instanceof File ? item : item.file);
const itemDir = (item: UploadItem): string => {
  if (!(item instanceof File)) return item.dir;
  // Files picked via a webkitdirectory input carry their folder-relative path.
  const rel = (item as File & { webkitRelativePath?: string }).webkitRelativePath;
  return rel && rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "";
};

interface MediaUploadContextValue {
  handleFiles: (items: UploadItem[]) => Promise<void>;
  accept?: string;
  multiple?: boolean;
  disabled?: boolean;
}

const MediaUploadContext = createContext<MediaUploadContextValue | null>(null);

interface MediaUploadProps {
  children: React.ReactNode;
  path?: string;
  onUpload?: (entry: FileSaveData) => void;
  media?: string;
  extensions?: string[];
  multiple?: boolean;
  rename?: boolean | "safe" | "random";
  disabled?: boolean;
}

interface MediaUploadTriggerProps {
  children: React.ReactElement<{ onClick?: () => void }>;
  /** Open a directory picker instead of a file picker; uploads the folder's
   * contents preserving its internal structure under the current path. */
  folder?: boolean;
}

interface MediaUploadDropZoneProps {
  children: React.ReactNode;
  className?: string;
}

function MediaUploadRoot({ children, path, onUpload, media, extensions, multiple, rename, disabled = false }: MediaUploadProps) {
  const { config } = useConfig();
  if (!config) throw new Error(`Configuration not found.`);

  const configMedia = useMemo(() => 
    media
      ? getSchemaByName(config.object, media, "media")
      : config.object.media[0],
    [media, config.object]
  );

  const accept = useMemo(() => {
    if (!configMedia?.extensions && !extensions) return undefined;
    
    const allowedExtensions = extensions 
      ? configMedia?.extensions
        ? extensions.filter(ext => configMedia.extensions.includes(ext))
        : extensions
      : configMedia?.extensions;

    return allowedExtensions?.length > 0
      ? allowedExtensions.map((extension: string) => `.${extension}`).join(",")
      : undefined;
  }, [extensions, configMedia?.extensions]);

  const apiBase = `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}`;
  const { data: storageInfo } = useSWR<StorageInfo>(
    `${apiBase}/storage/info`,
    fetchStorageInfo,
    { revalidateOnFocus: false, fallbackData: DEFAULT_STORAGE_INFO },
  );

  const handleFiles = useCallback(async (items: UploadItem[]) => {
    try {
      const info = storageInfo ?? DEFAULT_STORAGE_INFO;

      const PRESIGN_THRESHOLD = info.configured ? info.thresholdBytes : Number.POSITIVE_INFINITY;
      const MULTIPART_THRESHOLD = 100 * 1024 * 1024; // resumable past 100 MB
      const PART_SIZE = 8 * 1024 * 1024;

      // Transform + name everything first, then split into files that go to
      // S3 (uploaded individually) and files that go to GitHub (batched
      // into single commits — one commit per file both spams history and
      // trips GitHub's replica race under rapid consecutive commits).
      const prepared: { file: File; fullPath: string }[] = [];
      for (const item of items) {
        const rawFile = itemFile(item);
        const relativeDir = itemDir(item);
        const file = await transformImage(
          rawFile,
          configMedia?.transformations,
        );
        const uploadFilename = getUploadFileName(
          file.name,
          rename ?? configMedia?.rename,
        );

        // A single oversized file must not abort the rest of the upload:
        // report it and continue with the others.
        if (info.maxFileBytes !== -1 && file.size > info.maxFileBytes) {
          toast.error(
            `Skipped ${file.name}: ${(file.size / 1024 / 1024).toFixed(0)} MB exceeds the ${(info.maxFileBytes / 1024 / 1024).toFixed(0)} MB storage limit.`,
          );
          continue;
        }
        if (!info.configured && file.size > 25 * 1024 * 1024) {
          toast.error(
            `Skipped ${file.name}: too large for GitHub uploads (${(file.size / 1024 / 1024).toFixed(0)} MB). Configure S3/R2 storage in Settings → Storage for files over 25 MB.`,
          );
          continue;
        }

        prepared.push({
          file,
          fullPath: joinPathSegments([path ?? "", relativeDir, uploadFilename]),
        });
      }

      const s3Files = prepared.filter(({ file }) => file.size >= PRESIGN_THRESHOLD);
      const githubFiles = prepared.filter(({ file }) => file.size < PRESIGN_THRESHOLD);

      // S3-bound files: unchanged per-file flow.
      for (const { file, fullPath } of s3Files) {
        const uploadPromise = file.size >= MULTIPART_THRESHOLD
          ? uploadMultipart({ apiBase, file, fullPath, mediaName: configMedia.name, partSize: PART_SIZE })
          : uploadPresigned({ apiBase, file, fullPath, mediaName: configMedia.name });

        await toast.promise(uploadPromise, {
          loading: `Uploading ${file.name}`,
          success: (savedEntry) => {
            onUpload?.(savedEntry);
            return `Uploaded ${file.name}`;
          },
          error: (error: unknown) => error instanceof Error ? error.message : "Upload failed",
        });
      }

      if (githubFiles.length === 0) return;

      // Single file: keep the per-file endpoint (idempotent via replace).
      if (githubFiles.length === 1) {
        const { file, fullPath } = githubFiles[0];
        const uploadPromise = (async (): Promise<FileSaveData> => {
          const content = await readAsBase64(file);
          const response = await fetch(`${apiBase}/files/${encodeURIComponent(fullPath)}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              type: "media",
              name: configMedia.name,
              content,
              size: file.size,
              // Idempotent: re-uploading a file overwrites it instead of
              // creating a numbered duplicate.
              onConflict: "replace",
            }),
          });
          const data = await requireApiSuccess<any>(response, "Failed to upload file");
          return data.data as FileSaveData;
        })();

        await toast.promise(uploadPromise, {
          loading: `Uploading ${file.name}`,
          success: (savedEntry) => {
            onUpload?.(savedEntry);
            return `Uploaded ${file.name}`;
          },
          error: (error: unknown) => error instanceof Error ? error.message : "Upload failed",
        });
        return;
      }

      // Multiple GitHub-bound files: one commit per chunk via files-batch.
      // Chunk so a single request body stays well under Workers limits.
      const MAX_CHUNK_FILES = 20;
      const MAX_CHUNK_BYTES = 16 * 1024 * 1024; // raw bytes per request
      const chunks: { file: File; fullPath: string }[][] = [];
      let current: { file: File; fullPath: string }[] = [];
      let currentBytes = 0;
      for (const entry of githubFiles) {
        if (current.length > 0 && (current.length >= MAX_CHUNK_FILES || currentBytes + entry.file.size > MAX_CHUNK_BYTES)) {
          chunks.push(current);
          current = [];
          currentBytes = 0;
        }
        current.push(entry);
        currentBytes += entry.file.size;
      }
      if (current.length > 0) chunks.push(current);

      let uploadedCount = 0;
      for (const [chunkIndex, chunk] of chunks.entries()) {
        const batchPromise = (async () => {
          const files = await Promise.all(chunk.map(async ({ file, fullPath }) => ({
            path: fullPath,
            content: await readAsBase64(file),
            size: file.size,
          })));
          const targetDir = path ?? "";
          const response = await fetch(`${apiBase}/files-batch`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              type: "media",
              name: configMedia.name,
              files,
              message: `Upload ${files.length} file(s) to ${targetDir} (via Pages CMS)`,
            }),
          });
          const data = await requireApiSuccess<any>(response, "Failed to upload files");
          return data.data as { commitSha: string; files: { path: string; sha: string; size: number }[] };
        })();

        await toast.promise(batchPromise, {
          loading: chunks.length > 1
            ? `Uploading ${chunk.length} files (${chunkIndex + 1}/${chunks.length})…`
            : `Uploading ${chunk.length} files…`,
          success: (result) => {
            uploadedCount += result.files.length;
            for (const f of result.files) {
              const name = f.path.split("/").pop() || f.path;
              onUpload?.({
                type: "file",
                sha: f.sha,
                name,
                path: f.path,
                extension: name.includes(".") ? name.split(".").pop() : undefined,
                size: f.size,
                url: undefined,
              } as FileSaveData);
            }
            return `Uploaded ${uploadedCount}/${githubFiles.length} files`;
          },
          error: (error: unknown) => error instanceof Error ? error.message : "Upload failed",
        });
      }
    } catch (error) {
      console.error(error);
    }
  }, [apiBase, path, configMedia?.name, configMedia?.rename, configMedia?.transformations, onUpload, rename, storageInfo]);

  const contextValue = useMemo(() => ({
    handleFiles,
    accept,
    multiple,
    disabled,
  }), [handleFiles, accept, multiple, disabled]);

  return (
    <MediaUploadContext.Provider value={contextValue}>
      {children}
    </MediaUploadContext.Provider>
  );
}

function MediaUploadTrigger({ children, folder = false }: MediaUploadTriggerProps) {
  const context = useContext(MediaUploadContext);
  if (!context) throw new Error("MediaUploadTrigger must be used within a MediaUpload component");

  const fileInputRef = useRef<HTMLInputElement>(null);

  const filterAcceptedFiles = useCallback((files: File[]) => {
    const acceptedExtensions = context.accept?.split(",").map((ext) => ext.trim().toLowerCase());
    if (!acceptedExtensions?.length) return files;

    const validFiles = files.filter((file) => {
      const ext = `.${file.name.split(".").pop()?.toLowerCase()}`;
      return acceptedExtensions.includes(ext);
    });

    if (validFiles.length === 0) {
      toast.error(`Invalid file type. Allowed: ${context.accept}`);
      return [];
    }

    if (validFiles.length !== files.length) {
      toast.error(`Some files were skipped. Allowed: ${context.accept}`);
    }

    return validFiles;
  }, [context.accept]);

  const handleClick = useCallback(() => {
    if (context.disabled) return;
    fileInputRef.current?.click();
  }, [context.disabled]);

  const handleFileInput = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    if (context.disabled) return;
    const files = event.target.files;
    if (!files || files.length === 0) return;

    const validFiles = filterAcceptedFiles(Array.from(files));
    if (validFiles.length === 0) return;

    context.handleFiles(validFiles);
  }, [context, filterAcceptedFiles]);

  return (
    <>
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileInput}
        accept={folder ? undefined : context.accept}
        multiple={context.multiple}
        hidden
        // Non-standard but universally supported directory-picker attribute.
        {...(folder ? ({ webkitdirectory: "" } as Record<string, string>) : {})}
      />
      {cloneElement(children, { onClick: handleClick })}
    </>
  );
}

function MediaUploadDropZone({ children, className }: MediaUploadDropZoneProps) {
  const context = useContext(MediaUploadContext);
  if (!context) throw new Error("MediaUploadDropZone must be used within a MediaUpload component");
  
  const [isDragging, setIsDragging] = useState(false);

  const filterAcceptedItems = useCallback((items: UploadItem[]) => {
    const acceptedExtensions = context.accept?.split(",").map((ext) => ext.trim().toLowerCase());
    if (!acceptedExtensions?.length) return items;

    const validItems = items.filter((item) => {
      const ext = `.${itemFile(item).name.split(".").pop()?.toLowerCase()}`;
      return acceptedExtensions.includes(ext);
    });

    if (validItems.length === 0) {
      toast.error(`Invalid file type. Allowed: ${context.accept}`);
      return [];
    }

    if (validItems.length !== items.length) {
      toast.error(`Some files were skipped. Allowed: ${context.accept}`);
    }

    return validItems;
  }, [context.accept]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    if (context.disabled) return;
    e.preventDefault();
    setIsDragging(true);
  }, [context.disabled]);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    if (context.disabled) return;
    e.preventDefault();
    setIsDragging(false);
  }, [context.disabled]);

  const handleDrop = useCallback(async (e: React.DragEvent) => {
    if (context.disabled) return;
    e.preventDefault();
    setIsDragging(false);

    // Capture entries synchronously — DataTransferItems go stale after the
    // first await. Entries let us traverse dropped folders recursively.
    const entries = Array.from(e.dataTransfer.items ?? [])
      .map((item) => item.webkitGetAsEntry?.())
      .filter((entry): entry is FileSystemEntry => !!entry);

    let items: UploadItem[];
    if (entries.length > 0) {
      const collected: { file: File; dir: string }[] = [];
      const readAllEntries = async (dir: FileSystemDirectoryEntry): Promise<FileSystemEntry[]> => {
        // readEntries returns results in batches; loop until it comes back empty.
        const reader = dir.createReader();
        const all: FileSystemEntry[] = [];
        for (;;) {
          const batch = await new Promise<FileSystemEntry[]>((resolve, reject) =>
            reader.readEntries(resolve, reject),
          );
          if (batch.length === 0) return all;
          all.push(...batch);
        }
      };
      const traverse = async (entry: FileSystemEntry, dir: string): Promise<void> => {
        if (entry.isFile) {
          const file = await new Promise<File>((resolve, reject) =>
            (entry as FileSystemFileEntry).file(resolve, reject),
          );
          collected.push({ file, dir });
        } else if (entry.isDirectory) {
          const children = await readAllEntries(entry as FileSystemDirectoryEntry);
          for (const child of children) {
            await traverse(child, joinPathSegments([dir, entry.name]));
          }
        }
      };
      try {
        for (const entry of entries) await traverse(entry, "");
      } catch (error) {
        console.error("Failed to read dropped folder", error);
        toast.error("Could not read the dropped folder.");
        return;
      }
      items = collected;
    } else {
      const files = e.dataTransfer.files;
      if (!files || files.length === 0) return;
      items = Array.from(files);
    }

    const validItems = filterAcceptedItems(items);
    if (validItems.length === 0) return;

    context.handleFiles(validItems);
  }, [context, filterAcceptedItems]);

  return (
    <div
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className={cn("relative", className)}
    >
      {children}
      {!context.disabled && isDragging && (
        <div className="absolute inset-0 bg-primary/10 rounded-lg flex items-center justify-center">
          <p className="text-sm text-foreground font-medium bg-background rounded-full px-3 py-1">
            Drop files here to upload
          </p>
        </div>
      )}
    </div>
  );
}

async function readAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve((reader.result as string).replace(/^(.+,)/, ""));
    reader.onerror = () => reject(new Error("Failed to read file"));
    reader.readAsDataURL(file);
  });
}

async function uploadPresigned({
  apiBase, file, fullPath, mediaName,
}: { apiBase: string; file: File; fullPath: string; mediaName: string; }): Promise<FileSaveData> {
  const presign = await fetch(`${apiBase}/storage/presign`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: mediaName,
      path: fullPath,
      contentType: file.type || "application/octet-stream",
      size: file.size,
    }),
  });
  const presignData = await requireApiSuccess<any>(presign, "Failed to issue presigned URL");

  const put = await fetch(presignData.data.uploadUrl, {
    method: "PUT",
    headers: presignData.data.headers ?? { "Content-Type": file.type || "application/octet-stream" },
    body: file,
  });
  if (!put.ok) throw new Error(`Direct S3 upload failed (${put.status})`);

  const finalize = await fetch(`${apiBase}/storage/finalize`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: mediaName,
      path: fullPath,
      key: presignData.data.key,
    }),
  });
  const finalizeData = await requireApiSuccess<any>(finalize, "Failed to finalize upload");
  return finalizeData.data as FileSaveData;
}

async function uploadMultipart({
  apiBase, file, fullPath, mediaName, partSize,
}: { apiBase: string; file: File; fullPath: string; mediaName: string; partSize: number; }): Promise<FileSaveData> {
  const create = await fetch(`${apiBase}/storage/multipart`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      action: "create",
      name: mediaName,
      path: fullPath,
      contentType: file.type || "application/octet-stream",
      size: file.size,
    }),
  });
  const createData = await requireApiSuccess<any>(create, "Failed to start multipart upload");
  const { key, uploadId } = createData.data as { key: string; uploadId: string };

  const totalParts = Math.ceil(file.size / partSize);
  const partNumbers = Array.from({ length: totalParts }, (_, i) => i + 1);

  try {
    const sign = await fetch(`${apiBase}/storage/multipart`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "sign-parts",
        name: mediaName,
        key,
        uploadId,
        partNumbers,
      }),
    });
    const signData = await requireApiSuccess<any>(sign, "Failed to sign upload parts");
    const urls = signData.data.urls as { partNumber: number; url: string }[];
    const urlMap = new Map(urls.map((u) => [u.partNumber, u.url]));

    const parts: { PartNumber: number; ETag: string }[] = [];
    for (const partNumber of partNumbers) {
      const start = (partNumber - 1) * partSize;
      const end = Math.min(file.size, start + partSize);
      const chunk = file.slice(start, end);
      const url = urlMap.get(partNumber);
      if (!url) throw new Error(`Missing presigned URL for part ${partNumber}`);
      const partResp = await fetch(url, { method: "PUT", body: chunk });
      if (!partResp.ok) throw new Error(`Part ${partNumber} upload failed (${partResp.status})`);
      const etag = partResp.headers.get("ETag") ?? partResp.headers.get("etag");
      if (!etag) throw new Error(`Part ${partNumber} missing ETag`);
      parts.push({ PartNumber: partNumber, ETag: etag.replace(/"/g, "") });
    }

    const complete = await fetch(`${apiBase}/storage/multipart`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "complete", name: mediaName, key, uploadId, parts }),
    });
    await requireApiSuccess<any>(complete, "Failed to complete multipart upload");

    const finalize = await fetch(`${apiBase}/storage/finalize`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: mediaName, path: fullPath, key }),
    });
    const finalizeData = await requireApiSuccess<any>(finalize, "Failed to finalize upload");
    return finalizeData.data as FileSaveData;
  } catch (error) {
    void fetch(`${apiBase}/storage/multipart`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "abort", name: mediaName, key, uploadId }),
    });
    throw error;
  }
}

export const MediaUpload = Object.assign(MediaUploadRoot, {
  Trigger: MediaUploadTrigger,
  DropZone: MediaUploadDropZone,
});
