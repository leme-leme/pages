"use client";

import { useRef, cloneElement, useMemo, useCallback, createContext, useContext, useState } from "react";
import { useConfig } from "@/contexts/config-context";
import { getUploadFileName, joinPathSegments } from "@/lib/utils/file";
import { toast } from "sonner";
import { getSchemaByName } from "@/lib/schema";
import { cn } from "@/lib/utils";
import { requireApiSuccess } from "@/lib/api-client";
import { transformImage } from "@/lib/image-transform";
import type { FileSaveData } from "@/types/api";

interface MediaUploadContextValue {
  handleFiles: (files: File[]) => Promise<void>;
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

  const handleFiles = useCallback(async (files: File[]) => {
    try {
      for (const rawFile of files) {
        const file = await transformImage(
          rawFile,
          configMedia?.transformations,
        );
        const uploadFilename = getUploadFileName(
          file.name,
          rename ?? configMedia?.rename,
        );

        const PRESIGN_THRESHOLD = 25 * 1024 * 1024; // skip base64 round-trip past 25 MB
        const MULTIPART_THRESHOLD = 100 * 1024 * 1024; // resumable past 100 MB
        const PART_SIZE = 8 * 1024 * 1024;

        const fullPath = joinPathSegments([path ?? "", uploadFilename]);
        const apiBase = `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}`;

        const uploadPromise = (async (): Promise<FileSaveData> => {
          if (file.size >= MULTIPART_THRESHOLD) {
            return uploadMultipart({
              apiBase,
              file,
              fullPath,
              mediaName: configMedia.name,
              partSize: PART_SIZE,
            });
          }
          if (file.size >= PRESIGN_THRESHOLD) {
            return uploadPresigned({
              apiBase,
              file,
              fullPath,
              mediaName: configMedia.name,
            });
          }
          // Small files: existing JSON+base64 path through GitHub.
          const content = await readAsBase64(file);
          const response = await fetch(`${apiBase}/files/${encodeURIComponent(fullPath)}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              type: "media",
              name: configMedia.name,
              content,
              size: file.size,
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
      }
    } catch (error) {
      console.error(error);
    }
  }, [config, path, configMedia?.name, configMedia?.rename, configMedia?.transformations, onUpload, rename]);

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

function MediaUploadTrigger({ children }: MediaUploadTriggerProps) {
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
        accept={context.accept}
        multiple={context.multiple}
        hidden
      />
      {cloneElement(children, { onClick: handleClick })}
    </>
  );
}

function MediaUploadDropZone({ children, className }: MediaUploadDropZoneProps) {
  const context = useContext(MediaUploadContext);
  if (!context) throw new Error("MediaUploadDropZone must be used within a MediaUpload component");
  
  const [isDragging, setIsDragging] = useState(false);

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

  const handleDrop = useCallback((e: React.DragEvent) => {
    if (context.disabled) return;
    e.preventDefault();
    setIsDragging(false);
    
    const files = e.dataTransfer.files;
    if (!files || files.length === 0) return;

    const validFiles = filterAcceptedFiles(Array.from(files));
    if (validFiles.length === 0) return;

    context.handleFiles(validFiles);
  }, [context, filterAcceptedFiles]);

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
