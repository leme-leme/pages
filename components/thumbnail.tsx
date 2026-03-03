"use client";

import { useState, useEffect, useMemo } from "react";
import { getRawUrl } from "@/lib/githubImage";
import { useRepo } from "@/contexts/repo-context";
import { useConfig } from "@/contexts/config-context";
import { cn } from "@/lib/utils";
import { Ban, ImageOff, Loader } from "lucide-react";

const VIDEO_EXTENSIONS = new Set(["mp4", "webm", "mov", "ogg", "avi"]);

function isVideo(path: string): boolean {
  const ext = path.split(".").pop()?.toLowerCase();
  return ext ? VIDEO_EXTENSIONS.has(ext) : false;
}

// Translate a stored output-based path (e.g. "/media/foo.jpg") to
// the repo input path (e.g. "static/media/foo.jpg") using media config.
function outputToInputPath(
  path: string,
  media: any,
  name?: string
): string {
  if (!path) return path;
  if (!media) return path.replace(/^\//, "");

  // Normalize media to array of {input, output} objects
  const configs: any[] = Array.isArray(media)
    ? media
    : typeof media === "string"
      ? [{ input: media, output: media }]
      : [media];

  // Prefer named config, fall back to first
  const cfg = name
    ? configs.find((m: any) => m.name === name) ?? configs[0]
    : configs[0];

  if (!cfg || typeof cfg === "string") return path.replace(/^\//, "");

  const outputPrefix = (cfg.output ?? "").replace(/\/$/, "");
  const inputPrefix = (cfg.input ?? "").replace(/\/$/, "");

  const normalizedPath = path.startsWith("/") ? path : "/" + path;
  const normalizedOutput = outputPrefix.startsWith("/")
    ? outputPrefix
    : "/" + outputPrefix;

  if (
    normalizedOutput &&
    (normalizedPath === normalizedOutput ||
      normalizedPath.startsWith(normalizedOutput + "/"))
  ) {
    const rest = normalizedPath.slice(normalizedOutput.length); // e.g. "/foo.jpg"
    return (inputPrefix + rest).replace(/^\//, "");
  }

  return path.replace(/^\//, "");
}

export function Thumbnail({
  name,
  path,
  className
}: {
  name: string,
  path: string | null;
  className?: string;
}) {
  const [rawUrl, setRawUrl] = useState<string | null>(null);
  const [error, setError] = useState(null);

  const { owner, repo, isPrivate } = useRepo();
  const { config } = useConfig();
  const branch = config?.branch!;

  // Translate output path → repo input path so raw.githubusercontent.com works
  const repoPath = useMemo(() => {
    if (!path) return path;
    return outputToInputPath(path, config?.object?.media, name);
  }, [path, name, config]);

  useEffect(() => {
    const fetchRawUrl = async () => {
      if (repoPath) {
        setError(null);
        if (!rawUrl) setRawUrl(null);
        try {
          const url = await getRawUrl(owner, repo, branch, name, repoPath, isPrivate);
          setRawUrl(url);
        } catch (error: any) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          console.warn(errorMessage);
          setError(error.message);
        }
      }
    };

    fetchRawUrl();
  }, [repoPath, owner, repo, branch, isPrivate, name, rawUrl]);

  return (
    <div
      className={cn(
        "bg-muted w-full aspect-square overflow-hidden relative",
        className
      )}
    >
      {path
        ? rawUrl
          ? isVideo(path)
            ? <video
                src={rawUrl}
                className="absolute inset-0 w-full h-full object-cover"
                muted
                playsInline
                preload="metadata"
              />
            : <img
                src={rawUrl}
                alt={path.split("/").pop() || "thumbnail"}
                loading="lazy"
                className="absolute inset-0 w-full h-full object-cover"
              />
          : error
            ? <div className="flex justify-center items-center absolute inset-0 text-muted-foreground" title={error}>
                <Ban className="h-4 w-4"/>
              </div>
            : <div className="flex justify-center items-center absolute inset-0 text-muted-foreground" title="Loading...">
                <Loader className="h-4 w-4 animate-spin"/>
              </div>
        : <div className="flex justify-center items-center absolute inset-0 text-muted-foreground" title="No image">
            <ImageOff className="h-4 w-4"/>
          </div>
      }
    </div>
  );
};
