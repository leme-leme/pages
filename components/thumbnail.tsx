"use client";

import { useState, useEffect, useRef, useMemo } from "react";
import { getRawUrl, outputToInputPath } from "@/lib/githubImage";
import { useRepo } from "@/contexts/repo-context";
import { useConfig } from "@/contexts/config-context";
import { cn } from "@/lib/utils";
import { Ban, ImageOff, Loader } from "lucide-react";

const VIDEO_EXTENSIONS = new Set(["mp4", "webm", "mov", "ogg", "avi"]);

function isVideo(path: string): boolean {
  const ext = path.split(".").pop()?.toLowerCase();
  return ext ? VIDEO_EXTENSIONS.has(ext) : false;
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
  const [error, setError] = useState<string | null>(null);
  const videoRef = useRef<HTMLVideoElement>(null);

  const { owner, repo, isPrivate } = useRepo();
  const { config } = useConfig();
  const branch = config?.branch!;

  // Translate output path → repo input path so raw.githubusercontent.com works
  const repoPath = useMemo(() => {
    if (!path) return path;
    return outputToInputPath(path, config?.object?.media, name);
  }, [path, name, config]);

  useEffect(() => {
    if (!repoPath) return;
    let cancelled = false;
    setError(null);
    setRawUrl(null);
    getRawUrl(owner, repo, branch, name, repoPath, isPrivate)
      .then((url) => { if (!cancelled) setRawUrl(url); })
      .catch((err: any) => { if (!cancelled) setError(err?.message ?? "Error"); });
    return () => { cancelled = true; };
  }, [repoPath, owner, repo, branch, isPrivate, name]);

  // Seek to first frame so the video element shows a poster thumbnail
  const handleLoadedMetadata = () => {
    if (videoRef.current) {
      videoRef.current.currentTime = 0.1;
    }
  };

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
                ref={videoRef}
                src={rawUrl}
                className="absolute inset-0 w-full h-full object-cover"
                muted
                playsInline
                preload="metadata"
                onLoadedMetadata={handleLoadedMetadata}
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
