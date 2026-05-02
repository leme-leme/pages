"use client";

import { useState, useEffect, useRef, useMemo } from "react";
import { getRawUrl, outputToInputPath } from "@/lib/github-image";
import { useRepo } from "@/contexts/repo-context";
import { useConfig } from "@/contexts/config-context";
import { cn } from "@/lib/utils";
import { Ban, ImageOff, Loader } from "lucide-react";

const VIDEO_EXTENSIONS = new Set(["mp4", "webm", "mov", "ogg", "avi"]);

function isVideo(path: string): boolean {
  const ext = path.split(".").pop()?.toLowerCase();
  return ext ? VIDEO_EXTENSIONS.has(ext) : false;
}

function VideoThumbnail({ src, alt }: { src: string; alt: string }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const [duration, setDuration] = useState(0);
  const [hoverRatio, setHoverRatio] = useState(0);
  const [isHovering, setIsHovering] = useState(false);

  const handleLoadedMetadata = () => {
    const video = videoRef.current;
    if (!video) return;
    setDuration(Number.isFinite(video.duration) ? video.duration : 0);
    video.currentTime = 0.1;
  };

  const handlePointerMove = (event: React.PointerEvent<HTMLDivElement>) => {
    const container = containerRef.current;
    const video = videoRef.current;
    if (!container || !video || !duration) return;
    const rect = container.getBoundingClientRect();
    const ratio = Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width));
    setHoverRatio(ratio);
    video.currentTime = ratio * duration;
  };

  const handlePointerEnter = () => setIsHovering(true);
  const handlePointerLeave = () => {
    setIsHovering(false);
    setHoverRatio(0);
    const video = videoRef.current;
    if (video) video.currentTime = 0.1;
  };

  return (
    <div
      ref={containerRef}
      className="absolute inset-0"
      onPointerEnter={handlePointerEnter}
      onPointerMove={handlePointerMove}
      onPointerLeave={handlePointerLeave}
    >
      <video
        ref={videoRef}
        src={src}
        aria-label={alt}
        className="absolute inset-0 w-full h-full object-cover pointer-events-none"
        muted
        playsInline
        preload="metadata"
        onLoadedMetadata={handleLoadedMetadata}
      />
      {duration > 0 && (
        <div
          aria-hidden
          className={cn(
            "absolute left-0 right-0 bottom-0 h-0.5 bg-white/30 transition-opacity",
            isHovering ? "opacity-100" : "opacity-0",
          )}
        >
          <div
            className="h-full bg-white"
            style={{ width: `${hoverRatio * 100}%` }}
          />
        </div>
      )}
    </div>
  );
}

export function Thumbnail({
  name,
  path,
  className,
}: {
  name: string;
  path: string | null;
  className?: string;
}) {
  const [rawUrl, setRawUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { owner, repo, isPrivate } = useRepo();
  const { config } = useConfig();
  const branch = config?.branch!;

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

  return (
    <div
      className={cn(
        "bg-muted w-full aspect-square overflow-hidden relative",
        className,
      )}
    >
      {path
        ? rawUrl
          ? isVideo(path)
            ? <VideoThumbnail src={rawUrl} alt={path.split("/").pop() || "thumbnail"} />
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
