"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { getRawUrl, outputToInputPath } from "@/lib/github-image";
import { useRepo } from "@/contexts/repo-context";
import { useConfig } from "@/contexts/config-context";
import { Thumbnail } from "@/components/thumbnail";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { Ban, ChevronLeft, ChevronRight, Loader, X } from "lucide-react";

const VIDEO_EXTENSIONS = new Set(["mp4", "webm", "mov", "ogg", "avi"]);

const isVideo = (path: string) => {
  const ext = path.split(".").pop()?.toLowerCase();
  return ext ? VIDEO_EXTENSIONS.has(ext) : false;
};

type MediaItem = {
  path: string;
  name: string;
};

const MediaLightbox = ({
  name,
  path,
  items,
  onClose,
  onPathChange,
}: {
  name: string;
  path: string;
  items?: MediaItem[];
  onClose: () => void;
  onPathChange?: (path: string) => void;
}) => {
  const { owner, repo, isPrivate } = useRepo();
  const { config } = useConfig();
  const branch = config?.branch!;

  const repoPath = useMemo(
    () => outputToInputPath(path, config?.object?.media, name),
    [path, name, config],
  );

  const [rawUrl, setRawUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

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

  const navigableItems = items ?? [];
  const currentIndex = navigableItems.findIndex((i) => i.path === path);
  const canNavigate = navigableItems.length > 1 && currentIndex >= 0 && !!onPathChange;

  const navigate = (delta: number) => {
    if (!canNavigate) return;
    const next = (currentIndex + delta + navigableItems.length) % navigableItems.length;
    onPathChange!(navigableItems[next].path);
  };

  const filename = path.split("/").pop() ?? "media";

  const containerRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    containerRef.current?.focus();
  }, []);

  const stripRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (currentIndex < 0) return;
    const strip = stripRef.current;
    const active = strip?.querySelector<HTMLElement>(`[data-lightbox-thumb="${currentIndex}"]`);
    active?.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "center" });
  }, [currentIndex]);

  return (
    <div
      ref={containerRef}
      tabIndex={-1}
      onKeyDown={(e) => {
        if (e.key === "ArrowRight") { e.preventDefault(); navigate(1); }
        else if (e.key === "ArrowLeft") { e.preventDefault(); navigate(-1); }
        else if (e.key === "Escape") { e.preventDefault(); onClose(); }
      }}
      className="flex-1 min-h-0 grid grid-rows-[minmax(0,1fr)_auto_auto] gap-0 outline-none max-h-[calc(100dvh-5.5rem)] md:max-h-[calc(100dvh-6.5rem)]"
    >
      <div className="relative flex items-center justify-center min-h-0 overflow-hidden bg-muted/40 rounded-md">
        <Button
          type="button"
          variant="outline"
          size="icon"
          className="absolute top-2 right-2 z-10"
          onClick={onClose}
          aria-label="Close preview"
        >
          <X />
        </Button>
        {canNavigate && (
          <>
            <Button
              type="button"
              variant="outline"
              size="icon"
              className="absolute left-2 top-1/2 -translate-y-1/2 z-10"
              onClick={() => navigate(-1)}
              aria-label="Previous"
            >
              <ChevronLeft />
            </Button>
            <Button
              type="button"
              variant="outline"
              size="icon"
              className="absolute right-2 top-1/2 -translate-y-1/2 z-10"
              onClick={() => navigate(1)}
              aria-label="Next"
            >
              <ChevronRight />
            </Button>
          </>
        )}
        {rawUrl
          ? isVideo(path)
            ? <video
                key={rawUrl}
                src={rawUrl}
                controls
                autoPlay
                playsInline
                className="max-h-full max-w-full object-contain"
              />
            : <img
                src={rawUrl}
                alt={filename}
                className="max-h-full max-w-full object-contain"
              />
          : error
            ? <div className="flex items-center gap-2 text-muted-foreground p-8" title={error}>
                <Ban className="h-5 w-5" /> {error}
              </div>
            : <Loader className="h-6 w-6 animate-spin text-muted-foreground" />
        }
      </div>
      <div className="px-1 py-2 text-xs text-muted-foreground truncate">{filename}</div>
      {navigableItems.length > 1 && (
        <div
          ref={stripRef}
          className="flex gap-2 overflow-x-auto pb-1 scrollbar"
        >
          {navigableItems.map((item, idx) => (
            <button
              key={item.path}
              type="button"
              data-lightbox-thumb={idx}
              onClick={() => onPathChange?.(item.path)}
              aria-label={item.name}
              aria-current={idx === currentIndex ? "true" : undefined}
              className={cn(
                "shrink-0 w-20 sm:w-24 rounded-md overflow-hidden border-2 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                idx === currentIndex ? "border-primary" : "border-transparent hover:border-muted-foreground/40",
              )}
            >
              <Thumbnail name={name} path={item.path} className="aspect-video rounded-none" />
            </button>
          ))}
        </div>
      )}
    </div>
  );
};

export { MediaLightbox };
