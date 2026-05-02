"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { VisuallyHidden } from "@radix-ui/react-visually-hidden";
import { getRawUrl, outputToInputPath } from "@/lib/github-image";
import { useRepo } from "@/contexts/repo-context";
import { useConfig } from "@/contexts/config-context";
import { Thumbnail } from "@/components/thumbnail";
import { cn } from "@/lib/utils";
import { Ban, Loader } from "lucide-react";

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
  open,
  onOpenChange,
  name,
  path,
  items,
  onPathChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  name: string;
  path: string | null;
  items?: MediaItem[];
  onPathChange?: (path: string) => void;
}) => {
  const { owner, repo, isPrivate } = useRepo();
  const { config } = useConfig();
  const branch = config?.branch!;

  const repoPath = useMemo(() => {
    if (!path) return path;
    return outputToInputPath(path, config?.object?.media, name);
  }, [path, name, config]);

  const [rawUrl, setRawUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || !repoPath) return;
    let cancelled = false;
    setError(null);
    setRawUrl(null);
    getRawUrl(owner, repo, branch, name, repoPath, isPrivate)
      .then((url) => { if (!cancelled) setRawUrl(url); })
      .catch((err: any) => { if (!cancelled) setError(err?.message ?? "Error"); });
    return () => { cancelled = true; };
  }, [open, repoPath, owner, repo, branch, isPrivate, name]);

  const navigableItems = items ?? [];
  const currentIndex = path ? navigableItems.findIndex((i) => i.path === path) : -1;

  const navigate = (delta: number) => {
    if (!onPathChange || navigableItems.length === 0 || currentIndex < 0) return;
    const next = (currentIndex + delta + navigableItems.length) % navigableItems.length;
    onPathChange(navigableItems[next].path);
  };

  const filename = path ? path.split("/").pop() ?? "media" : "media";

  const stripRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open || currentIndex < 0) return;
    const strip = stripRef.current;
    const active = strip?.querySelector<HTMLElement>(`[data-lightbox-thumb="${currentIndex}"]`);
    active?.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "center" });
  }, [open, currentIndex]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="!max-w-none w-screen h-screen sm:!max-w-[calc(100vw-2rem)] sm:w-[calc(100vw-2rem)] sm:h-[calc(100vh-2rem)] p-0 sm:p-4 bg-background border-0 sm:border shadow-2xl grid-rows-[1fr_auto_auto] gap-0 rounded-none sm:rounded-lg"
        onKeyDown={(e) => {
          if (e.key === "ArrowRight") { e.preventDefault(); navigate(1); }
          else if (e.key === "ArrowLeft") { e.preventDefault(); navigate(-1); }
        }}
      >
        <VisuallyHidden>
          <DialogTitle>{filename}</DialogTitle>
        </VisuallyHidden>
        <div className="flex items-center justify-center min-h-0 overflow-hidden">
          {path && rawUrl
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
        <div className="px-3 py-2 text-xs text-muted-foreground truncate border-t">{filename}</div>
        {navigableItems.length > 1 && (
          <div
            ref={stripRef}
            className="flex gap-2 overflow-x-auto p-2 border-t scrollbar"
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
      </DialogContent>
    </Dialog>
  );
};

export { MediaLightbox };
