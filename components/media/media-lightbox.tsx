"use client";

import { useEffect, useMemo, useState } from "react";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { VisuallyHidden } from "@radix-ui/react-visually-hidden";
import { getRawUrl, outputToInputPath } from "@/lib/github-image";
import { useRepo } from "@/contexts/repo-context";
import { useConfig } from "@/contexts/config-context";
import { Ban, Loader } from "lucide-react";

const VIDEO_EXTENSIONS = new Set(["mp4", "webm", "mov", "ogg", "avi"]);

const isVideo = (path: string) => {
  const ext = path.split(".").pop()?.toLowerCase();
  return ext ? VIDEO_EXTENSIONS.has(ext) : false;
};

const MediaLightbox = ({
  open,
  onOpenChange,
  name,
  path,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  name: string;
  path: string | null;
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

  const filename = path ? path.split("/").pop() ?? "media" : "media";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-[95vw] w-auto p-2 sm:p-2 bg-background border-0 shadow-2xl grid-rows-[auto_1fr] gap-0">
        <VisuallyHidden>
          <DialogTitle>{filename}</DialogTitle>
        </VisuallyHidden>
        <div className="flex items-center justify-center min-w-[min(60vw,20rem)] min-h-[min(60vh,16rem)] max-h-[85vh]">
          {path && rawUrl
            ? isVideo(path)
              ? <video
                  src={rawUrl}
                  controls
                  autoPlay
                  playsInline
                  className="max-h-[85vh] max-w-full object-contain"
                />
              : <img
                  src={rawUrl}
                  alt={filename}
                  className="max-h-[85vh] max-w-full object-contain"
                />
            : error
              ? <div className="flex items-center gap-2 text-muted-foreground p-8" title={error}>
                  <Ban className="h-5 w-5" /> {error}
                </div>
              : <Loader className="h-6 w-6 animate-spin text-muted-foreground" />
          }
        </div>
        <div className="px-2 pt-1 pb-1 text-xs text-muted-foreground truncate">{filename}</div>
      </DialogContent>
    </Dialog>
  );
};

export { MediaLightbox };
