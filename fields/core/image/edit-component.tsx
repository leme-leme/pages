"use client";

import { forwardRef, useCallback, useState, useEffect, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { MediaUpload } from "@/components/media/media-upload";
import { MediaDialog } from "@/components/media/media-dialog";
import { MediaLightbox } from "@/components/media/media-lightbox";
import { Trash2, Upload, FolderOpen, Images } from "lucide-react";
import { useConfig } from "@/contexts/config-context";
import { extensionCategories, normalizePath } from "@/lib/utils/file";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { DndContext, closestCenter, KeyboardSensor, PointerSensor, useSensor, useSensors } from '@dnd-kit/core';
import { arrayMove, SortableContext, sortableKeyboardCoordinates, verticalListSortingStrategy, rectSortingStrategy } from '@dnd-kit/sortable';
import { useSortable } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { v4 as uuidv4 } from 'uuid';
import { getSchemaByName } from "@/lib/schema";
import { Thumbnail } from "@/components/thumbnail";
import { getAllowedExtensions } from "./index";

const generateId = () => uuidv4().slice(0, 8);

const ImageTeaser = ({ file, media, mediaConfig, rootPath, allowedExtensions, onRemove, onReplace }: {
  file: string;
  media: string;
  mediaConfig: any;
  rootPath?: string;
  allowedExtensions?: string[];
  onRemove: (file: string) => void;
  onReplace: (newPath: string) => void;
}) => {
  return (
    <div className="absolute bottom-1.5 right-1.5">
      <TooltipProvider>
        <Tooltip>
          <MediaDialog
            media={media}
            initialPath={rootPath ?? mediaConfig?.input}
            maxSelected={1}
            extensions={allowedExtensions}
            onSubmit={(newPaths) => { if (newPaths[0]) onReplace(newPaths[0]); }}
          >
            <TooltipTrigger asChild>
              <Button
                type="button"
                size="icon-xs"
                variant="secondary"
                className="rounded-r-none"
              >
                <Images className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
          </MediaDialog>
          <TooltipContent>
            Replace from images
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>

      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              type="button"
              size="icon-xs"
              variant="secondary"
              onClick={() => onRemove(file)}
              className="rounded-l-none"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            Remove
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    </div>
  )
};

const SortableItem = ({ id, file, media, mediaConfig, rootPath, allowedExtensions, onRemove, onReplace, onPreview }: {
  id: string;
  file: string;
  media: string;
  mediaConfig: any;
  rootPath?: string;
  allowedExtensions?: string[];
  onRemove: (file: string) => void;
  onReplace: (newPath: string) => void;
  onPreview: (file: string) => void;
}) => {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging
  } = useSortable({ id: id });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : 1,
    zIndex: isDragging ? 1 : 0,
    position: 'relative' as const
  };

  return (
    <div ref={setNodeRef} style={style} className="aspect-square">
      <div
        {...attributes}
        {...listeners}
        onClick={() => onPreview(file)}
        className="w-full h-full cursor-grab active:cursor-grabbing"
      >
        <Thumbnail name={media} path={file} className="rounded-md w-full h-full object-cover"/>
      </div>
      <ImageTeaser
        file={file}
        media={media}
        mediaConfig={mediaConfig}
        rootPath={rootPath}
        allowedExtensions={allowedExtensions}
        onRemove={onRemove}
        onReplace={onReplace}
      />
    </div>
  );
};

const EditComponent = forwardRef((props: any, ref: React.Ref<HTMLInputElement>) => {
  const { value, field, onChange } = props;
  const { config } = useConfig();
  
  const [files, setFiles] = useState<Array<{ id: string, path: string }>>(() => 
    value
      ? Array.isArray(value)
        ? value.map(path => ({ id: generateId(), path }))
        : [{ id: generateId(), path: value }]
      : []
  );

  const mediaConfig = useMemo(() => {
    return (config?.object?.media?.length && field.options?.media !== false)
      ? field.options?.media && typeof field.options.media === 'string'
        ? getSchemaByName(config.object, field.options.media, "media")
        : config.object.media[0]
      : undefined;
  }, [field.options?.media, config?.object]);

  const rootPath = useMemo(() => {
    if (!field.options?.path) {
      return mediaConfig?.input;
    }

    const normalizedPath = normalizePath(field.options.path);
    const normalizedMediaPath = normalizePath(mediaConfig?.input);

    if (!normalizedPath.startsWith(normalizedMediaPath)) {
      console.warn(`"${field.options.path}" is not within media root "${mediaConfig?.input}". Defaulting to media root.`);
      return mediaConfig?.input;
    }

    return normalizedPath;
  }, [field.options?.path, mediaConfig?.input]);

  const allowedExtensions = useMemo(() => {
    if (!mediaConfig) return [];
    return getAllowedExtensions(field, mediaConfig);
  }, [field, mediaConfig]);

  const isMultiple = useMemo(() => 
    !!field.options?.multiple,
    [field.options?.multiple]
  );

  const remainingSlots = useMemo(() => 
    field.options?.multiple
      ? (typeof field.options.multiple === 'object' && field.options.multiple.max)
        ? field.options.multiple.max - files.length
        : Infinity
      : 1 - files.length,
    [field.options?.multiple, files.length]
  );

  useEffect(() => {
    if (isMultiple) {
      onChange(files.map(f => f.path));
    } else {
      onChange(files[0]?.path ?? "");
    }
  }, [files, isMultiple, onChange]);

  const handleUpload = useCallback((fileData: any) => {
    if (!config) return;
    
    const newFile = { id: generateId(), path: fileData.path };
    
    if (isMultiple) {
      setFiles(prev => [...prev, newFile]);
    } else {
      setFiles([newFile]);
    }
  }, [isMultiple, config]);

  const handleRemove = useCallback((fileId: string) => {
    setFiles(prev => prev.filter(file => file.id !== fileId));
  }, []);

  const handleReplace = useCallback((fileId: string, newPath: string) => {
    setFiles(prev => prev.map(file => file.id === fileId ? { ...file, path: newPath } : file));
  }, []);

  // distance constraint lets plain clicks fall through to the thumbnail's
  // onClick (lightbox) instead of being swallowed as a drag start.
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates,
    })
  );

  const [lightboxPath, setLightboxPath] = useState<string | null>(null);

  const handleDragEnd = (event: any) => {
    const { active, over } = event;

    if (active.id !== over.id) {
      setFiles((items) => {
        const oldIndex = items.findIndex(item => item.id === active.id);
        const newIndex = items.findIndex(item => item.id === over.id);
        return arrayMove(items, oldIndex, newIndex);
      });
    }
  };

  const handleSelected = useCallback((newPaths: string[]) => {
    if (newPaths.length === 0) {
      setFiles([]);
    } else {
      const newFiles = newPaths.map(path => ({
        id: generateId(),
        path
      }));
      
      if (isMultiple) {
        setFiles(prev => [...prev, ...newFiles]);
      } else {
        setFiles([newFiles[0]]);
      }
    }
  }, [isMultiple]);

  if (!mediaConfig) {
    return (
      <p className="text-muted-foreground bg-muted rounded-md px-3 py-2">
      No media configuration found. {' '}
      <a 
        href={`/${config?.owner}/${config?.repo}/${encodeURIComponent(config?.branch || "")}/settings`}
        className="underline hover:text-foreground"
      >
        Check your settings
      </a>.
    </p>
    );
  }

  return (
    <MediaUpload path={rootPath} media={mediaConfig.name} extensions={allowedExtensions || undefined} onUpload={handleUpload} multiple={isMultiple}>
      <MediaUpload.DropZone>
        <div className="space-y-2">
          {files.length > 0 && (
            isMultiple ? (
              <DndContext
                sensors={sensors}
                collisionDetection={closestCenter}
                onDragEnd={handleDragEnd}
              >
                <SortableContext
                  items={files.map(f => f.id)}
                  strategy={rectSortingStrategy}
                >
                  <div className="grid gap-2" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(7rem, 1fr))" }}>
                    {files.map((file) => (
                      <SortableItem
                        key={file.id}
                        id={file.id}
                        file={file.path}
                        media={mediaConfig.name}
                        mediaConfig={mediaConfig}
                        rootPath={rootPath}
                        allowedExtensions={allowedExtensions}
                        onRemove={() => handleRemove(file.id)}
                        onReplace={(newPath) => handleReplace(file.id, newPath)}
                        onPreview={setLightboxPath}
                      />
                    ))}
                  </div>
                </SortableContext>
              </DndContext>
            ) : (
              <div className="aspect-square w-28 relative">
                <button
                  type="button"
                  onClick={() => setLightboxPath(files[0].path)}
                  className="block w-28 h-28 rounded-md overflow-hidden focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background"
                >
                  <Thumbnail name={mediaConfig.name} path={files[0].path} className="rounded-md w-28 h-28"/>
                </button>
                <ImageTeaser
                  file={files[0].path}
                  media={mediaConfig.name}
                  mediaConfig={mediaConfig}
                  rootPath={rootPath}
                  allowedExtensions={allowedExtensions}
                  onRemove={() => handleRemove(files[0].id)}
                  onReplace={(newPath) => handleReplace(files[0].id, newPath)}
                />
              </div>
            )
          )}
          {remainingSlots > 0 && (
            <div className="flex gap-2">
              <MediaUpload.Trigger>
                <Button type="button" size="sm" variant="outline" className="gap-2">
                  <Upload className="h-3.5 w-3.5"/>
                  {isMultiple && files.length > 0 ? "Add more" : "Upload"}
                </Button>
              </MediaUpload.Trigger>
              <TooltipProvider>
                <Tooltip>
                  <MediaDialog
                    media={mediaConfig.name}
                    initialPath={rootPath}
                    maxSelected={remainingSlots === Infinity ? undefined : remainingSlots}
                    extensions={allowedExtensions}
                    onSubmit={handleSelected}
                  >
                    <TooltipTrigger asChild>
                      <Button type="button" size="icon-sm" variant="outline">
                        <FolderOpen className="h-3.5 w-3.5"/>
                      </Button>
                    </TooltipTrigger>
                  </MediaDialog>
                  <TooltipContent>
                    {isMultiple ? "Select from media library" : "Select from media"}
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            </div>
          )}
        </div>
      </MediaUpload.DropZone>
      <MediaLightbox
        open={lightboxPath !== null}
        onOpenChange={(open) => { if (!open) setLightboxPath(null); }}
        name={mediaConfig.name}
        path={lightboxPath}
      />
    </MediaUpload>
  );
});

EditComponent.displayName = "EditComponent";

export { EditComponent };