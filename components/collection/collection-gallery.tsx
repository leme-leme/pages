"use client";

import { Fragment, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import {
  DndContext,
  KeyboardSensor,
  PointerSensor,
  closestCenter,
  useSensor,
  useSensors,
  type DragEndEvent,
} from "@dnd-kit/core";
import {
  SortableContext,
  arrayMove,
  rectSortingStrategy,
  sortableKeyboardCoordinates,
  useSortable,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { GripVertical, Loader, Save, Undo2 } from "lucide-react";
import { Thumbnail } from "@/components/thumbnail";
import { FileOptions } from "@/components/file/file-options";
import { Button, buttonVariants } from "@/components/ui/button";
import { useConfig } from "@/contexts/config-context";
import { useRepo } from "@/contexts/repo-context";
import { safeAccess, getFieldByPath } from "@/lib/schema";
import { requireApiSuccess } from "@/lib/api-client";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

type Item = {
  path: string;
  name: string;
  sha: string;
  type: "file" | "dir";
  fields?: Record<string, any>;
};

type CollectionGalleryProps = {
  data: Item[];
  schema: any;
  name: string;
  primaryField: string;
  canDelete: boolean;
  canRename: boolean;
  onDelete: (path: string) => void;
  onRename: (path: string, newPath: string) => void;
};

const isImageField = (field: any) =>
  field?.type === "image" || (field?.type === "string" && field?.options?.media);

const findImageFieldName = (fields: any[] | undefined): string | null => {
  if (!fields) return null;
  for (const f of fields) {
    if (isImageField(f)) return f.name;
  }
  return null;
};

const resolveImageValue = (value: unknown): string | null => {
  if (!value) return null;
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    const first = value.find((v) => typeof v === "string" && v);
    return typeof first === "string" ? first : null;
  }
  return null;
};

function GalleryCard({
  item,
  schema,
  name,
  primaryField,
  imageFieldName,
  canDelete,
  canRename,
  onDelete,
  onRename,
  dragHandle,
  isDragging,
}: {
  item: Item;
  schema: any;
  name: string;
  primaryField: string;
  imageFieldName: string | null;
  canDelete: boolean;
  canRename: boolean;
  onDelete: (path: string) => void;
  onRename: (path: string, newPath: string) => void;
  dragHandle?: ReactNode;
  isDragging?: boolean;
}) {
  const { config } = useConfig();
  if (!config) return null;
  const label = String(safeAccess(item.fields ?? {}, primaryField) ?? item.name);
  const imageRaw = imageFieldName ? safeAccess(item.fields ?? {}, imageFieldName) : null;
  const imagePath = resolveImageValue(imageRaw);
  const imageField = imageFieldName ? getFieldByPath(schema.fields, imageFieldName) : null;
  const mediaName: string | undefined =
    typeof imageField?.options?.media === "string" ? imageField.options.media : undefined;

  return (
    <div
      className={cn(
        "group relative border rounded-md overflow-hidden bg-background flex flex-col",
        isDragging && "opacity-50",
      )}
    >
      <div className="relative aspect-[4/3] bg-muted overflow-hidden">
        <Link
          href={`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}/edit/${encodeURIComponent(item.path)}`}
          prefetch
          className="block w-full h-full"
        >
          {imagePath ? (
            <Thumbnail name={mediaName ?? ""} path={imagePath} className="w-full h-full object-cover" />
          ) : (
            <div className="w-full h-full flex items-center justify-center text-muted-foreground text-xs">
              No image
            </div>
          )}
        </Link>
        {dragHandle}
      </div>
      <div className="flex items-center gap-1 px-2 py-1.5 min-w-0">
        <span className="text-sm font-medium truncate flex-1 min-w-0">{label}</span>
        <div className="flex gap-1 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
          <Link
            className={cn(buttonVariants({ variant: "outline", size: "sm" }), "h-7 text-xs")}
            href={`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}/edit/${encodeURIComponent(item.path)}`}
            prefetch
          >
            Edit
          </Link>
          <FileOptions
            path={item.path}
            sha={item.sha}
            type="collection"
            name={name}
            canDelete={canDelete}
            canRename={canRename}
            onDelete={onDelete}
            onRename={onRename}
          >
            <Button variant="outline" size="icon-sm" className="w-7 h-7">
              <span aria-hidden>⋯</span>
            </Button>
          </FileOptions>
        </div>
      </div>
    </div>
  );
}

function SortableGalleryCard(props: {
  item: Item;
  schema: any;
  name: string;
  primaryField: string;
  imageFieldName: string | null;
  canDelete: boolean;
  canRename: boolean;
  onDelete: (path: string) => void;
  onRename: (path: string, newPath: string) => void;
}) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: props.item.path });
  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    zIndex: isDragging ? 10 : 0,
  } as const;

  return (
    <div ref={setNodeRef} style={style}>
      <GalleryCard
        {...props}
        isDragging={isDragging}
        dragHandle={
          <button
            type="button"
            className="absolute top-1.5 left-1.5 bg-background/80 backdrop-blur-sm rounded-md p-1 cursor-grab active:cursor-grabbing"
            {...attributes}
            {...listeners}
            aria-label="Drag to reorder"
          >
            <GripVertical className="h-3.5 w-3.5 text-muted-foreground" />
          </button>
        }
      />
    </div>
  );
}

export function CollectionGallery({
  data,
  schema,
  name,
  primaryField,
  canDelete,
  canRename,
  onDelete,
  onRename,
}: CollectionGalleryProps) {
  const { config } = useConfig();
  const repo = useRepo();
  const sortField: string | undefined = schema.view?.default?.sort;
  const hasFrontmatterSort = !!(sortField && schema.fields?.some((f: any) => f.name === sortField));
  const imageFieldName = useMemo(() => {
    if (typeof schema.view?.image === "string") return schema.view.image;
    return findImageFieldName(schema.fields);
  }, [schema]);

  const initialOrder = useMemo(() => data.filter((d) => d.type === "file").map((d) => d.path), [data]);
  const [order, setOrder] = useState<string[]>(initialOrder);
  const [isReordering, setIsReordering] = useState(false);
  const [isSaving, setIsSaving] = useState(false);

  // Reset local order when underlying data changes
  useMemo(() => setOrder(initialOrder), [initialOrder.join("")]);

  const itemsByPath = useMemo(() => {
    const map = new Map<string, Item>();
    for (const item of data) map.set(item.path, item);
    return map;
  }, [data]);

  const folders = data.filter((d) => d.type === "dir");
  const orderedFiles = order.map((p) => itemsByPath.get(p)).filter((x): x is Item => Boolean(x));
  const isDirty = orderedFiles.some((item, idx) => initialOrder[idx] !== item.path);

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event;
    if (!over || active.id === over.id) return;
    setOrder((prev) => {
      const oldIndex = prev.indexOf(String(active.id));
      const newIndex = prev.indexOf(String(over.id));
      if (oldIndex < 0 || newIndex < 0) return prev;
      return arrayMove(prev, oldIndex, newIndex);
    });
  };

  const handleResetOrder = () => setOrder(initialOrder);

  const handleSaveOrder = async () => {
    if (!hasFrontmatterSort || !sortField || !config) return;
    setIsSaving(true);
    try {
      const updates = orderedFiles.map((item, idx) => ({
        path: item.path,
        content: { ...(item.fields ?? {}), [sortField]: idx + 1 },
      }));

      const response = await fetch(
        `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/files-batch`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name,
            message: `Reorder ${name} (via Pages CMS)`,
            updates,
          }),
        },
      );
      const result = await requireApiSuccess<any>(response, "Reorder failed");
      toast.success(result.message ?? "Order saved.");
      setIsReordering(false);
    } catch (err: any) {
      toast.error(err?.message ?? "Reorder failed");
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      {hasFrontmatterSort && (
        <div className="flex items-center justify-end gap-2">
          {isReordering ? (
            <>
              {isDirty && (
                <Button variant="outline" size="sm" onClick={handleResetOrder} disabled={isSaving}>
                  <Undo2 className="h-3.5 w-3.5" /> Reset
                </Button>
              )}
              <Button size="sm" onClick={handleSaveOrder} disabled={!isDirty || isSaving}>
                {isSaving ? <Loader className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
                {isSaving ? "Saving" : "Save order"}
              </Button>
              <Button variant="ghost" size="sm" onClick={() => { setIsReordering(false); setOrder(initialOrder); }} disabled={isSaving}>
                Cancel
              </Button>
            </>
          ) : (
            <Button variant="outline" size="sm" onClick={() => setIsReordering(true)}>
              <GripVertical className="h-3.5 w-3.5" /> Reorder
            </Button>
          )}
        </div>
      )}

      {folders.length > 0 && (
        <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(10rem, 1fr))" }}>
          {folders.map((item) => (
            <Link
              key={item.path}
              href={`/${config?.owner}/${config?.repo}/${encodeURIComponent(config?.branch ?? "")}/collection/${encodeURIComponent(name)}?path=${encodeURIComponent(item.path)}`}
              className="border rounded-md p-3 text-sm hover:bg-muted truncate"
            >
              {item.name}/
            </Link>
          ))}
        </div>
      )}

      {isReordering ? (
        <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
          <SortableContext items={orderedFiles.map((f) => f.path)} strategy={rectSortingStrategy}>
            <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(12rem, 1fr))" }}>
              {orderedFiles.map((item) => (
                <SortableGalleryCard
                  key={item.path}
                  item={item}
                  schema={schema}
                  name={name}
                  primaryField={primaryField}
                  imageFieldName={imageFieldName}
                  canDelete={canDelete}
                  canRename={canRename}
                  onDelete={onDelete}
                  onRename={onRename}
                />
              ))}
            </div>
          </SortableContext>
        </DndContext>
      ) : (
        <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(12rem, 1fr))" }}>
          {orderedFiles.map((item) => (
            <Fragment key={item.path}>
              <GalleryCard
                item={item}
                schema={schema}
                name={name}
                primaryField={primaryField}
                imageFieldName={imageFieldName}
                canDelete={canDelete}
                canRename={canRename}
                onDelete={onDelete}
                onRename={onRename}
              />
            </Fragment>
          ))}
        </div>
      )}
    </div>
  );
}
