"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useConfig } from "@/contexts/config-context";
import {
  getParentPath,
  getFileName,
  normalizePath,
  sortFiles
} from "@/lib/utils/file";
import { viewComponents } from "@/fields/registry";
import { getSchemaByName, getPrimaryField, getFieldByPath, safeAccess } from "@/lib/schema";
import { EmptyCreate } from "@/components/empty-create";
import { FileOptions } from "@/components/file/file-options";
import { CollectionTable } from "./collection-table";
import { FolderCreate} from "@/components/folder-create";
import { Message } from "@/components/message";
import { PathBreadcrumb } from "@/components/path-breadcrumb";
import { Button, buttonVariants } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  CornerLeftUp,
  Ellipsis,
  FolderPlus,
  GripVertical,
  Loader,
  Plus,
  Search
} from "lucide-react";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
} from "@dnd-kit/core";
import {
  arrayMove,
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { restrictToVerticalAxis } from "@dnd-kit/modifiers";
import { CSS } from "@dnd-kit/utilities";

// Sortable row for drag-to-reorder mode
function SortableReorderRow({ item, primaryField }: { item: Record<string, any>; primaryField: string }) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: item.path });
  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : 1,
  };
  const label = safeAccess(item.fields, primaryField) ?? item.name;
  return (
    <div
      ref={setNodeRef}
      style={style}
      className="flex items-center gap-3 px-3 py-2.5 border-b last:border-b-0 bg-background"
    >
      <button
        type="button"
        {...attributes}
        {...listeners}
        className="cursor-grab active:cursor-grabbing text-muted-foreground hover:text-foreground shrink-0"
        tabIndex={-1}
      >
        <GripVertical className="h-4 w-4" />
      </button>
      <span className="truncate text-sm">{String(label)}</span>
      <span className="ml-auto text-xs text-muted-foreground shrink-0">{item.name}</span>
    </div>
  );
}

export function CollectionView({
  name,
  path,
}: {
  name: string;
  path?: string;
}) {
  const [search, setSearch] = useState("");
  const [data, setData] = useState<Record<string, any>[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isReordering, setIsReordering] = useState(false);
  const [reorderData, setReorderData] = useState<Record<string, any>[]>([]);
  const [orderSha, setOrderSha] = useState<string | null>(null);
  const [isSavingOrder, setIsSavingOrder] = useState(false);

  const searchParams = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();

  const { config } = useConfig();
  if (!config) throw new Error(`Configuration not found.`);

  const schema = useMemo(() => getSchemaByName(config?.object, name), [config, name]);
  if (!schema) throw new Error(`Schema not found for "${name}".`);
  if (schema.type !== "collection") throw new Error(`"${name}" is not a collection.`);

  const viewFields = useMemo(() => {
    let pathAndFieldArray: any[] = [];
    if (schema.fields) {
      if (schema.view?.fields && schema.view?.fields.length > 0) {
        // If we have a list of fields defined for the view
        schema.view.fields.forEach((path: string) => {
          const field = getFieldByPath(schema.fields, path);
          if (field && !['object', 'block'].includes(field.type)) pathAndFieldArray.push({ path: path, field: field });
        });
      } else {
        pathAndFieldArray = schema.fields
          .filter((field: any) => !['object', 'block'].includes(field.type) && !field.hidden)
          .map((field: any) => ({ path: field.name, field: field }));
      }
    } else {
      pathAndFieldArray.push({
        path: "name",
        field: {
          label: "Name",
          name: "name",
          type: "string"
        }
      });
    }

    // If the filename starts with {year}-{month}-{day} and date is listed in the
    // view fields and is not an actual field, or if there are no fields, we add a date field
    if (
      !pathAndFieldArray.find((item: any) => item.path === "date")
      && schema.filename.startsWith("{year}-{month}-{day}")
      && !schema.filenameIsDefault
      && (
        (schema.view?.fields && schema.view?.fields.includes("date"))
        || !schema.view?.fields
      )
    ) {
      pathAndFieldArray.push({
        path: "date",
        field: {
          label: "Date",
          name: "date",
          type: "date"
        }
      });
    }

    return pathAndFieldArray;
  }, [schema]);

  const primaryField = useMemo(() => getPrimaryField(schema) ?? "name", [schema]);

  // Detect whether this collection has a date field (if so, skip drag-to-reorder feature)
  const hasDateField = useMemo(() =>
    viewFields.some((vf: any) => vf.field.type === 'date' || vf.field.name === 'date'),
    [viewFields]
  );

  const dndSensors = useSensors(
    useSensor(PointerSensor),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  );

  const fetchCollectionData = useCallback(async (fetchPath: string): Promise<Record<string, any>[] | undefined> => {
    if (!config) return undefined;

    try {
      const apiUrl = `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collections/${encodeURIComponent(name)}?path=${encodeURIComponent(fetchPath)}`;
      
      const response = await fetch(apiUrl);
      if (!response.ok) {
        if(response.status === 404 && fetchPath === (path || schema.path)) {
          throw new Error("Not found");
        }
        throw new Error(`API Error ${response.status}`);
      }

      const result = await response.json();
      if (result.status !== 'success') {
        throw new Error(result.message || 'Fetch failed');
      }

      if (result.data.errors?.length) {
        result.data.errors.forEach((e: any) => toast.error(e));
      }

      const unsortedData = result.data.contents || [];
      
      if (unsortedData.length === 0) return [];
      return unsortedData.sort((a: any, b: any) => {
        if (a.type === "dir" && b.type === "file") return schema.view?.foldersFirst ? -1 : 1;
        if (a.type === "file" && b.type === "dir") return schema.view?.foldersFirst ? 1 : -1;
        return a.name.localeCompare(b.name);
      });

    } catch (err: any) {
      console.error(`Fetch failed for path ${fetchPath}:`, err);
      if (fetchPath === (path || schema.path)) {
        setError(err.message);
      } else {
        toast.error(`Could not load items inside ${getFileName(fetchPath)}: ${err.message}`);
      }
      return undefined;
    }
  }, [config, name, path, schema.path, schema.view?.foldersFirst]);

  const handleDelete = useCallback((path: string) => {
    setData((prevData) => prevData?.filter((item: any) => item.path !== path));
  }, []);

  const handleRename = useCallback((path: string, newPath: string) => {
    setData((prevData: any) => {
      if (!prevData) return prevData;
      
      const updateNestedData = (items: any[]): any[] => {
        return items.map((item: any) => {
          // If this is the item being renamed
          if (item.path === path) {
            return { ...item, path: newPath, name: getFileName(newPath) };
          }
          
          // If this item has subRows, recursively update them
          if (item.subRows && Array.isArray(item.subRows)) {
            const updatedSubRows = updateNestedData(item.subRows);
            // Only create a new item reference if subRows changed
            if (updatedSubRows !== item.subRows) {
              return { ...item, subRows: updatedSubRows };
            }
          }
          
          // Return the original item if no changes
          return item;
        });
      };
      
      // Check if the item is moving to a different folder
      if (getParentPath(normalizePath(path)) !== getParentPath(normalizePath(newPath))) {
        // For items moved to a different folder, we need to:
        // 1. Remove the item from its original location (recursively)
        const removeItem = (items: any[]): any[] => {
          return items.filter(item => {
            if (item.path === path) return false;
            if (item.subRows && Array.isArray(item.subRows)) {
              item.subRows = removeItem(item.subRows);
            }
            return true;
          });
        };
        
        return sortFiles(removeItem(prevData));
      }
      
      // For items renamed within the same folder, update the item
      return sortFiles(updateNestedData(prevData));
    });
  }, []);

  const handleFolderCreate = useCallback((entry: any) => {
    const parentPath = getParentPath(entry.path);
    const parent = {
      type: "dir",
      name: getFileName(parentPath),
      path: parentPath,
      size: 0,
      url: null,
    }
    
    setData((prevData) => {
      if (!prevData) return [parent];
      return sortFiles([...prevData, parent]);
    });
  }, []);

  const handleConfirmRenameNode = useCallback((path: string, newPath: string) => {
    try {
      const normalizedPath = normalizePath(path);
      const normalizedNewPath = normalizePath(newPath);
      
      const renamePromise = new Promise(async (resolve, reject) => {
        try {
          const response = await fetch(`/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/files/${encodeURIComponent(normalizedPath)}/rename`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              type: "content",
              name,
              newPath: normalizedNewPath,
            }),
          });
          if (!response.ok) throw new Error(`Failed to rename file: ${response.status} ${response.statusText}`);

          const data: any = await response.json();
          if (data.status !== "success") throw new Error(data.message);

          resolve(data);
        } catch (error) {
          reject(error);
        }
      });

      toast.promise(renamePromise, {
        loading: `Renaming "${path}" to "${newPath}"`,
        success: (data: any) => {
          router.push(`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}/new?parent=${encodeURIComponent(getParentPath(normalizedNewPath))}`);
          return data.message;
        },
        error: (error: any) => error.message,
      });
    } catch (error) {
      console.error(error);
    }
  }, [config.owner, config.repo, config.branch, name, router]);

  const columns = useMemo(() => {
    let tableColumns: any;
    tableColumns = viewFields.map((pathAndField: any) => {
      const path = pathAndField.path;
      const field = pathAndField.field;
      if (!field) return null;
      
      return {
        accessorKey: path,
        accessorFn: (originalRow: any) => safeAccess(originalRow.fields, path),
        header: field?.label ?? field.name,
        meta: { className: field.name === primaryField ? "truncate w-full min-w-[12rem] max-w-[1px]" : "" },
        cell: ({ cell, row }: { cell: any, row: any }) => {
          const cellValue = cell.getValue();
          const FieldComponent = viewComponents?.[field.type];
          const CellView = FieldComponent 
            ? <FieldComponent value={cellValue} field={field}/>
            : Array.isArray(cellValue)
              ? cellValue.join(', ')
              : cellValue;
          if (field.name === primaryField) {
            return (
              <Link
                className="font-medium truncate"
                href={`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}/edit/${encodeURIComponent(row.original.path)}`}
                prefetch={true}
              >
                {CellView}
              </Link>
            );
          }
          return (
            <div className="truncate w-full max-w-[12rem]">
              {CellView}
            </div>
          );
        },
        sortUndefined: schema.view?.foldersFirst ? "first" : "last"
      };
    }) || [];

    tableColumns.push({
      accessorKey: "actions",
      header: "",
      meta: { className: "sticky right-0 bg-background [tr:hover_&]:bg-muted/50 shadow-[inset_4px_0_6px_-4px_rgba(0,0,0,0.06)]" },
      cell: ({ row }: { row: any }) => (
        <div className="flex gap-1 justify-end">
          {row.original.type === 'file' &&
            <>
              <Link
                className={cn(buttonVariants({ variant: "outline", size: "sm" }), "h-8")}
                href={`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${name}/edit/${encodeURIComponent(row.original.path)}`}
                prefetch={true}
              >
                Edit
              </Link>
              <FileOptions path={row.original.path} sha={row.original.sha} type="collection" name={name} onDelete={handleDelete} onRename={handleRename}>
                <Button variant="outline" size="icon-sm" className="w-8 h-8">
                  <Ellipsis className="h-4 w-4" />
                </Button>
              </FileOptions>
            </>
          }
          {schema.view?.layout === 'tree' && (
            row.original.type === 'file' &&
            !row.original.isNode &&
            !(row.depth === 0 && row.original.name === schema.view?.node?.filename)
              ? <AlertDialog>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <AlertDialogTrigger asChild>
                        <Button variant="outline" size="icon-sm" className="w-8 h-8">
                          <Plus className="h-4 w-4" />
                        </Button>
                      </AlertDialogTrigger>
                    </TooltipTrigger>
                    <TooltipContent>Add children entry</TooltipContent>
                  </Tooltip>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>Rename this file first?</AlertDialogTitle>
                      <AlertDialogDescription>
                        Before adding children to this file, you must rename it from &quot;{row.original.path}&quot; to 
                        &quot;{row.original.path.replace(`.${schema.extension}`, `/${schema.view?.node?.filename}`)}&quot;.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction onClick={() => handleConfirmRenameNode(row.original.path, row.original.path.replace(`.${schema.extension}`, `/${schema.view?.node?.filename}`))}>Rename</AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              :  <Tooltip>
                  <TooltipTrigger asChild>
                    <Link
                      className={cn(buttonVariants({ variant: "outline", size: "icon-sm" }), "w-8 h-8")}
                      href={row.original.isNode
                        ? `/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}/new?parent=${encodeURIComponent(row.original.parentPath)}`
                        : row.original.type === 'dir'
                          ? `/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}/new?parent=${encodeURIComponent(row.original.path)}`
                          : `/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}/new?parent=${encodeURIComponent(row.original.path)}`
                      }
                      prefetch={true}
                    >
                      <Plus className="h-4 w-4" />
                    </Link>
                  </TooltipTrigger>
                  <TooltipContent>
                    Add children entry
                  </TooltipContent>
                </Tooltip>
          )}
        </div>
      ),
      enableSorting: false
    });

    return tableColumns;
  }, [config.owner, config.repo, config.branch, name, viewFields, primaryField, handleDelete, handleRename, schema.view?.foldersFirst, schema.view?.layout, schema.view?.node?.filename, schema.extension, handleConfirmRenameNode]);

  const initialState = useMemo(() => {
    const sortId = viewFields == null
      ? "name"
      : (
          schema.view?.default?.sort
          || (viewFields.find((item: any) => item.field.name === "date") && "date")
          || primaryField
        );

    return {
      sorting: [{
        id: sortId,
        desc: sortId === "date"
          ? true
          : schema.view?.default?.order === "desc"
            ? true
            : false,
      }],
      pagination: {
        pageSize: 25,
      },
    };
  }, [schema, primaryField, viewFields]);

  // Load _order.json and apply sort order to fetched data
  const applyOrder = useCallback(async (fetchedData: Record<string, any>[], collectionPath: string) => {
    if (!config || hasDateField) return fetchedData;
    try {
      const orderPath = `${collectionPath.replace(/\/$/, "")}/_order.json`;
      const res = await fetch(`/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/files/${encodeURIComponent(orderPath)}`);
      const json = await res.json();
      if (json.status === "success" && json.data.sha) {
        setOrderSha(json.data.sha);
        const order: string[] = JSON.parse(json.data.content);
        if (Array.isArray(order)) {
          const map = new Map(fetchedData.map((d: any) => [d.name, d]));
          const sorted: Record<string, any>[] = [];
          order.forEach(name => { if (map.has(name)) sorted.push(map.get(name)!); });
          fetchedData.forEach(d => { if (!order.includes(d.name)) sorted.push(d); });
          return sorted;
        }
      }
    } catch {
      // _order.json not found or invalid — ignore
    }
    return fetchedData;
  }, [config, hasDateField]);

  useEffect(() => {
    const currentPath = schema.view?.layout === 'tree'
      ? schema.path
      : path || schema.path;
    let isMounted = true;

    setIsLoading(true);
    setError(null);
    setIsReordering(false);

    fetchCollectionData(currentPath)
      .then(async fetchedData => {
        if (isMounted && fetchedData) {
          const ordered = await applyOrder(fetchedData, currentPath);
          if (isMounted) setData(ordered);
        }
      })
      .finally(() => {
        if (isMounted) {
          setIsLoading(false);
        }
      });

    return () => { isMounted = false };
  }, [fetchCollectionData, applyOrder, path, schema.path, schema.view?.layout]);

  const handleSaveOrder = useCallback(async () => {
    if (!config) return;
    const collectionPath = path || schema.path;
    const orderPath = `${collectionPath.replace(/\/$/, "")}/_order.json`;
    setIsSavingOrder(true);
    try {
      const res = await fetch(`/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/files/${encodeURIComponent(orderPath)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "raw", content: reorderData.map((d: any) => d.name), sha: orderSha ?? undefined }),
      });
      const json = await res.json();
      if (json.status !== "success") throw new Error(json.message);
      setOrderSha(json.data.sha ?? null);
      setData(reorderData);
      setIsReordering(false);
      toast.success("Order saved.");
    } catch (err: any) {
      toast.error(`Failed to save order: ${err.message}`);
    } finally {
      setIsSavingOrder(false);
    }
  }, [config, path, schema.path, reorderData, orderSha]);

  const handleNavigate = (newPath: string) => {
    // setPath(newPath);
    // Optionally update the URL to reflect the state
    const params = new URLSearchParams(Array.from(searchParams.entries()));
    params.set("path", newPath || schema.path);
    router.push(`${pathname}?${params.toString()}`);
  }

  const handleNavigateParent = () => {
    if (!path || path === schema.path) return;
    handleNavigate(getParentPath(path));
  }

  const handleExpand = useCallback(async (row: any) => {
    if (!row) return;
    const subRows = await fetchCollectionData(row.isNode ? row.parentPath : row.path);
    if (subRows !== undefined) {
      setData((currentData: any[]) => {
        const updateNestedData = (items: any[]): any[] => {
          return items.map((item: any) => {
            if (item.path === row.path) return { ...item, subRows };
            if (item.subRows && Array.isArray(item.subRows)) {
              const updatedSubRows = updateNestedData(item.subRows);
              if (updatedSubRows !== item.subRows) {
                return { ...item, subRows: updatedSubRows };
              }
            }
            return item;
          });
        };
        
        return updateNestedData(currentData);
      });
    }
  }, [fetchCollectionData]);

  const loadingSkeleton = useMemo(() => (
    <table className="w-full">
      <thead>
        <tr className="border-b">
          <th className="pr-3 align-middle h-12">
            <Skeleton className="w-8 h-4 rounded" />
          </th>
          <th className="px-3 align-middle h-12">
            <Skeleton className="w-16 h-4 rounded" />
          </th>
          <th className="px-3 align-middle h-12">
            <Skeleton className="w-12 h-4 rounded" />
          </th>
          <th className="pl-3 align-middle h-12">
            <Skeleton className="w-12 h-4 rounded" />
          </th>
        </tr>
      </thead>
      <tbody>
        {[...Array(5)].map((_, index) => (
          <tr className="border-b" key={index}>
            <td className="pr-3 pl-0 align-middle h-14">
              <Skeleton className="h-8 w-8 rounded-md" />
            </td>
            <td className="px-3 align-middle w-full min-w-[12rem] max-w-[1px] h-14">
              <Skeleton className="w-full h-5 rounded" />
            </td>
            <td className="px-3 align-middle h-14">
              <Skeleton className="w-24 h-5 rounded" />
            </td>
            <td className="pl-3 pr-0 align-middle h-14">
              <div className="flex gap-1">
                <Button variant="outline" size="sm" className="h-8" disabled>Edit</Button>
                <Button variant="outline" size="icon-sm" className="w-8 h-8" disabled>
                  <Ellipsis className="h-4 w-4" />
                </Button>
                {schema.view?.layout === 'tree' && (
                  <Button variant="outline" size="icon-sm" className="w-8 h-8" disabled>
                    <Plus className="h-4 w-4" />
                  </Button>
                )}
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  ), [schema.view?.layout]);
  
  if (error) {
    if (error === "Not found") {
      return (
        <Message
            title="Folder missing"
            description={`The collection folder "${schema.path}" has not been created yet.`}
            className="absolute inset-0"
          >
          <EmptyCreate type="content" name={schema.name}>Create folder</EmptyCreate>
        </Message>
      );
    } else {
      <Message
        title="Something's wrong"
        description={error}
        className="absolute inset-0"
        cta="Go to settings"
        href={`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/settings`}
      />
    }
  }

  return (
    <>
      <div className="flex-1 flex flex-col space-y-6">
        <header className="flex items-center gap-x-2">
          <div className="sm:flex-1">
            {schema.view?.layout !== 'tree' && (
              <>
                <PathBreadcrumb path={path || schema.path} rootPath={schema.path} handleNavigate={handleNavigate} className="hidden sm:block"/>
                <Button onClick={handleNavigateParent} size="icon-sm" variant="outline" className="shrink-0 sm:hidden" disabled={!path || path === schema.path}>
                  <CornerLeftUp className="w-4 h-4"/>
                </Button>
              </>
            )}
          </div>
          <div className="relative flex-1">
            <Search className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 opacity-50 pointer-events-none"/>
            <Input className="h-9 pl-9" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          {schema.subfolders !== false && !isReordering && (
            <FolderCreate path={path || schema.path} type="content" name={name} onCreate={handleFolderCreate}>
              <Button type="button" variant="outline" className="ml-auto shrink-0" size="icon-sm">
                <FolderPlus className="h-3.5 w-3.5"/>
              </Button>
            </FolderCreate>
          )}
          {!hasDateField && schema.view?.layout !== 'tree' && !isLoading && (
            isReordering ? (
              <>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setIsReordering(false)}
                  disabled={isSavingOrder}
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  size="sm"
                  onClick={handleSaveOrder}
                  disabled={isSavingOrder}
                >
                  {isSavingOrder ? <Loader className="h-3.5 w-3.5 animate-spin mr-1.5" /> : null}
                  Save order
                </Button>
              </>
            ) : (
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      type="button"
                      variant="outline"
                      size="icon-sm"
                      onClick={() => { setReorderData([...data]); setIsReordering(true); }}
                    >
                      <GripVertical className="h-3.5 w-3.5" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Reorder entries</TooltipContent>
                </Tooltip>
              </TooltipProvider>
            )
          )}
          {!isReordering && (
            <>
              <Link
                className={cn(buttonVariants({size: "sm"}), "hidden sm:flex")}
                href={`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}/new${schema.view?.layout !== 'tree' && path && path !== schema.path ? `?parent=${encodeURIComponent(path)}` : ""}`}
              >
                  Add an entry
              </Link>
              <Link
                className={cn(buttonVariants({size: "icon-sm"}), "sm:hidden shrink-0")}
                href={`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/collection/${encodeURIComponent(name)}/new${schema.view?.layout !== 'tree' && path && path !== schema.path ? `?parent=${encodeURIComponent(path)}` : ""}`}
              >
                  <Plus className="h-4 w-4"/>
              </Link>
            </>
          )}
        </header>
        {isLoading
          ? loadingSkeleton
          : isReordering
            ? (
              <DndContext
                sensors={dndSensors}
                collisionDetection={closestCenter}
                modifiers={[restrictToVerticalAxis]}
                onDragEnd={(event) => {
                  const { active, over } = event;
                  if (over && active.id !== over.id) {
                    setReorderData(items => {
                      const oldIndex = items.findIndex(i => i.path === active.id);
                      const newIndex = items.findIndex(i => i.path === over.id);
                      return arrayMove(items, oldIndex, newIndex);
                    });
                  }
                }}
              >
                <SortableContext items={reorderData.map(d => d.path)} strategy={verticalListSortingStrategy}>
                  <div className="border rounded-md overflow-hidden">
                    {reorderData.filter((d: any) => d.type !== 'dir').map(item => (
                      <SortableReorderRow key={item.path} item={item} primaryField={primaryField} />
                    ))}
                  </div>
                </SortableContext>
              </DndContext>
            )
            : <CollectionTable
                columns={columns}
                data={data}
                search={search}
                setSearch={setSearch}
                initialState={initialState}
                onExpand={handleExpand}
                pathname={pathname}
                path={path || schema.path}
                isTree={schema.view?.layout === 'tree'}
                primaryField={primaryField}
              />
        }
      </div>
    </>
  );
}