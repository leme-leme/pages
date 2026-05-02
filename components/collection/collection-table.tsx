"use client"

import { useEffect, useMemo, useState, useCallback, useRef } from "react";
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  getExpandedRowModel,
  useReactTable,
  RowData,
  ExpandedState,
  Row
} from "@tanstack/react-table"
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
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { restrictToVerticalAxis } from "@dnd-kit/modifiers";
import { CSS } from "@dnd-kit/utilities";
import { Button } from "@/components/ui/button";
import {
  Pagination,
  PaginationContent,
  PaginationEllipsis,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import Link from "next/link";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { ArrowUp, ArrowDown, GripVertical, Loader, CircleMinus, CirclePlus, Folder, FolderOpen, Save, Undo2 } from "lucide-react";

declare module '@tanstack/react-table' {
  interface ColumnMeta<TData extends RowData, TValue> {
    className?: string;
  }
}

export type TableData = {
  name: string;
  path: string;
  sha?: string;
  content?: string;
  object?: Record<string, any>;
  type: "file" | "dir";
  isNode?: boolean;
  parentPath?: string;
  subRows?: TableData[];
  fields?: Record<string, any>;
}

function SortableTableRow({
  id,
  visibleCells,
  primaryField,
}: {
  id: string;
  visibleCells: any[];
  primaryField?: string;
}) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id });
  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : 1,
    zIndex: isDragging ? 10 : 0,
  } as const;

  return (
    <TableRow ref={setNodeRef as any} style={style}>
      <TableCell className="p-2 border-b py-0 h-12 w-8">
        <button
          type="button"
          className="cursor-grab active:cursor-grabbing text-muted-foreground hover:text-foreground"
          aria-label="Drag to reorder"
          {...attributes}
          {...listeners}
        >
          <GripVertical className="h-4 w-4" />
        </button>
      </TableCell>
      {visibleCells.map((cell: any) => (
        <TableCell
          key={cell.id}
          className={cn("p-2 border-b py-0 h-12", cell.column.columnDef.meta?.className)}
        >
          {flexRender(cell.column.columnDef.cell, cell.getContext())}
        </TableCell>
      ))}
    </TableRow>
  );
}

const LShapeIcon = ({ className }: { className?: string }) => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" className={className}>
    <path d="M4 4V11C4 12.0609 4.42143 13.0783 5.17157 13.8284C5.92172 14.5786 6.93913 15 8 15H20" 
      stroke="currentColor" 
      strokeWidth="2" 
      strokeLinecap="round" 
      strokeLinejoin="round"/>
  </svg>
);

export function CollectionTable<TData extends TableData>({
  columns,
  data,
  initialState,
  search,
  setSearch,
  onExpand,
  pathname,
  path,
  isTree = false,
  primaryField,
  reorderable = false,
  onReorder,
}: {
  columns: any[],
  data: Record<string, any>[],
  initialState?: Record<string, any>,
  search: string,
  setSearch: (value: string) => void,
  onExpand: (row: any) => Promise<any>,
  pathname: string,
  path: string,
  isTree?: boolean,
  primaryField?: string,
  /** When true, render a Reorder toggle that puts the table into a sortable mode. */
  reorderable?: boolean,
  /** Called with the new file order (paths) when the user saves. */
  onReorder?: (orderedPaths: string[]) => Promise<void>,
}) {
  const [expanded, setExpanded] = useState<ExpandedState>({});

  // Reorder mode (only meaningful when reorderable === true).
  const initialFilePaths = useMemo(
    () => data.filter((d) => d.type === "file").map((d) => d.path as string),
    [data],
  );
  const [isReordering, setIsReordering] = useState(false);
  const [orderPaths, setOrderPaths] = useState<string[]>(initialFilePaths);
  const [isSavingOrder, setIsSavingOrder] = useState(false);

  // Reset local order when underlying data changes (e.g. after a save).
  useEffect(() => {
    setOrderPaths(initialFilePaths);
  }, [initialFilePaths.join("")]);

  const [loadingRows, setLoadingRows] = useState<Record<string, boolean>>({});
  const loadingPathSetRef = useRef<Set<string>>(new Set());

  const handleRowExpansion = useCallback(async (row: Row<TData>) => {
    const needsLoading = row.getCanExpand() && !row.getIsExpanded() && row.original.subRows === undefined;
    const loadPath = row.original.isNode ? row.original.parentPath : row.original.path;

    if (needsLoading) {
      if (!loadPath) return;
      if (loadingPathSetRef.current.has(loadPath)) return;

      loadingPathSetRef.current.add(loadPath);
      setLoadingRows(prev => ({ ...prev, [row.id]: true }));
      try {
        await onExpand(row.original);
      } catch (error) {
        console.error("onExpand failed for row:", row.id, error);
        setLoadingRows(prev => {
          const newState = { ...prev };
          delete newState[row.id];
          return newState;
        });
        return;
      } finally {
        loadingPathSetRef.current.delete(loadPath);
        setLoadingRows(prev => {
          const newState = { ...prev };
          delete newState[row.id];
          return newState;
        });
      }
    }
    row.toggleExpanded();
  }, [onExpand]);

  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    initialState,
    getPaginationRowModel: getPaginationRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getExpandedRowModel: getExpandedRowModel(),
    getRowCanExpand: (row) => row.original.isNode || row.original.type === "dir",
    getSubRows: (row) => row.subRows,
    state: {
      globalFilter: search,
      expanded,
    },
    onGlobalFilterChange: setSearch,
    onExpandedChange: setExpanded,
  });

  const currentPage = table.getState().pagination.pageIndex;
  const pageCount = table.getPageCount();

  const paginationItems = (() => {
    if (pageCount <= 7) {
      return Array.from({ length: pageCount }, (_, i) => i);
    }

    const pages = new Set<number>([0, pageCount - 1, currentPage]);
    if (currentPage - 1 >= 0) pages.add(currentPage - 1);
    if (currentPage + 1 < pageCount) pages.add(currentPage + 1);

    const ordered = Array.from(pages).sort((a, b) => a - b);
    const items: Array<number | "ellipsis"> = [];

    for (let i = 0; i < ordered.length; i += 1) {
      if (i > 0 && ordered[i] - ordered[i - 1] > 1) {
        items.push("ellipsis");
      }
      items.push(ordered[i]);
    }

    return items;
  })();

  useEffect(() => {
    if (!isTree) return;
    
    table.getRowModel().rows.forEach((row) => {
      if (
        !row.getIsExpanded() &&
        (
          (row.original.isNode && row.original.parentPath && path.startsWith(row.original.parentPath)) ||
          (row.original.type === "dir" && path.startsWith(row.original.path))
        )
      ) {
        handleRowExpansion(row as Row<TData>);
      }
    });
  }, [isTree, path, handleRowExpansion, table, data]);

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  const dataByPath = useMemo(() => {
    const m = new Map<string, Record<string, any>>();
    for (const item of data) m.set(item.path, item);
    return m;
  }, [data]);

  const fileItems = useMemo(
    () => orderPaths.map((p) => dataByPath.get(p)).filter((x): x is Record<string, any> => Boolean(x)),
    [orderPaths, dataByPath],
  );
  const folderItems = useMemo(() => data.filter((d) => d.type === "dir"), [data]);
  const isOrderDirty = useMemo(
    () => orderPaths.some((p, i) => initialFilePaths[i] !== p),
    [orderPaths, initialFilePaths],
  );

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event;
    if (!over || active.id === over.id) return;
    setOrderPaths((prev) => {
      const oldIndex = prev.indexOf(String(active.id));
      const newIndex = prev.indexOf(String(over.id));
      if (oldIndex < 0 || newIndex < 0) return prev;
      return arrayMove(prev, oldIndex, newIndex);
    });
  };

  const handleSaveOrder = async () => {
    if (!onReorder) return;
    setIsSavingOrder(true);
    try {
      await onReorder(orderPaths);
      setIsReordering(false);
    } catch (err: any) {
      toast.error(err?.message ?? "Reorder failed");
    } finally {
      setIsSavingOrder(false);
    }
  };

  const handleResetOrder = () => setOrderPaths(initialFilePaths);

  return (
    <div className="space-y-2">
      {reorderable && (
        <div className="flex items-center justify-end gap-2">
          {isReordering ? (
            <>
              {isOrderDirty && (
                <Button variant="outline" size="sm" onClick={handleResetOrder} disabled={isSavingOrder}>
                  <Undo2 className="h-3.5 w-3.5" /> Reset
                </Button>
              )}
              <Button size="sm" onClick={handleSaveOrder} disabled={!isOrderDirty || isSavingOrder}>
                {isSavingOrder ? <Loader className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
                {isSavingOrder ? "Saving" : "Save order"}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => { setIsReordering(false); setOrderPaths(initialFilePaths); }}
                disabled={isSavingOrder}
              >
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
      {reorderable && isReordering ? (
        <Table className="border-separate border-spacing-0 text-sm">
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id} className="sticky -top-4 md:-top-6 z-20 bg-background hover:bg-background">
                <TableHead className="p-2 h-10 border-b w-8" aria-label="Drag handle column" />
                {headerGroup.headers.map((header) => (
                  <TableHead
                    key={header.id}
                    className={cn("p-2 h-10 border-b truncate", header.column.columnDef.meta?.className)}
                  >
                    {flexRender(header.column.columnDef.header, header.getContext())}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            <DndContext
              sensors={sensors}
              collisionDetection={closestCenter}
              modifiers={[restrictToVerticalAxis]}
              onDragEnd={handleDragEnd}
            >
              <SortableContext items={fileItems.map((f) => f.path)} strategy={verticalListSortingStrategy}>
                {folderItems.length > 0 && folderItems.map((row) => (
                  <TableRow key={`folder-${row.path}`} className="opacity-60">
                    <TableCell className="p-2 border-b w-8" />
                    <TableCell colSpan={columns.length} className="p-2 border-b py-0 h-12">
                      <span className="flex items-center gap-x-2 font-medium">
                        <Folder className="h-4 w-4" /> {row.name}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
                {fileItems.map((row) => {
                  const tableRow = table.getRowModel().rows.find((r) => r.original.path === row.path);
                  return (
                    <SortableTableRow
                      key={row.path}
                      id={row.path}
                      visibleCells={tableRow?.getVisibleCells() ?? []}
                      primaryField={primaryField}
                    />
                  );
                })}
              </SortableContext>
            </DndContext>
          </TableBody>
        </Table>
      ) : (
      <Table className="border-separate border-spacing-0 text-sm">
        <TableHeader>
          {table.getHeaderGroups().map((headerGroup) => (
            <TableRow key={headerGroup.id} className="sticky -top-4 md:-top-6 z-20 bg-background hover:bg-background">
              {headerGroup.headers.map((header) => {
                return (
                  <TableHead
                    key={header.id}
                    className={cn(
                      "p-2 h-10 border-b hover:bg-muted/50 cursor-pointer select-none last:cursor-default last:hover:bg-background truncate",
                      header.column.columnDef.meta?.className
                    )}
                    onClick={header.column.getToggleSortingHandler()}
                    title={
                      header.column.getCanSort()
                        ? header.column.getNextSortingOrder() === 'asc'
                          ? 'Sort ascending'
                          : header.column.getNextSortingOrder() === 'desc'
                            ? 'Sort descending'
                            : 'Clear sort'
                        : undefined
                    }
                  >
                    <div className="flex items-center gap-x-2">
                      {header.isPlaceholder
                        ? null
                        : flexRender(
                            header.column.columnDef.header,
                            header.getContext()
                          )}
                      {{
                        asc: <ArrowUp className="h-4 w-4 opacity-50"/>,
                        desc: <ArrowDown className="xh-4 w-4 opacity-50"/>,
                      }[header.column.getIsSorted() as string] ?? null}
                    </div>
                  </TableHead>
                )
              })}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {table.getRowModel().rows?.length ? (
            table.getRowModel().rows.map((row) => (
              <TableRow key={row.id}>
                {
                  row.original.type === "dir"
                    ? <>
                      <TableCell
                        colSpan={columns.length - 1}
                        className="p-2 border-b py-0 h-12"
                        style={{
                          paddingLeft: row.depth > 0
                            ? `${row.depth * 2}rem`
                            : undefined
                        }}
                      >
                        {isTree
                          ? <button
                              className="flex items-center gap-x-2 font-medium"
                              onClick={() => handleRowExpansion(row as Row<TData>)}
                            >
                              {loadingRows[row.id]
                                ? <Loader className="h-4 w-4 animate-spin text-muted-foreground" />
                                : row.getIsExpanded()
                                  ? <FolderOpen className="h-4 w-4" />
                                  : <Folder className="h-4 w-4" />
                              }
                              {row.original.name}
                            </button>
                          : <Link
                              className="flex items-center gap-x-2 font-medium"
                              href={`${pathname}?path=${encodeURIComponent(row.original.path)}`}
                            >
                              <Folder className="h-4 w-4" />
                              {row.original.name}
                            </Link>
                        }
                      </TableCell>
                      <TableCell className="p-2 border-b py-0 h-12">
                        {
                          (() => {
                            const lastCell = row.getVisibleCells()[row.getVisibleCells().length - 1];
                            return flexRender(lastCell.column.columnDef.cell, lastCell.getContext());
                          })()
                        }
                      </TableCell>
                      </>
                    : row.getVisibleCells().map((cell, index) => (
                      <TableCell
                        key={cell.id}
                        className={cn(
                          "p-2 border-b py-0 h-12",
                          cell.column.columnDef.meta?.className,
                        )}
                        style={{
                          paddingLeft: (cell.column.id === primaryField && row.depth > 0)
                            ? `${row.depth * 1.5}rem`
                            : undefined
                        }}
                      >
                        <div className="flex items-center gap-x-1">
                          {row.depth > 0 && cell.column.id === primaryField && <LShapeIcon className="h-4 w-4 text-muted-foreground opacity-50"/>}
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                          {isTree && row.getCanExpand() && cell.column.id === primaryField && (
                            loadingRows[row.id]
                              ? <Button variant="ghost" size="icon-sm" className="h-6 w-6 rounded-full" disabled>
                                  <Loader className="h-4 w-4 animate-spin text-muted-foreground" />
                                </Button>
                              : <Button
                                  variant="ghost"
                                  size="icon-sm"
                                  className="h-6 w-6 rounded-full"
                                  onClick={() => handleRowExpansion(row as Row<TData>)}
                                  disabled={row.getIsExpanded() && Array.isArray(row.original.subRows) && row.original.subRows.length === 0}
                                >
                                  {row.getIsExpanded() ? <CircleMinus className="text-muted-foreground hover:text-foreground h-4 w-4" /> : <CirclePlus className="text-muted-foreground hover:text-foreground h-4 w-4" />}
                                  <span className="sr-only">{row.getIsExpanded() ? 'Collapse row' : 'Expand row'}</span>
                                </Button>
                          )}
                          
                        </div>
                      </TableCell>
                    ))
                }
              </TableRow>
            ))
          ) : (
            <TableRow className="hover:bg-transparent">
              <TableCell colSpan={columns.length} className="text-center text-muted-foreground text-sm p-6">
                <span>No entries</span>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
      )}
      {!isReordering && pageCount > 1 && (
        <footer className="flex items-center justify-end">
          <Pagination className="mx-0 w-auto justify-end">
            <PaginationContent>
              <PaginationItem>
                <PaginationPrevious
                  href="#"
                  iconOnly
                  onClick={(event) => {
                    event.preventDefault();
                    if (table.getCanPreviousPage()) table.previousPage();
                  }}
                  className={!table.getCanPreviousPage() ? "pointer-events-none opacity-50" : undefined}
                />
              </PaginationItem>
              {paginationItems.map((item, index) => (
                <PaginationItem key={`${item}-${index}`}>
                  {item === "ellipsis" ? (
                    <PaginationEllipsis />
                  ) : (
                    <PaginationLink
                      href="#"
                      isActive={item === currentPage}
                      onClick={(event) => {
                        event.preventDefault();
                        table.setPageIndex(item);
                      }}
                    >
                      {item + 1}
                    </PaginationLink>
                  )}
                </PaginationItem>
              ))}
              <PaginationItem>
                <PaginationNext
                  href="#"
                  iconOnly
                  onClick={(event) => {
                    event.preventDefault();
                    if (table.getCanNextPage()) table.nextPage();
                  }}
                  className={!table.getCanNextPage() ? "pointer-events-none opacity-50" : undefined}
                />
              </PaginationItem>
            </PaginationContent>
          </Pagination>
        </footer>
      )}
    </div>
  )
}
