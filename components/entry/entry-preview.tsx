"use client";

import { useEffect, useRef } from "react";
import { cn } from "@/lib/utils";

interface EntryPreviewProps {
  content: string;
  format?: "markdown" | "html";
  className?: string;
}

/**
 * Renders a live preview of markdown or HTML content.
 * Uses the browser's native DOMParser and marked (already a dependency via other packages).
 * Falls back to a simple pre-formatted display if parsing fails.
 */
export function EntryPreview({ content, format = "markdown", className }: EntryPreviewProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const render = async () => {
      try {
        let html = content ?? "";

        if (format === "markdown") {
          // Use marked if available (it's a transitive dep), otherwise basic conversion
          try {
            const { marked } = await import("marked");
            html = await marked(content ?? "", { gfm: true, breaks: true });
          } catch {
            // Fallback: very basic markdown-to-html
            html = content
              .replace(/^### (.+)$/gm, "<h3>$1</h3>")
              .replace(/^## (.+)$/gm, "<h2>$1</h2>")
              .replace(/^# (.+)$/gm, "<h1>$1</h1>")
              .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
              .replace(/\*(.+?)\*/g, "<em>$1</em>")
              .replace(/`(.+?)`/g, "<code>$1</code>")
              .replace(/\n\n/g, "</p><p>")
              .replace(/^(.+)$/, "<p>$1</p>");
          }
        }

        containerRef.current.innerHTML = html;
      } catch (e) {
        if (containerRef.current) {
          containerRef.current.textContent = content;
        }
      }
    };

    render();
  }, [content, format]);

  return (
    <div
      ref={containerRef}
      className={cn(
        "prose prose-sm max-w-none",
        "prose-headings:font-semibold prose-headings:text-foreground",
        "prose-p:text-foreground prose-li:text-foreground",
        "prose-code:bg-muted prose-code:rounded prose-code:px-1 prose-code:text-sm",
        "prose-pre:bg-muted prose-pre:rounded prose-pre:p-3",
        "prose-blockquote:border-l-2 prose-blockquote:border-border prose-blockquote:pl-4 prose-blockquote:text-muted-foreground",
        "prose-a:text-primary prose-a:underline",
        "min-h-[200px]",
        className
      )}
    />
  );
}
