"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { RepoSidebar } from "@/components/repo/repo-sidebar";
import { Button, buttonVariants } from "@/components/ui/button";
import { ExternalLink, Menu, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { useConfig } from "@/contexts/config-context";
import { useRepo } from "@/contexts/repo-context";
import { trackVisit } from "@/lib/tracker";

export function RepoLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [isMenuOpen, setMenuOpen] = useState(false);
  const { config } = useConfig();
  const { owner, repo } = useRepo();
  const pathname = usePathname();

  // Close on navigation
  useEffect(() => {
    setMenuOpen(false);
  }, [pathname]);

  // Close on Escape
  useEffect(() => {
    if (!isMenuOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMenuOpen(false);
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isMenuOpen]);

  useEffect(() => {
    if (config?.owner && config?.repo && config?.branch) {
      trackVisit(owner, repo, config.branch);
    }
  }, [config, owner, repo]);

  return (
    <>
      {/* Mobile sidebar — slides in from left, no overlay */}
      <aside
        className={cn(
          "xl:hidden fixed inset-y-0 left-0 z-30 flex flex-col w-72 border-r bg-background gap-y-2",
          "transition-transform duration-300 ease-in-out",
          isMenuOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        <RepoSidebar onClick={() => setMenuOpen(false)} />
      </aside>

      <div className="flex h-screen w-full">
        {/* Desktop sidebar — always visible */}
        <aside className="hidden xl:flex flex-col h-screen w-72 border-r gap-y-2">
          <RepoSidebar />
        </aside>

        {/* Main content — slides right on mobile when sidebar opens */}
        <main
          className={cn(
            "flex flex-col flex-1 relative h-screen overflow-hidden",
            "xl:transition-none transition-transform duration-300 ease-in-out",
            isMenuOpen ? "xl:translate-x-0 translate-x-72" : "translate-x-0"
          )}
        >
          {/* Mobile top bar — slides with content, hamburger always visible */}
          <div className="xl:hidden h-14 shrink-0 flex items-center px-4 md:px-6 border-b bg-background">
            <Button
              variant="outline"
              size="icon"
              onClick={() => setMenuOpen(v => !v)}
              aria-label={isMenuOpen ? "Close menu" : "Open menu"}
            >
              {isMenuOpen
                ? <X className="h-4 w-4" />
                : <Menu className="h-4 w-4" />
              }
            </Button>
            {config?.object?.site_url && (
              <a
                href={config.object.site_url}
                target="_blank"
                rel="noreferrer"
                className={cn(buttonVariants({ variant: "outline", size: "icon" }), "ml-auto")}
                aria-label="Visit site"
              >
                <ExternalLink className="h-4 w-4" />
              </a>
            )}
          </div>

          <div className="flex-1 overflow-auto scrollbar p-4 md:p-6">
            {children}
          </div>
        </main>
      </div>
    </>
  );
}
