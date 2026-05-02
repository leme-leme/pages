"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { DocumentTitle, formatRepoBranchTitle } from "@/components/document-title";
import { useConfig } from "@/contexts/config-context";
import { Button } from "@/components/ui/button";
import { SubmitButton } from "@/components/submit-button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";
import { requireApiSuccess } from "@/lib/api-client";

type SiteAnalyticsConfig = {
  ga4MeasurementId: string | null;
  plausibleDomain: string | null;
  plausibleApiHost: string | null;
  cfBeaconToken: string | null;
  requireConsent: boolean;
  honorDnt: boolean;
};

const empty: SiteAnalyticsConfig = {
  ga4MeasurementId: null,
  plausibleDomain: null,
  plausibleApiHost: null,
  cfBeaconToken: null,
  requireConsent: true,
  honorDnt: true,
};

type DashboardData = {
  events: { date: string; type: string; count: number }[];
  errors: { date: string; status: string; route: string; count: number }[];
  storage: { date: string; bytesIn: number; bytesOut: number }[];
  webVitals: { metric: string; date: string; p75: number; p99: number; samples: number }[];
};

const fmtBytes = (bytes: number): string => {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = bytes;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
};

export default function Page() {
  const { config } = useConfig();
  if (!config) throw new Error(`Configuration not found.`);
  const { owner, repo, branch } = config;

  const [cfg, setCfg] = useState<SiteAnalyticsConfig>(empty);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [interval, setInterval] = useState<"1d" | "7d" | "30d" | "90d">("7d");

  const apiBase = `/api/${owner}/${repo}/${encodeURIComponent(branch)}/analytics`;
  const snippetUrl = useMemo(() => {
    if (typeof window === "undefined") return "";
    return `${window.location.origin}${apiBase}/snippet.js`;
  }, [apiBase]);

  useEffect(() => {
    let abort = false;
    (async () => {
      try {
        const res = await fetch(`${apiBase}/config`);
        const data = await requireApiSuccess<{ data: SiteAnalyticsConfig | null }>(res, "Failed to load config");
        if (!abort) setCfg(data.data ?? empty);
      } catch (error) {
        if (!abort) toast.error(error instanceof Error ? error.message : "Failed to load config");
      } finally {
        if (!abort) setLoading(false);
      }
    })();
    return () => { abort = true; };
  }, [apiBase]);

  useEffect(() => {
    let abort = false;
    setDashboard(null);
    (async () => {
      try {
        const res = await fetch(`${apiBase}/dashboard?interval=${interval}`);
        const data = await requireApiSuccess<{ data: DashboardData }>(res, "Failed to load dashboard");
        if (!abort) setDashboard(data.data);
      } catch (error) {
        if (!abort) console.warn(error);
      }
    })();
    return () => { abort = true; };
  }, [apiBase, interval]);

  const save = useCallback(async (event: React.FormEvent) => {
    event.preventDefault();
    setSaving(true);
    try {
      const res = await fetch(`${apiBase}/config`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(cfg),
      });
      await requireApiSuccess(res, "Failed to save config");
      toast.success("Saved.");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to save config");
    } finally {
      setSaving(false);
    }
  }, [apiBase, cfg]);

  const eventTotalsByType = useMemo(() => {
    if (!dashboard) return [] as { type: string; total: number }[];
    const map = new Map<string, number>();
    for (const row of dashboard.events) map.set(row.type, (map.get(row.type) ?? 0) + Number(row.count));
    return Array.from(map.entries()).map(([type, total]) => ({ type, total })).sort((a, b) => b.total - a.total);
  }, [dashboard]);

  return (
    <div className="max-w-screen-md mx-auto flex-1 flex flex-col h-full p-4 md:p-6 gap-6">
      <DocumentTitle title={formatRepoBranchTitle("Analytics", owner, repo, branch)} />

      <div className="flex items-center justify-between gap-2">
        <h1 className="font-semibold text-lg">Analytics</h1>
        <div className="flex gap-1">
          {(["1d", "7d", "30d", "90d"] as const).map((value) => (
            <Button
              key={value}
              size="sm"
              variant={interval === value ? "default" : "outline"}
              onClick={() => setInterval(value)}
            >
              {value}
            </Button>
          ))}
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Activity</CardTitle>
          <CardDescription>CMS events the past {interval}.</CardDescription>
        </CardHeader>
        <CardContent>
          {dashboard == null ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : eventTotalsByType.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No events recorded. Configure the <code>AE</code> binding and the <code>CF_ACCOUNT_ID</code> +
              <code> CF_ANALYTICS_API_TOKEN</code> env vars to enable analytics.
            </p>
          ) : (
            <ul className="space-y-1 text-sm">
              {eventTotalsByType.map(({ type, total }) => (
                <li key={type} className="flex items-center gap-2 justify-between">
                  <span className="font-mono text-xs text-muted-foreground">{type}</span>
                  <span className="tabular-nums">{total.toLocaleString()}</span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Storage</CardTitle>
          <CardDescription>Bytes in / out the past {interval}.</CardDescription>
        </CardHeader>
        <CardContent>
          {dashboard == null ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : dashboard.storage.length === 0 ? (
            <p className="text-sm text-muted-foreground">No storage events.</p>
          ) : (
            <ul className="space-y-1 text-sm font-mono">
              {dashboard.storage.map((row) => (
                <li key={row.date} className="grid grid-cols-3 gap-2">
                  <span>{row.date}</span>
                  <span className="text-emerald-700 dark:text-emerald-400">↑ {fmtBytes(row.bytesIn)}</span>
                  <span className="text-blue-700 dark:text-blue-400">↓ {fmtBytes(row.bytesOut)}</span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Errors</CardTitle>
          <CardDescription>5xx responses the past {interval}.</CardDescription>
        </CardHeader>
        <CardContent>
          {dashboard == null ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : dashboard.errors.length === 0 ? (
            <p className="text-sm text-muted-foreground">No server errors. Nice.</p>
          ) : (
            <ul className="space-y-1 text-sm font-mono">
              {dashboard.errors.slice(0, 20).map((row, idx) => (
                <li key={idx} className="grid grid-cols-[6rem_4rem_1fr_4rem] gap-2 truncate">
                  <span>{row.date}</span>
                  <span className="text-red-600">{row.status}</span>
                  <span className="truncate text-muted-foreground">{row.route}</span>
                  <span className="text-right tabular-nums">{Number(row.count)}</span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Web Vitals (p75)</CardTitle>
          <CardDescription>Real-user metrics from the last {interval}.</CardDescription>
        </CardHeader>
        <CardContent>
          {dashboard == null ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : dashboard.webVitals.length === 0 ? (
            <p className="text-sm text-muted-foreground">No web vital samples yet.</p>
          ) : (
            <ul className="space-y-1 text-sm font-mono">
              {dashboard.webVitals.slice(0, 30).map((row, idx) => (
                <li key={idx} className="grid grid-cols-4 gap-2">
                  <span>{row.date}</span>
                  <span className="font-medium">{row.metric}</span>
                  <span className="tabular-nums">p75 {Math.round(row.p75)}</span>
                  <span className="tabular-nums text-muted-foreground">n {row.samples}</span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Site analytics injection</CardTitle>
          <CardDescription>
            Add this to your deployed site&apos;s &lt;head&gt;:
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <pre className="text-xs bg-muted p-3 rounded overflow-x-auto">
            <code>{`<script src="${snippetUrl}" async></script>`}</code>
          </pre>

          <form onSubmit={save} className="space-y-4">
            <div className="space-y-1">
              <Label htmlFor="ga4">Google Analytics 4 measurement ID</Label>
              <Input
                id="ga4"
                placeholder="G-XXXXXXX"
                value={cfg.ga4MeasurementId ?? ""}
                disabled={loading}
                onChange={(e) => setCfg((c) => ({ ...c, ga4MeasurementId: e.target.value || null }))}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="plausible-domain">Plausible site domain</Label>
              <Input
                id="plausible-domain"
                placeholder="example.com"
                value={cfg.plausibleDomain ?? ""}
                disabled={loading}
                onChange={(e) => setCfg((c) => ({ ...c, plausibleDomain: e.target.value || null }))}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="plausible-host">Plausible host (self-hosted only)</Label>
              <Input
                id="plausible-host"
                placeholder="https://plausible.io"
                value={cfg.plausibleApiHost ?? ""}
                disabled={loading}
                onChange={(e) => setCfg((c) => ({ ...c, plausibleApiHost: e.target.value || null }))}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="cf-token">Cloudflare Web Analytics beacon token</Label>
              <Input
                id="cf-token"
                placeholder="32 hex chars"
                value={cfg.cfBeaconToken ?? ""}
                disabled={loading}
                onChange={(e) => setCfg((c) => ({ ...c, cfBeaconToken: e.target.value || null }))}
              />
            </div>
            <div className="flex items-center gap-3">
              <Switch
                id="require-consent"
                checked={cfg.requireConsent}
                onCheckedChange={(v) => setCfg((c) => ({ ...c, requireConsent: v }))}
              />
              <Label htmlFor="require-consent">Require visitor consent (cookie banner)</Label>
            </div>
            <div className="flex items-center gap-3">
              <Switch
                id="honor-dnt"
                checked={cfg.honorDnt}
                onCheckedChange={(v) => setCfg((c) => ({ ...c, honorDnt: v }))}
              />
              <Label htmlFor="honor-dnt">Honor Do-Not-Track / Sec-GPC</Label>
            </div>
            <SubmitButton type="submit" disabled={loading || saving}>
              {saving ? "Saving…" : "Save"}
            </SubmitButton>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
