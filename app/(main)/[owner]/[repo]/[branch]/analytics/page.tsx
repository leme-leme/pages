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
import { BarChart, DayBars, Sparkline } from "@/components/charts/sparkline";
import { toast } from "sonner";
import { requireApiSuccess } from "@/lib/api-client";

type Interval = "1d" | "7d" | "30d" | "90d";

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

type DeployStats = {
  total: number;
  succeeded: number;
  failed: number;
  inProgress: number;
  successRate: number;
  meanDurationMs: number | null;
  p95DurationMs: number | null;
};

type DashboardData = {
  events: { date: string; type: string; count: number }[];
  errors: { date: string; status: string; route: string; count: number }[];
  storage: { date: string; bytesIn: number; bytesOut: number }[];
  webVitals: { metric: string; date: string; p75: number; p99: number; samples: number }[];
  topActors: { actorEmail: string; events: number }[];
  topEntries: { resourceId: string; resourceType: string; count: number; bytes: number }[];
  topMedia: { resourceId: string; resourceType: string; count: number; bytes: number }[];
  topCountries: { country: string; count: number }[];
  userAgents: { bucket: string; count: number }[];
  deploys: { stats: DeployStats | null; byDay: { date: string; total: number; succeeded: number; failed: number }[] };
  unconfigured?: boolean;
};

type RealtimeData = { minutes: { minute: string; type: string; count: number }[]; unconfigured?: boolean };

const fmtBytes = (bytes: number): string => {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = bytes;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
};

const fmtDuration = (ms: number | null): string => {
  if (ms == null || !Number.isFinite(ms)) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  return `${(ms / 60_000).toFixed(1)} m`;
};

export default function Page() {
  const { config } = useConfig();
  if (!config) throw new Error(`Configuration not found.`);
  const { owner, repo, branch } = config;

  const [cfg, setCfg] = useState<SiteAnalyticsConfig>(empty);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [realtime, setRealtime] = useState<RealtimeData | null>(null);
  const [interval, setIntervalSel] = useState<Interval>("7d");

  const apiBase = `/api/${owner}/${repo}/${encodeURIComponent(branch)}/analytics`;
  const snippetUrl = useMemo(() => {
    if (typeof window === "undefined") return "";
    return `${window.location.origin}${apiBase}/snippet.js`;
  }, [apiBase]);
  const eventEndpoint = useMemo(() => {
    if (typeof window === "undefined") return "";
    return `${window.location.origin}${apiBase}/event`;
  }, [apiBase]);

  // Site-config load
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

  // Dashboard load
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

  // Realtime — poll every 10s.
  useEffect(() => {
    let abort = false;
    const tick = async () => {
      try {
        const res = await fetch(`${apiBase}/realtime`);
        const data = await requireApiSuccess<{ data: RealtimeData }>(res, "Failed to load realtime");
        if (!abort) setRealtime(data.data);
      } catch {
        // ignore
      }
    };
    void tick();
    const id = window.setInterval(tick, 10_000);
    return () => { abort = true; window.clearInterval(id); };
  }, [apiBase]);

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

  // Aggregate event totals into a per-day series for the activity sparkline.
  const eventTotalsByDay = useMemo(() => {
    if (!dashboard) return [] as { date: string; value: number }[];
    const map = new Map<string, number>();
    for (const row of dashboard.events) map.set(row.date, (map.get(row.date) ?? 0) + Number(row.count));
    return Array.from(map.entries()).map(([date, value]) => ({ date, value })).sort((a, b) => a.date.localeCompare(b.date));
  }, [dashboard]);

  const eventTotalsByType = useMemo(() => {
    if (!dashboard) return [] as { label: string; value: number }[];
    const map = new Map<string, number>();
    for (const row of dashboard.events) map.set(row.type, (map.get(row.type) ?? 0) + Number(row.count));
    return Array.from(map.entries())
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value);
  }, [dashboard]);

  const storageInByDay = useMemo(() =>
    (dashboard?.storage ?? []).map((r) => ({ date: r.date, value: Number(r.bytesIn) || 0 }))
  , [dashboard]);
  const storageOutByDay = useMemo(() =>
    (dashboard?.storage ?? []).map((r) => ({ date: r.date, value: Number(r.bytesOut) || 0 }))
  , [dashboard]);

  const realtimeBuckets = useMemo(() => {
    if (!realtime) return [] as { date: string; value: number }[];
    const map = new Map<string, number>();
    for (const row of realtime.minutes) map.set(row.minute, (map.get(row.minute) ?? 0) + Number(row.count));
    return Array.from(map.entries()).map(([date, value]) => ({ date, value })).sort((a, b) => a.date.localeCompare(b.date));
  }, [realtime]);
  const realtimeTotal = realtimeBuckets.reduce((s, b) => s + b.value, 0);

  return (
    <div className="max-w-screen-md mx-auto flex-1 flex flex-col h-full p-4 md:p-6 gap-6">
      <DocumentTitle title={formatRepoBranchTitle("Analytics", owner, repo, branch)} />

      <div className="flex items-center justify-between gap-2">
        <h1 className="font-semibold text-lg">Analytics</h1>
        <div className="flex items-center gap-2">
          <a
            href={`${apiBase}/dashboard?interval=${interval}&format=csv`}
            className="text-sm text-muted-foreground hover:text-foreground underline-offset-2 hover:underline"
          >
            Export CSV
          </a>
          <div className="flex gap-1">
            {(["1d", "7d", "30d", "90d"] as const).map((value) => (
              <Button
                key={value}
                size="sm"
                variant={interval === value ? "default" : "outline"}
                onClick={() => setIntervalSel(value)}
              >
                {value}
              </Button>
            ))}
          </div>
        </div>
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>Realtime</CardTitle>
            <CardDescription>Last 60 minutes, refreshed every 10s.</CardDescription>
          </div>
          <span className="text-2xl font-semibold tabular-nums">{realtimeTotal.toLocaleString()}</span>
        </CardHeader>
        <CardContent>
          {realtime?.unconfigured ? (
            <p className="text-sm text-muted-foreground">
              Set <code>CF_ACCOUNT_ID</code> + <code>CF_ANALYTICS_API_TOKEN</code> to enable realtime.
            </p>
          ) : realtimeBuckets.length === 0 ? (
            <p className="text-sm text-muted-foreground">No events in the last hour.</p>
          ) : (
            <Sparkline values={realtimeBuckets.map((b) => b.value)} ariaLabel="events per minute" height={48} />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Activity</CardTitle>
          <CardDescription>CMS events the past {interval}.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {dashboard?.unconfigured ? (
            <p className="text-sm text-muted-foreground">
              Set <code>CF_ACCOUNT_ID</code> + <code>CF_ANALYTICS_API_TOKEN</code> env vars to enable analytics.
            </p>
          ) : !dashboard ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : eventTotalsByDay.length === 0 ? (
            <p className="text-sm text-muted-foreground">No events recorded yet.</p>
          ) : (
            <>
              <DayBars values={eventTotalsByDay} formatValue={(n) => n.toLocaleString()} />
              <BarChart data={eventTotalsByType} />
            </>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Top contributors</CardTitle>
          </CardHeader>
          <CardContent>
            {!dashboard ? (
              <p className="text-sm text-muted-foreground">Loading…</p>
            ) : dashboard.topActors.length === 0 ? (
              <p className="text-sm text-muted-foreground">No data.</p>
            ) : (
              <BarChart
                data={dashboard.topActors.map((a) => ({ label: a.actorEmail, value: Number(a.events) }))}
              />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top countries</CardTitle>
          </CardHeader>
          <CardContent>
            {!dashboard ? (
              <p className="text-sm text-muted-foreground">Loading…</p>
            ) : dashboard.topCountries.length === 0 ? (
              <p className="text-sm text-muted-foreground">No data.</p>
            ) : (
              <BarChart
                data={dashboard.topCountries.map((c) => ({ label: c.country || "??", value: Number(c.count) }))}
              />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top entries</CardTitle>
          </CardHeader>
          <CardContent>
            {!dashboard ? (
              <p className="text-sm text-muted-foreground">Loading…</p>
            ) : dashboard.topEntries.length === 0 ? (
              <p className="text-sm text-muted-foreground">No data.</p>
            ) : (
              <BarChart
                data={dashboard.topEntries.map((r) => ({ label: r.resourceId, value: Number(r.count) }))}
              />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top media</CardTitle>
          </CardHeader>
          <CardContent>
            {!dashboard ? (
              <p className="text-sm text-muted-foreground">Loading…</p>
            ) : dashboard.topMedia.length === 0 ? (
              <p className="text-sm text-muted-foreground">No data.</p>
            ) : (
              <BarChart
                data={dashboard.topMedia.map((r) => ({
                  label: r.resourceId,
                  sublabel: fmtBytes(Number(r.bytes)),
                  value: Number(r.count),
                }))}
              />
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Storage</CardTitle>
          <CardDescription>Bytes in / out the past {interval}.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {!dashboard ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : (dashboard.storage.length === 0) ? (
            <p className="text-sm text-muted-foreground">No storage events.</p>
          ) : (
            <>
              <div className="text-xs text-muted-foreground">↑ uploaded</div>
              <DayBars values={storageInByDay} formatValue={fmtBytes} />
              <div className="text-xs text-muted-foreground">↓ egressed</div>
              <DayBars values={storageOutByDay} formatValue={fmtBytes} />
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Errors</CardTitle>
          <CardDescription>5xx responses the past {interval}.</CardDescription>
        </CardHeader>
        <CardContent>
          {!dashboard ? (
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
          {!dashboard ? (
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
          <CardTitle>Deploys (GitHub Actions)</CardTitle>
          <CardDescription>Last {interval === "1d" ? "7d" : interval}.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {!dashboard ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : !dashboard.deploys.stats || dashboard.deploys.stats.total === 0 ? (
            <p className="text-sm text-muted-foreground">No action runs.</p>
          ) : (
            <>
              <div className="grid grid-cols-4 gap-2 text-sm">
                <div>
                  <div className="text-muted-foreground text-xs">Total</div>
                  <div className="font-medium tabular-nums">{dashboard.deploys.stats.total}</div>
                </div>
                <div>
                  <div className="text-muted-foreground text-xs">Success</div>
                  <div className="font-medium tabular-nums">
                    {(dashboard.deploys.stats.successRate * 100).toFixed(1)}%
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground text-xs">Mean</div>
                  <div className="font-medium tabular-nums">
                    {fmtDuration(dashboard.deploys.stats.meanDurationMs)}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground text-xs">p95</div>
                  <div className="font-medium tabular-nums">
                    {fmtDuration(dashboard.deploys.stats.p95DurationMs)}
                  </div>
                </div>
              </div>
              <DayBars
                values={dashboard.deploys.byDay.map((d) => ({ date: d.date, value: d.total }))}
              />
            </>
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

          <details className="text-xs text-muted-foreground">
            <summary className="cursor-pointer">Send custom events from your site</summary>
            <pre className="mt-2 bg-muted p-3 rounded overflow-x-auto">
              <code>{`navigator.sendBeacon(
  "${eventEndpoint}",
  JSON.stringify({ name: "newsletter.signup", page: location.pathname })
);`}</code>
            </pre>
          </details>

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
