"use client";

import { useMemo, useState } from "react";
import useSWR from "swr";
import { toast } from "sonner";
import { format } from "date-fns";
import { CalendarClock, Loader2, Repeat, Trash2, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export type ScheduleAction = "publish" | "unpublish" | "delete";
export type ScheduleKind = "once" | "recurring";

export type ScheduleConfig = {
  action: ScheduleAction;
  scheduleKind: ScheduleKind;
  runAt?: string; // ISO (once)
  cronExpr?: string; // recurring
  timezone: string;
};

const CRON_PRESETS: { label: string; value: string }[] = [
  { label: "Every day at 09:00", value: "0 9 * * *" },
  { label: "Every Monday at 09:00", value: "0 9 * * 1" },
  { label: "First of the month at 09:00", value: "0 9 1 * *" },
  { label: "Custom…", value: "custom" },
];

const STATUS_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  pending: "default",
  running: "secondary",
  done: "secondary",
  failed: "destructive",
  canceled: "outline",
};

const browserTimezone = () => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
};

const fetcher = (url: string) => fetch(url).then((r) => r.json());

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  schedulesUrl: string; // GET/POST endpoint for this entry's schedules
  canUnpublish: boolean; // collection has a status/published field
  // Parent builds the action payload (it owns the current editor content).
  onConfirm: (config: ScheduleConfig) => Promise<void>;
};

export function ScheduleDialog({ open, onOpenChange, schedulesUrl, canUnpublish, onConfirm }: Props) {
  const [action, setAction] = useState<ScheduleAction>("publish");
  const [kind, setKind] = useState<ScheduleKind>("once");
  const [runAtLocal, setRunAtLocal] = useState("");
  const [preset, setPreset] = useState(CRON_PRESETS[0].value);
  const [customCron, setCustomCron] = useState("");
  const [timezone, setTimezone] = useState(browserTimezone());
  const [submitting, setSubmitting] = useState(false);

  const { data, isLoading, mutate } = useSWR<{ data: any[] }>(open ? schedulesUrl : null, fetcher);
  const jobs = data?.data ?? [];

  const cronExpr = preset === "custom" ? customCron.trim() : preset;

  const actionOptions = useMemo(() => {
    const opts: { value: ScheduleAction; label: string }[] = [{ value: "publish", label: "Publish" }];
    if (canUnpublish) opts.push({ value: "unpublish", label: "Unpublish (set draft)" });
    opts.push({ value: "delete", label: "Delete" });
    return opts;
  }, [canUnpublish]);

  const resetForm = () => {
    setRunAtLocal("");
    setPreset(CRON_PRESETS[0].value);
    setCustomCron("");
  };

  const handleSubmit = async () => {
    const config: ScheduleConfig = { action, scheduleKind: kind, timezone };
    if (kind === "once") {
      if (!runAtLocal) {
        toast.error("Pick a date and time.");
        return;
      }
      const parsed = new Date(runAtLocal);
      if (Number.isNaN(parsed.getTime())) {
        toast.error("Invalid date and time.");
        return;
      }
      if (parsed.getTime() <= Date.now()) {
        toast.error("The scheduled time must be in the future.");
        return;
      }
      config.runAt = parsed.toISOString();
    } else {
      if (!cronExpr) {
        toast.error("Provide a cron expression.");
        return;
      }
      config.cronExpr = cronExpr;
    }

    setSubmitting(true);
    try {
      await onConfirm(config);
      resetForm();
      await mutate();
    } catch (error) {
      // onConfirm surfaces its own toast; nothing more to do here.
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancelJob = async (id: number) => {
    try {
      const res = await fetch(`${schedulesUrl.split("?")[0]}/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to cancel schedule.");
      toast.success("Schedule canceled.");
      await mutate();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to cancel schedule.");
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <CalendarClock className="size-5" /> Schedule update
          </DialogTitle>
          <DialogDescription>
            Schedule a one-off or recurring change to this entry. Scheduled runs are committed by
            Pages CMS at the chosen time.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4">
          <div className="grid gap-2">
            <Label>Action</Label>
            <Select value={action} onValueChange={(v) => setAction(v as ScheduleAction)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {actionOptions.map((o) => (
                  <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            {action !== "delete" && (
              <p className="text-muted-foreground text-xs">Uses the current editor content.</p>
            )}
          </div>

          <div className="grid gap-2">
            <Label>When</Label>
            <Select value={kind} onValueChange={(v) => setKind(v as ScheduleKind)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="once">Once</SelectItem>
                <SelectItem value="recurring">Recurring</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {kind === "once" ? (
            <div className="grid gap-2">
              <Label htmlFor="schedule-runat">Date &amp; time</Label>
              <Input
                id="schedule-runat"
                type="datetime-local"
                value={runAtLocal}
                onChange={(e) => setRunAtLocal(e.target.value)}
              />
            </div>
          ) : (
            <>
              <div className="grid gap-2">
                <Label>Repeat</Label>
                <Select value={preset} onValueChange={setPreset}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CRON_PRESETS.map((p) => (
                      <SelectItem key={p.value} value={p.value}>{p.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {preset === "custom" && (
                  <Input
                    placeholder="Cron expression, e.g. 0 9 * * 1"
                    value={customCron}
                    onChange={(e) => setCustomCron(e.target.value)}
                  />
                )}
              </div>
              <div className="grid gap-2">
                <Label htmlFor="schedule-tz">Timezone</Label>
                <Input
                  id="schedule-tz"
                  value={timezone}
                  onChange={(e) => setTimezone(e.target.value)}
                />
              </div>
              {action === "publish" && (
                <p className="flex items-start gap-1.5 text-amber-600 text-xs dark:text-amber-500">
                  <Repeat className="mt-0.5 size-3.5 shrink-0" />
                  Each run re-commits the snapshot taken now, overwriting later manual edits.
                </p>
              )}
            </>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={submitting}>
            {submitting && <Loader2 className="size-4 animate-spin" />}
            Schedule
          </Button>
        </DialogFooter>

        {(isLoading || jobs.length > 0) && (
          <div className="mt-2 border-t pt-3">
            <p className="mb-2 font-medium text-sm">Scheduled for this entry</p>
            {isLoading ? (
              <p className="text-muted-foreground text-xs">Loading…</p>
            ) : (
              <ul className="grid gap-1.5">
                {jobs.map((job) => (
                  <li key={job.id} className="flex items-center justify-between gap-2 text-sm">
                    <span className="flex min-w-0 items-center gap-2">
                      <Badge variant={STATUS_VARIANT[job.status] ?? "outline"}>{job.status}</Badge>
                      <span className="truncate capitalize">{job.action}</span>
                      <span className="text-muted-foreground truncate">
                        {job.scheduleKind === "recurring"
                          ? job.cronExpr
                          : format(new Date(job.runAt), "PPp")}
                      </span>
                    </span>
                    {(job.status === "pending" || job.status === "failed") && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="size-7 shrink-0"
                        onClick={() => handleCancelJob(job.id)}
                        aria-label="Cancel schedule"
                      >
                        {job.status === "failed" ? <X className="size-4" /> : <Trash2 className="size-4" />}
                      </Button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
