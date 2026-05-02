"use client";

import { useEffect, useState } from "react";
import { DocumentTitle, formatRepoBranchTitle } from "@/components/document-title";
import { useConfig } from "@/contexts/config-context";
import { useUser } from "@/contexts/user-context";
import { hasGithubIdentity } from "@/lib/authz-shared";
import { requireApiSuccess } from "@/lib/api-client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyTitle,
} from "@/components/ui/empty";
import { Loader, Save, Trash2 } from "lucide-react";
import { toast } from "sonner";

const DEFAULT_FORM = {
  endpoint: "",
  region: "us-east-1",
  bucket: "",
  prefix: "",
  accessKey: "",
  secretKey: "",
  forcePathStyle: true,
  visibility: "public" as "public" | "private",
  thresholdMB: 25,
  maxFileMB: -1,
  publicBaseUrl: "",
};

export default function Page() {
  const { config } = useConfig();
  const { user } = useUser();

  const [form, setForm] = useState(DEFAULT_FORM);
  const [hasAccessKey, setHasAccessKey] = useState(false);
  const [hasSecretKey, setHasSecretKey] = useState(false);
  const [source, setSource] = useState<"d1" | "env" | "config" | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!config) return;
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const response = await fetch(
          `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/storage/config`,
        );
        const result = await requireApiSuccess<any>(response, "Failed to load storage config");
        if (cancelled) return;
        const cfg = result.data;
        if (cfg) {
          setForm({
            endpoint: cfg.endpoint ?? "",
            region: cfg.region ?? "us-east-1",
            bucket: cfg.bucket ?? "",
            prefix: cfg.prefix ?? "",
            accessKey: "",
            secretKey: "",
            forcePathStyle: cfg.forcePathStyle ?? true,
            visibility: (cfg.visibility ?? "public") as "public" | "private",
            thresholdMB: cfg.thresholdBytes ? Math.round(cfg.thresholdBytes / 1024 / 1024) : 25,
            maxFileMB: cfg.maxFileBytes && cfg.maxFileBytes > 0 ? Math.round(cfg.maxFileBytes / 1024 / 1024) : -1,
            publicBaseUrl: cfg.publicBaseUrl ?? "",
          });
          setHasAccessKey(!!cfg.hasAccessKey);
          setHasSecretKey(!!cfg.hasSecretKey);
          setSource(cfg.source ?? null);
        } else {
          setForm(DEFAULT_FORM);
          setHasAccessKey(false);
          setHasSecretKey(false);
          setSource(null);
        }
      } catch (err: any) {
        toast.error(err?.message ?? "Failed to load storage config");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [config]);

  if (!config) throw new Error("Configuration not found.");

  if (!hasGithubIdentity(user)) {
    return (
      <Empty className="absolute inset-0 border-0 rounded-none">
        <EmptyHeader>
          <EmptyTitle>Access denied</EmptyTitle>
          <EmptyDescription>Only GitHub users can manage storage settings.</EmptyDescription>
        </EmptyHeader>
      </Empty>
    );
  }

  const handleSave = async () => {
    if (!form.endpoint || !form.bucket) {
      toast.error("Endpoint and bucket are required.");
      return;
    }
    if (!hasAccessKey && !form.accessKey) {
      toast.error("Access key is required.");
      return;
    }
    if (!hasSecretKey && !form.secretKey) {
      toast.error("Secret key is required.");
      return;
    }
    setSaving(true);
    try {
      const body: Record<string, any> = {
        endpoint: form.endpoint,
        region: form.region || "us-east-1",
        bucket: form.bucket,
        prefix: form.prefix,
        forcePathStyle: form.forcePathStyle,
        visibility: form.visibility,
        thresholdBytes: Math.max(1, form.thresholdMB) * 1024 * 1024,
        maxFileBytes: form.maxFileMB > 0 ? form.maxFileMB * 1024 * 1024 : -1,
        publicBaseUrl: form.publicBaseUrl || null,
      };
      if (form.accessKey) body.accessKey = form.accessKey;
      if (form.secretKey) body.secretKey = form.secretKey;

      const response = await fetch(
        `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/storage/config`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
      );
      await requireApiSuccess<any>(response, "Failed to save storage config");
      toast.success("Storage settings saved.");
      if (form.accessKey) setHasAccessKey(true);
      if (form.secretKey) setHasSecretKey(true);
      setForm((prev) => ({ ...prev, accessKey: "", secretKey: "" }));
      setSource("d1");
    } catch (err: any) {
      toast.error(err?.message ?? "Failed to save storage config");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    setSaving(true);
    try {
      const response = await fetch(
        `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/storage/config`,
        { method: "DELETE" },
      );
      await requireApiSuccess<any>(response, "Failed to delete storage config");
      toast.success("Storage settings cleared.");
      setForm(DEFAULT_FORM);
      setHasAccessKey(false);
      setHasSecretKey(false);
      setSource(null);
    } catch (err: any) {
      toast.error(err?.message ?? "Failed to delete storage config");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="max-w-screen-md mx-auto flex-1 flex flex-col w-full space-y-4">
      <DocumentTitle
        title={formatRepoBranchTitle("Storage", config.owner, config.repo, config.branch)}
      />
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">Storage</h1>
        <p className="text-sm text-muted-foreground">
          Per-project S3-compatible bucket (R2, MinIO, Backblaze B2, AWS S3) used for direct media uploads. Credentials are encrypted at rest.
          {source === "config" && (
            <> Currently sourced from <code className="text-xs px-1 py-0.5 bg-muted rounded">media.storage</code> in <code className="text-xs px-1 py-0.5 bg-muted rounded">.pages.yml</code>; saving here overrides it.</>
          )}
          {source === "env" && (
            <> Currently using global worker env defaults; saving here overrides them for this project.</>
          )}
        </p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-16 text-muted-foreground">
          <Loader className="size-5 animate-spin" />
        </div>
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Bucket</CardTitle>
              <CardDescription>Where uploaded media lives.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <Field label="Endpoint" required hint="https://<account>.r2.cloudflarestorage.com / https://s3.amazonaws.com / etc.">
                <Input
                  type="url"
                  value={form.endpoint}
                  onChange={(e) => setForm({ ...form, endpoint: e.target.value })}
                  placeholder="https://..."
                />
              </Field>
              <Field label="Region">
                <Input
                  value={form.region}
                  onChange={(e) => setForm({ ...form, region: e.target.value })}
                  placeholder="us-east-1"
                />
              </Field>
              <Field label="Bucket" required>
                <Input
                  value={form.bucket}
                  onChange={(e) => setForm({ ...form, bucket: e.target.value })}
                  placeholder="my-media-bucket"
                />
              </Field>
              <Field label="Prefix" hint="Object key prefix (folder).">
                <Input
                  value={form.prefix}
                  onChange={(e) => setForm({ ...form, prefix: e.target.value })}
                  placeholder="uploads/"
                />
              </Field>
              <Field label="Force path style" hint="Required for R2, MinIO and most S3-compatibles.">
                <Switch
                  checked={form.forcePathStyle}
                  onCheckedChange={(checked) => setForm({ ...form, forcePathStyle: checked })}
                />
              </Field>
              <Field label="Visibility">
                <Select
                  value={form.visibility}
                  onValueChange={(value) => setForm({ ...form, visibility: value as "public" | "private" })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="public">Public (URL)</SelectItem>
                    <SelectItem value="private">Private (presigned)</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
              <Field label="Public base URL" hint="Optional CDN/custom-domain prefix served from the bucket.">
                <Input
                  type="url"
                  value={form.publicBaseUrl}
                  onChange={(e) => setForm({ ...form, publicBaseUrl: e.target.value })}
                  placeholder="https://media.example.com"
                />
              </Field>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Credentials</CardTitle>
              <CardDescription>
                Stored encrypted in D1. Leave blank to keep the existing credentials.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <Field label="Access key" required={!hasAccessKey}>
                <Input
                  value={form.accessKey}
                  onChange={(e) => setForm({ ...form, accessKey: e.target.value })}
                  placeholder={hasAccessKey ? "•••••••• (saved)" : "AKIA..."}
                  autoComplete="off"
                />
              </Field>
              <Field label="Secret key" required={!hasSecretKey}>
                <Input
                  type="password"
                  value={form.secretKey}
                  onChange={(e) => setForm({ ...form, secretKey: e.target.value })}
                  placeholder={hasSecretKey ? "•••••••• (saved)" : ""}
                  autoComplete="off"
                />
              </Field>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Upload limits</CardTitle>
              <CardDescription>Direct-to-S3 kicks in for files larger than the threshold.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <Field label="Threshold (MB)" hint="Files at or above this size go straight to the bucket.">
                <Input
                  type="number"
                  min={1}
                  value={form.thresholdMB}
                  onChange={(e) => setForm({ ...form, thresholdMB: Number(e.target.value) || 1 })}
                />
              </Field>
              <Field label="Max file size (MB)" hint="-1 for unlimited.">
                <Input
                  type="number"
                  min={-1}
                  value={form.maxFileMB}
                  onChange={(e) => setForm({ ...form, maxFileMB: Number(e.target.value) || -1 })}
                />
              </Field>
            </CardContent>
          </Card>

          <div className="flex items-center justify-between gap-2 pb-4">
            {(hasAccessKey || hasSecretKey || source === "d1") ? (
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button variant="outline" disabled={saving}>
                    <Trash2 className="size-4" /> Clear settings
                  </Button>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle>Clear storage settings?</AlertDialogTitle>
                    <AlertDialogDescription>
                      Removes the bucket configuration and credentials for this project. Existing uploads in the bucket are not affected.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction onClick={handleDelete}>Clear</AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            ) : <span />}
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <Loader className="size-4 animate-spin" /> : <Save className="size-4" />}
              Save
            </Button>
          </div>
        </>
      )}
    </div>
  );
}

function Field({
  label,
  hint,
  required,
  children,
}: {
  label: string;
  hint?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label className="text-sm font-medium">
        {label}{required && <span className="text-destructive"> *</span>}
      </Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}
