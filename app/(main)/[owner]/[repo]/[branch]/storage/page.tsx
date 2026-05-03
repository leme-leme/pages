"use client";

import Link from "next/link";
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
import { CheckCircle2, ChevronDown, ExternalLink, Loader, Save, Trash2, XCircle } from "lucide-react";
import { toast } from "sonner";

type Source = "d1" | "env" | "config";

type ActiveConfig = {
  endpoint: string;
  region: string;
  bucket: string;
  prefix: string;
  forcePathStyle: boolean;
  visibility: "public" | "private";
  thresholdBytes: number;
  maxFileBytes: number;
  publicBaseUrl: string | null;
  source: Source;
  hasAccessKey: boolean;
  hasSecretKey: boolean;
};

type ConfigBlock = {
  provider?: "r2" | "s3";
  bucket?: string;
  accountId?: string;
  endpoint?: string;
  region?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  publicUrl?: string;
  prefix?: string;
  visibility?: "public" | "private";
  forcePathStyle?: boolean;
  thresholdBytes?: number;
  maxFileBytes?: number;
};

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

const sourceLabel: Record<Source, string> = {
  d1: "Per-project override (encrypted in D1)",
  config: "media.storage in .pages.yml",
  env: "Worker env defaults",
};

export default function Page() {
  const { config } = useConfig();
  const { user } = useUser();

  const [active, setActive] = useState<ActiveConfig | null>(null);
  const [configBlock, setConfigBlock] = useState<ConfigBlock | null>(null);
  const [envStatus, setEnvStatus] = useState<Record<string, boolean>>({});
  const [form, setForm] = useState(DEFAULT_FORM);
  const [showOverride, setShowOverride] = useState(false);
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
        const data = result.data ?? {};
        const cfg = (data.active ?? null) as ActiveConfig | null;
        setActive(cfg);
        setConfigBlock((data.configBlock ?? null) as ConfigBlock | null);
        setEnvStatus((data.envStatus ?? {}) as Record<string, boolean>);
        setShowOverride(cfg?.source === "d1");

        if (cfg) {
          setForm({
            endpoint: cfg.endpoint,
            region: cfg.region,
            bucket: cfg.bucket,
            prefix: cfg.prefix,
            accessKey: "",
            secretKey: "",
            forcePathStyle: cfg.forcePathStyle,
            visibility: cfg.visibility,
            thresholdMB: cfg.thresholdBytes ? Math.round(cfg.thresholdBytes / 1024 / 1024) : 25,
            maxFileMB: cfg.maxFileBytes && cfg.maxFileBytes > 0 ? Math.round(cfg.maxFileBytes / 1024 / 1024) : -1,
            publicBaseUrl: cfg.publicBaseUrl ?? "",
          });
        } else {
          setForm(DEFAULT_FORM);
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

  const hasAccessKey = active?.hasAccessKey ?? false;
  const hasSecretKey = active?.hasSecretKey ?? false;
  const source = active?.source ?? null;

  const handleSave = async () => {
    if (!form.endpoint || !form.bucket) {
      toast.error("Endpoint and bucket are required.");
      return;
    }
    if (source !== "d1" && !form.accessKey) {
      toast.error("Access key is required.");
      return;
    }
    if (source !== "d1" && !form.secretKey) {
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
      toast.success("Override saved.");
      setForm((prev) => ({ ...prev, accessKey: "", secretKey: "" }));
      setActive((prev) => ({
        ...(prev ?? ({} as ActiveConfig)),
        endpoint: body.endpoint,
        region: body.region,
        bucket: body.bucket,
        prefix: body.prefix,
        forcePathStyle: body.forcePathStyle,
        visibility: body.visibility,
        thresholdBytes: body.thresholdBytes,
        maxFileBytes: body.maxFileBytes,
        publicBaseUrl: body.publicBaseUrl,
        source: "d1",
        hasAccessKey: hasAccessKey || !!form.accessKey,
        hasSecretKey: hasSecretKey || !!form.secretKey,
      }));
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
      await requireApiSuccess<any>(response, "Failed to delete storage override");
      toast.success("Override cleared.");
      const reload = await fetch(
        `/api/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/storage/config`,
      );
      const result = await requireApiSuccess<any>(reload, "Failed to reload storage config");
      const data = result.data ?? {};
      setActive((data.active ?? null) as ActiveConfig | null);
      setConfigBlock((data.configBlock ?? null) as ConfigBlock | null);
      setEnvStatus((data.envStatus ?? {}) as Record<string, boolean>);
      setShowOverride(false);
      setForm(DEFAULT_FORM);
    } catch (err: any) {
      toast.error(err?.message ?? "Failed to delete storage override");
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
          S3-compatible bucket used for direct media uploads.
        </p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-16 text-muted-foreground">
          <Loader className="size-5 animate-spin" />
        </div>
      ) : (
        <>
          <ActiveStatusCard active={active} />

          {configBlock && (
            <ConfigBlockCard
              block={configBlock}
              envStatus={envStatus}
              configHref={`/${config.owner}/${config.repo}/${encodeURIComponent(config.branch)}/configuration`}
            />
          )}

          {!showOverride ? (
            <Card>
              <CardHeader>
                <CardTitle>Per-project override</CardTitle>
                <CardDescription>
                  Encrypted credentials stored in D1, taking precedence over <code className="text-xs px-1 py-0.5 bg-muted rounded">.pages.yml</code>.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Button variant="outline" onClick={() => setShowOverride(true)}>
                  <ChevronDown className="size-4" /> Configure override
                </Button>
              </CardContent>
            </Card>
          ) : (
            <>
              <Card>
                <CardHeader>
                  <CardTitle>Per-project override</CardTitle>
                  <CardDescription>Encrypted in D1. Wins over <code className="text-xs px-1 py-0.5 bg-muted rounded">.pages.yml</code> and worker env.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 sm:grid-cols-2">
                    <Field label="Endpoint" required>
                      <Input
                        type="url"
                        value={form.endpoint}
                        onChange={(e) => setForm({ ...form, endpoint: e.target.value })}
                        placeholder="https://..."
                      />
                    </Field>
                    <Field label="Bucket" required>
                      <Input
                        value={form.bucket}
                        onChange={(e) => setForm({ ...form, bucket: e.target.value })}
                        placeholder="my-media-bucket"
                      />
                    </Field>
                    <Field label="Access key" required={!hasAccessKey}>
                      <Input
                        value={form.accessKey}
                        onChange={(e) => setForm({ ...form, accessKey: e.target.value })}
                        placeholder={hasAccessKey ? "•••••••• (saved)" : ""}
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
                  </div>

                  <details className="group">
                    <summary className="cursor-pointer text-sm font-medium text-muted-foreground hover:text-foreground select-none flex items-center gap-1.5">
                      <ChevronDown className="size-4 transition-transform group-open:rotate-180" /> Advanced
                    </summary>
                    <div className="grid gap-4 sm:grid-cols-2 pt-4">
                      <Field label="Region">
                        <Input
                          value={form.region}
                          onChange={(e) => setForm({ ...form, region: e.target.value })}
                          placeholder="us-east-1"
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
                            <SelectItem value="public">Public</SelectItem>
                            <SelectItem value="private">Private (presigned)</SelectItem>
                          </SelectContent>
                        </Select>
                      </Field>
                      <Field label="Prefix" hint="Object key prefix.">
                        <Input
                          value={form.prefix}
                          onChange={(e) => setForm({ ...form, prefix: e.target.value })}
                          placeholder="uploads/"
                        />
                      </Field>
                      <Field label="Public base URL" hint="CDN / custom domain.">
                        <Input
                          type="url"
                          value={form.publicBaseUrl}
                          onChange={(e) => setForm({ ...form, publicBaseUrl: e.target.value })}
                          placeholder="https://media.example.com"
                        />
                      </Field>
                      <Field label="Threshold (MB)" hint="Files at or above this size skip GitHub.">
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
                      <Field label="Force path style" hint="Required for most non-AWS providers.">
                        <Switch
                          checked={form.forcePathStyle}
                          onCheckedChange={(checked) => setForm({ ...form, forcePathStyle: checked })}
                        />
                      </Field>
                    </div>
                  </details>
                </CardContent>
              </Card>

              <div className="flex items-center justify-between gap-2 pb-4">
                {source === "d1" ? (
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button variant="outline" disabled={saving}>
                        <Trash2 className="size-4" /> Clear override
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>Clear per-project override?</AlertDialogTitle>
                        <AlertDialogDescription>
                          Removes the D1 row for this project. Storage will fall back to <code>.pages.yml</code> or worker env. Existing uploads in the bucket are unaffected.
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction onClick={handleDelete}>Clear</AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                ) : (
                  <Button variant="ghost" onClick={() => setShowOverride(false)}>
                    Cancel
                  </Button>
                )}
                <Button onClick={handleSave} disabled={saving}>
                  {saving ? <Loader className="size-4 animate-spin" /> : <Save className="size-4" />}
                  Save override
                </Button>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}

function ActiveStatusCard({ active }: { active: ActiveConfig | null }) {
  if (!active) {
    return (
      <Card>
        <CardHeader className="flex flex-row items-start gap-3 space-y-0">
          <XCircle className="size-5 text-muted-foreground shrink-0 mt-0.5" />
          <div>
            <CardTitle>Not configured</CardTitle>
            <CardDescription>Uploads &gt; 25 MB will fail.</CardDescription>
          </div>
        </CardHeader>
      </Card>
    );
  }
  return (
    <Card>
      <CardHeader className="flex flex-row items-start gap-3 space-y-0">
        <CheckCircle2 className="size-5 text-emerald-600 shrink-0 mt-0.5" />
        <div className="min-w-0 flex-1">
          <CardTitle>Active · <span className="font-mono text-sm">{active.bucket}</span></CardTitle>
          <CardDescription>
            {sourceLabel[active.source]} · uploads ≥ {Math.round(active.thresholdBytes / 1024 / 1024)} MB go direct
          </CardDescription>
        </div>
      </CardHeader>
    </Card>
  );
}

function ConfigBlockCard({
  block,
  envStatus,
  configHref,
}: {
  block: ConfigBlock;
  envStatus: Record<string, boolean>;
  configHref: string;
}) {
  const envEntries = Object.entries(envStatus);
  const missing = envEntries.filter(([, set]) => !set).length;

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-2">
        <div>
          <CardTitle>From .pages.yml</CardTitle>
          <CardDescription>
            <code className="text-xs px-1 py-0.5 bg-muted rounded">media.storage</code> block, with <code className="text-xs px-1 py-0.5 bg-muted rounded">${"{}"}</code> placeholders resolved against worker env at upload time.
          </CardDescription>
        </div>
        <Button asChild variant="ghost" size="sm">
          <Link href={configHref}>
            Edit <ExternalLink className="size-3.5" />
          </Link>
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        <pre className="text-xs bg-muted p-3 rounded overflow-x-auto">
          <code>{renderYaml(block)}</code>
        </pre>
        {envEntries.length > 0 && (
          <div className="space-y-2">
            <div className="text-sm font-medium">
              Worker secrets {missing > 0 ? <span className="text-destructive">({missing} missing)</span> : <span className="text-emerald-600">(all set)</span>}
            </div>
            <ul className="grid gap-1.5 sm:grid-cols-2">
              {envEntries.map(([name, set]) => (
                <li key={name} className="flex items-center gap-2 text-sm">
                  {set
                    ? <CheckCircle2 className="size-4 text-emerald-600 shrink-0" />
                    : <XCircle className="size-4 text-destructive shrink-0" />}
                  <code className="text-xs px-1 py-0.5 bg-muted rounded truncate">{name}</code>
                </li>
              ))}
            </ul>
            {missing > 0 && (
              <p className="text-xs text-muted-foreground">
                Missing secrets must be added with <code className="text-xs px-1 py-0.5 bg-muted rounded">npx wrangler secret put NAME</code> and a redeploy.
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function renderYaml(block: ConfigBlock): string {
  const order: (keyof ConfigBlock)[] = [
    "provider", "bucket", "accountId", "endpoint", "region",
    "accessKeyId", "secretAccessKey", "publicUrl", "prefix",
    "visibility", "forcePathStyle", "thresholdBytes", "maxFileBytes",
  ];
  const lines: string[] = ["media:", "  storage:"];
  for (const key of order) {
    const value = block[key];
    if (value === undefined || value === null || value === "") continue;
    lines.push(`    ${key}: ${value}`);
  }
  return lines.join("\n");
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
