import { env } from "cloudflare:workers";
import { and, eq, sql } from "drizzle-orm";
import { db } from "@/db";
import { projectAnalyticsConfigTable } from "@/db/schema";
import { getCachedConfig } from "@/lib/config-store";

export type ResolvedAnalytics = {
  source: "d1" | "config";
  ga4MeasurementId: string | null;
  cfBeaconToken: string | null;
  requireConsent: boolean;
  honorDnt: boolean;
};

const ENV_PLACEHOLDER = /^\$\{([A-Z0-9_]+)\}$/;

const resolveEnvValue = (value: string | undefined | null): string => {
  if (!value) return "";
  const match = ENV_PLACEHOLDER.exec(value.trim());
  if (!match) return value;
  const e = env as unknown as Record<string, string | undefined>;
  return e[match[1]] ?? "";
};

const fromD1 = async (
  owner: string,
  repo: string,
  branch: string,
): Promise<ResolvedAnalytics | null> => {
  const row = await db.query.projectAnalyticsConfigTable.findFirst({
    where: and(
      sql`lower(${projectAnalyticsConfigTable.owner}) = ${owner.toLowerCase()}`,
      sql`lower(${projectAnalyticsConfigTable.repo}) = ${repo.toLowerCase()}`,
      eq(projectAnalyticsConfigTable.branch, branch),
    ),
  })
    ?? await db.query.projectAnalyticsConfigTable.findFirst({
      where: and(
        sql`lower(${projectAnalyticsConfigTable.owner}) = ${owner.toLowerCase()}`,
        sql`lower(${projectAnalyticsConfigTable.repo}) = ${repo.toLowerCase()}`,
        eq(projectAnalyticsConfigTable.branch, ""),
      ),
    });
  if (!row) return null;
  if (!row.ga4MeasurementId && !row.cfBeaconToken) return null;
  return {
    source: "d1",
    ga4MeasurementId: row.ga4MeasurementId ?? null,
    cfBeaconToken: row.cfBeaconToken ?? null,
    requireConsent: !!row.requireConsent,
    honorDnt: !!row.honorDnt,
  };
};

type AnalyticsBlock = {
  ga4MeasurementId?: string;
  cfBeaconToken?: string;
  requireConsent?: boolean;
  honorDnt?: boolean;
};

export const findAnalyticsBlockInConfig = (configObject: any): AnalyticsBlock | null => {
  const block = configObject?.analytics;
  if (!block || typeof block !== "object") return null;
  return block as AnalyticsBlock;
};

const fromConfig = async (
  owner: string,
  repo: string,
  branch: string,
): Promise<ResolvedAnalytics | null> => {
  const cached = await getCachedConfig(owner, repo, branch).catch(() => null);
  const block = findAnalyticsBlockInConfig(cached?.object);
  if (!block) return null;

  const ga4 = resolveEnvValue(block.ga4MeasurementId) || null;
  const cf = resolveEnvValue(block.cfBeaconToken) || null;
  if (!ga4 && !cf) return null;

  return {
    source: "config",
    ga4MeasurementId: ga4,
    cfBeaconToken: cf,
    requireConsent: block.requireConsent ?? true,
    honorDnt: block.honorDnt ?? true,
  };
};

export const resolveAnalyticsConfig = async (
  owner: string,
  repo: string,
  branch: string,
): Promise<ResolvedAnalytics | null> => {
  return (await fromD1(owner, repo, branch)) ?? (await fromConfig(owner, repo, branch));
};
