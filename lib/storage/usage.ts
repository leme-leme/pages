import { db } from "@/db";
import { storageUsageTable } from "@/db/schema";
import { and, eq, sql } from "drizzle-orm";

export type UsageDelta = {
  bytesStoredDelta?: number;
  bytesEgressedDelta?: number;
  fileCountDelta?: number;
};

const recordUsage = async (
  owner: string,
  repo: string,
  branch: string,
  delta: UsageDelta,
) => {
  const lowerOwner = owner.toLowerCase();
  const lowerRepo = repo.toLowerCase();
  const branchKey = branch ?? "";

  const stored = delta.bytesStoredDelta ?? 0;
  const egressed = delta.bytesEgressedDelta ?? 0;
  const fileCount = delta.fileCountDelta ?? 0;
  if (!stored && !egressed && !fileCount) return;

  const existing = await db.query.storageUsageTable.findFirst({
    where: and(
      sql`lower(${storageUsageTable.owner}) = ${lowerOwner}`,
      sql`lower(${storageUsageTable.repo}) = ${lowerRepo}`,
      eq(storageUsageTable.branch, branchKey),
    ),
  });

  if (existing) {
    await db.update(storageUsageTable)
      .set({
        bytesStored: Math.max(0, existing.bytesStored + stored),
        bytesEgressed: Math.max(0, existing.bytesEgressed + egressed),
        fileCount: Math.max(0, existing.fileCount + fileCount),
        updatedAt: new Date(),
      })
      .where(eq(storageUsageTable.id, existing.id));
    return;
  }

  await db.insert(storageUsageTable).values({
    owner: lowerOwner,
    repo: lowerRepo,
    branch: branchKey,
    bytesStored: Math.max(0, stored),
    bytesEgressed: Math.max(0, egressed),
    fileCount: Math.max(0, fileCount),
  });
};

const getUsage = async (owner: string, repo: string, branch?: string) => {
  const lowerOwner = owner.toLowerCase();
  const lowerRepo = repo.toLowerCase();
  if (branch != null) {
    return db.query.storageUsageTable.findFirst({
      where: and(
        sql`lower(${storageUsageTable.owner}) = ${lowerOwner}`,
        sql`lower(${storageUsageTable.repo}) = ${lowerRepo}`,
        eq(storageUsageTable.branch, branch),
      ),
    });
  }
  return db.query.storageUsageTable.findMany({
    where: and(
      sql`lower(${storageUsageTable.owner}) = ${lowerOwner}`,
      sql`lower(${storageUsageTable.repo}) = ${lowerRepo}`,
    ),
  });
};

export { recordUsage, getUsage };
