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

  await db.insert(storageUsageTable)
    .values({
      owner: lowerOwner,
      repo: lowerRepo,
      branch: branchKey,
      bytesStored: Math.max(0, stored),
      bytesEgressed: Math.max(0, egressed),
      fileCount: Math.max(0, fileCount),
    })
    .onConflictDoUpdate({
      target: [
        sql`lower(${storageUsageTable.owner})`,
        sql`lower(${storageUsageTable.repo})`,
        storageUsageTable.branch,
      ],
      set: {
        bytesStored: sql`max(0, ${storageUsageTable.bytesStored} + ${stored})`,
        bytesEgressed: sql`max(0, ${storageUsageTable.bytesEgressed} + ${egressed})`,
        fileCount: sql`max(0, ${storageUsageTable.fileCount} + ${fileCount})`,
        updatedAt: new Date(),
      },
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
