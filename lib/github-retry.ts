/**
 * Retry helper for GitHub's transient branch-moved 409s.
 *
 * Rapid sequential commits to the same branch (multi-file uploads, bulk
 * deletes) intermittently fail with 409 "<branch> is at <sha> but expected
 * <sha>" — an internal ref race, not a real conflict. These are safe to
 * retry with backoff. Real conflicts (a stale file `sha` we supplied) have
 * different messages and are never retried here.
 */

export const isBranchMovedError = (error: any): boolean => {
  // Depending on how octokit wraps the failure, the GitHub message may only
  // be present on error.message (RequestError formats it as
  // "<message> - <documentation_url>"), so check both.
  const message = [error?.response?.data?.message, error?.message]
    .filter((m): m is string => typeof m === "string")
    .join(" ");
  return error?.status === 409
    && /is at [0-9a-f]{7,40} but expected [0-9a-f]{7,40}/i.test(message);
};

export const BRANCH_MOVED_FRIENDLY_MESSAGE =
  "GitHub is still syncing the previous commit (this happens during rapid consecutive changes). The file was not saved — retry it.";

// ~26s cumulative worst case: GitHub's read replica occasionally lags its
// own previous commit by 10s+ during a rapid commit burst, so short retry
// windows still lose files.
export async function withBranchMovedRetry<T>(
  fn: () => Promise<T>,
  attempts = 8,
): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (!isBranchMovedError(error) || attempt >= attempts) throw error;
      await new Promise((resolve) => setTimeout(resolve, 750 * attempt));
    }
  }
}
