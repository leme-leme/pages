/**
 * Create an Octokit instance that wraps the requests with a check for credentials
 * to surface revoked/lost access (401 Bad credentials).
 *
 * The custom fetch also adds bounded retry/backoff for idempotent (GET/HEAD)
 * requests on transient failures — GitHub 5xx, short secondary rate limits, and
 * network errors. Server components (e.g. the repo/branch layouts) make several
 * live GitHub calls per navigation with short-lived in-memory caches, so a
 * single transient blip would otherwise crash the RSC render. Retrying here
 * absorbs the vast majority of those before they ever surface.
 */

import { Octokit } from "@octokit/rest";
import { createHttpError } from "@/lib/api-error";

// Up to MAX_RETRIES extra attempts (so MAX_RETRIES + 1 total) for idempotent calls.
const MAX_RETRIES = 2;
// Only auto-wait for short secondary rate limits; longer ones fail fast.
const RATE_LIMIT_RETRY_CAP_SECONDS = 3;

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

// Exponential backoff with jitter: ~300ms, ~600ms, … capped at 2.5s.
const backoffDelay = (attempt: number) => {
  const base = Math.min(2500, 300 * 2 ** attempt);
  return base + Math.floor(Math.random() * 200);
};

const isIdempotentMethod = (method?: string) => {
  const normalized = (method || "GET").toUpperCase();
  return normalized === "GET" || normalized === "HEAD";
};

const getRetryAfter = (response: Response) => {
  const retryAfter = response.headers.get("retry-after");
  if (retryAfter) return retryAfter;

  const remaining = response.headers.get("x-ratelimit-remaining");
  const reset = response.headers.get("x-ratelimit-reset");
  if (remaining !== "0" || !reset) return null;

  const resetSeconds = Number(reset);
  if (!Number.isFinite(resetSeconds)) return null;

  return String(Math.max(1, resetSeconds - Math.floor(Date.now() / 1000)));
};

const isGithubRateLimitResponse = (response: Response, message: string) => {
  if (response.status !== 403 && response.status !== 429) return false;

  const normalizedMessage = message.toLowerCase();
  return (
    normalizedMessage.includes("rate limit") ||
    response.headers.get("x-ratelimit-remaining") === "0" ||
    Boolean(response.headers.get("retry-after"))
  );
};

export const createOctokitInstance = (token: string, options?: any) => {
  if (!token) throw new Error("Auth token is required to initialize Octokit");

  return new Octokit({
    ...options,
    auth: token,
    request: {
      fetch: async (url: string, requestOptions: RequestInit) => {
        const idempotent = isIdempotentMethod(requestOptions?.method as string | undefined);

        for (let attempt = 0; ; attempt++) {
          let response: Response;
          try {
            response = await fetch(url, requestOptions);
          } catch (networkError) {
            // Network/timeout/abort: retry idempotent requests, else surface.
            if (idempotent && attempt < MAX_RETRIES) {
              await sleep(backoffDelay(attempt));
              continue;
            }
            throw networkError;
          }

          // Transient server errors: retry idempotent requests with backoff.
          if (idempotent && response.status >= 500 && attempt < MAX_RETRIES) {
            await sleep(backoffDelay(attempt));
            continue;
          }

          if (response.status === 401 || response.status === 403 || response.status === 429) {
            let message = response.status === 401
              ? "GitHub authentication failed."
              : "GitHub request failed.";

            try {
              const data = await response.clone().json();
              if (typeof data.message === "string") {
                message = data.message;
              }
              if (response.status === 401 && data.message === "Bad credentials") {
                message = "GitHub authentication failed: bad credentials.";
              }
            } catch {}

            if (response.status === 401) {
              throw createHttpError(message, 401);
            }

            if (isGithubRateLimitResponse(response, message)) {
              const retryAfter = getRetryAfter(response);
              const retryAfterSeconds = retryAfter ? Number(retryAfter) : null;

              // Auto-retry only short secondary rate limits for idempotent calls.
              if (
                idempotent &&
                attempt < MAX_RETRIES &&
                retryAfterSeconds !== null &&
                Number.isFinite(retryAfterSeconds) &&
                retryAfterSeconds <= RATE_LIMIT_RETRY_CAP_SECONDS
              ) {
                await sleep(retryAfterSeconds * 1000 + backoffDelay(attempt));
                continue;
              }

              throw createHttpError(
                retryAfter
                  ? `GitHub rate limit reached. Please wait ${retryAfter} seconds and try again.`
                  : "GitHub rate limit reached. Please wait a minute and try again.",
                429,
                retryAfter ? { "Retry-After": retryAfter } : undefined,
              );
            }
          }

          return response;
        }
      },
    },
  });
};
