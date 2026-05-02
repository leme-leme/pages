import {
  handleImageOptimization,
  DEFAULT_DEVICE_SIZES,
  DEFAULT_IMAGE_SIZES,
} from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

interface ScheduledEvent {
  cron: string;
  scheduledTime: number;
}

export default {
  async fetch(
    request: Request,
    env: Cloudflare.Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/_vinext/image") {
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      return handleImageOptimization(
        request,
        {
          fetchAsset: (path) =>
            env.ASSETS.fetch(new Request(new URL(path, request.url))),
          transformImage: async (body, { width, format, quality }) => {
            const result = await env.IMAGES.input(body)
              .transform(width > 0 ? { width } : {})
              .output({ format, quality });
            return result.response();
          },
        },
        allowedWidths,
      );
    }

    try {
      return await handler.fetch(request, env, ctx);
    } catch (err: any) {
      console.error("[worker] handler.fetch threw", {
        url: request.url,
        method: request.method,
        name: err?.name,
        message: err?.message,
        stack: err?.stack,
        cause: err?.cause?.message,
        causeStack: err?.cause?.stack,
      });
      throw err;
    }
  },

  async scheduled(
    event: ScheduledEvent,
    _env: Cloudflare.Env,
    ctx: ExecutionContext,
  ): Promise<void> {
    if (event.cron === "0 3 * * *") {
      ctx.waitUntil((async () => {
        const { gcOrphanMedia } = await import("@/lib/storage/lifecycle");
        const result = await gcOrphanMedia();
        console.log("[scheduled] orphan-gc", { deleted: result.deleted.length });
      })());
      return;
    }

    if (event.cron === "*/30 * * * *") {
      ctx.waitUntil((async () => {
        const { pickReconcileTargets, reconcileBucketWithCache } =
          await import("@/lib/storage/lifecycle");
        const targets = await pickReconcileTargets(5);
        for (const target of targets) {
          try {
            const r = await reconcileBucketWithCache(target.owner, target.repo, target.branch);
            console.log("[scheduled] reconcile", target, r);
          } catch (error) {
            console.warn("[scheduled] reconcile failed", target, error);
          }
        }
      })());
      return;
    }

    if (event.cron === "0 2 * * *") {
      ctx.waitUntil((async () => {
        try {
          const { rollupYesterday } = await import("@/lib/analytics/rollup");
          const { rows } = await rollupYesterday();
          console.log("[scheduled] analytics-rollup", { rows });
        } catch (error) {
          console.warn("[scheduled] analytics-rollup failed", error);
        }
      })());
      return;
    }
  },
};
