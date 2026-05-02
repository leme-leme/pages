declare namespace Cloudflare {
  interface Env {
    ASSETS: Fetcher;
    IMAGES: ImagesBinding;
    DB: D1Database;
    AE?: AnalyticsEngineDataset;
  }
}

interface AnalyticsEngineDataset {
  writeDataPoint(event: {
    indexes?: string[];
    blobs?: (string | undefined | null)[];
    doubles?: (number | undefined | null)[];
  }): void;
}

interface ImagesBinding {
  input(body: ReadableStream | ArrayBuffer | Uint8Array | Blob): {
    transform(opts: { width?: number; height?: number }): {
      output(opts: { format: string; quality?: number }): Promise<{
        response(): Response;
      }>;
    };
  };
}

interface CloudflareEnv extends Cloudflare.Env {}
