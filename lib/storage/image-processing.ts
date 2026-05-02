import { env } from "cloudflare:workers";
import {
  type StorageConfig,
  s3Get,
  s3Upload,
} from "@/lib/storage/s3";

const IMAGE_EXTS = new Set(["jpg", "jpeg", "png", "webp", "avif", "heic", "tiff", "gif"]);
const PROCESSABLE_EXTS = new Set(["jpg", "jpeg", "png", "webp", "avif"]);

export const VARIANTS = {
  thumb: { width: 240, format: "webp" as const, quality: 80 },
  medium: { width: 1024, format: "webp" as const, quality: 82 },
  large: { width: 2048, format: "webp" as const, quality: 85 },
};

export type VariantName = keyof typeof VARIANTS;

const extOf = (key: string) => key.toLowerCase().split(".").pop() ?? "";

export const isImage = (key: string) => IMAGE_EXTS.has(extOf(key));

const variantKey = (key: string, name: VariantName) => {
  // foo/bar.jpg -> foo/bar.variants/thumb.webp
  const lastSlash = key.lastIndexOf("/");
  const dir = lastSlash >= 0 ? key.slice(0, lastSlash + 1) : "";
  const file = lastSlash >= 0 ? key.slice(lastSlash + 1) : key;
  const dot = file.lastIndexOf(".");
  const stem = dot > 0 ? file.slice(0, dot) : file;
  return `${dir}${stem}.variants/${name}.${VARIANTS[name].format}`;
};

const imagesBinding = (): { input: (b: any) => any } | null => {
  const e = env as unknown as { IMAGES?: { input: (b: any) => any } };
  return e.IMAGES ?? null;
};

// Download → optionally generate WebP variants → upload back. Best-effort:
// any failure is logged and returns the keys actually written.
export async function generateImageVariants(
  cfg: StorageConfig,
  key: string,
): Promise<{ written: { name: VariantName; key: string; size: number }[] }> {
  if (!isImage(key) || !PROCESSABLE_EXTS.has(extOf(key))) return { written: [] };
  const images = imagesBinding();
  if (!images) return { written: [] };

  const original = await s3Get(cfg, key);
  if (!original) return { written: [] };

  const written: { name: VariantName; key: string; size: number }[] = [];

  for (const [name, opts] of Object.entries(VARIANTS) as [VariantName, typeof VARIANTS[VariantName]][]) {
    try {
      const out = await images
        .input(original.body)
        .transform({ width: opts.width })
        .output({ format: `image/${opts.format}`, quality: opts.quality });
      const resp = out.response();
      const arrayBuffer = await resp.arrayBuffer();
      const bytes = new Uint8Array(arrayBuffer);
      const variant = variantKey(key, name);
      await s3Upload(cfg, variant, bytes, `image/${opts.format}`);
      written.push({ name, key: variant, size: bytes.byteLength });
    } catch (error) {
      console.warn(`[image-processing] failed variant ${name} for ${key}`, error);
    }
  }

  return { written };
}

// EXIF strip via re-encode to same format (best-effort, only for jpg/png/webp).
export async function stripImageMetadata(
  cfg: StorageConfig,
  key: string,
): Promise<boolean> {
  if (!isImage(key) || !PROCESSABLE_EXTS.has(extOf(key))) return false;
  const images = imagesBinding();
  if (!images) return false;

  const original = await s3Get(cfg, key);
  if (!original) return false;

  const ext = extOf(key);
  const targetFormat = ext === "png" ? "image/png" : ext === "webp" ? "image/webp" : "image/jpeg";

  try {
    const out = await images
      .input(original.body)
      .transform({})
      .output({ format: targetFormat, quality: 90 });
    const arrayBuffer = await out.response().arrayBuffer();
    const bytes = new Uint8Array(arrayBuffer);
    await s3Upload(cfg, key, bytes, targetFormat);
    return true;
  } catch (error) {
    console.warn(`[image-processing] EXIF strip failed for ${key}`, error);
    return false;
  }
}
