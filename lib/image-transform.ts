/**
 * Client-side raster-image transformation applied before media upload.
 *
 * Config shape mirrors Sveltia CMS's `media_library.config.transformations`
 * so the .pages.yml author can drop-in the same block they'd use there:
 *
 *   media:
 *     - name: images
 *       input: public/images
 *       output: /images
 *       transformations:
 *         raster_image:
 *           format: webp      # webp | jpeg | png
 *           quality: 82       # 0–100 (mapped to 0–1 for canvas API)
 *           width: 2400       # max dimension; aspect ratio preserved
 *           height: 2400
 *
 * Images uploaded through Pages CMS's media dialog get re-encoded in the
 * browser before the base64 body is posted to the /files endpoint — same
 * benefit Sveltia got: raw camera JPEGs go in, ~5–10× smaller WebPs hit
 * the repo.
 *
 * SVGs and unknown image types pass through unchanged. Non-image files
 * (videos, zips, docs) are untouched.
 */

export type RasterTransform = {
  format?: "webp" | "jpeg" | "png";
  quality?: number; // 0–100
  width?: number;   // max width in px; aspect preserved
  height?: number;  // max height in px; aspect preserved
};

export type ImageTransformations = {
  raster_image?: RasterTransform;
  svg?: { optimize?: boolean };
};

const FORMAT_MIME: Record<NonNullable<RasterTransform["format"]>, string> = {
  webp: "image/webp",
  jpeg: "image/jpeg",
  png:  "image/png",
};

const FORMAT_EXT: Record<NonNullable<RasterTransform["format"]>, string> = {
  webp: "webp",
  jpeg: "jpg",
  png:  "png",
};

const swapExtension = (name: string, ext: string): string =>
  name.includes(".") ? name.replace(/\.[^.]+$/, `.${ext}`) : `${name}.${ext}`;

const isRasterImage = (file: File): boolean =>
  file.type.startsWith("image/") && file.type !== "image/svg+xml";

/**
 * Returns a re-encoded File when `transformations.raster_image` is set
 * and `file` is a transformable raster image. Otherwise returns `file`
 * unchanged. Never throws — a transform failure falls back to the
 * original file so uploads still succeed on unsupported formats.
 */
export async function transformImage(
  file: File,
  transformations?: ImageTransformations,
): Promise<File> {
  const cfg = transformations?.raster_image;
  if (!cfg || !isRasterImage(file)) return file;

  const format = cfg.format ?? "webp";
  const qualityPct = cfg.quality ?? 82;
  const quality = Math.min(Math.max(qualityPct, 0), 100) / 100;

  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch (err) {
    // createImageBitmap() can reject on exotic formats (HEIC on non-Safari,
    // bad EXIF, etc.). Ship the original rather than blocking the upload.
    console.warn(`[image-transform] createImageBitmap failed for ${file.name}; uploading original.`, err);
    return file;
  }

  let { width, height } = bitmap;
  const maxW = cfg.width;
  const maxH = cfg.height;

  // Scale down only — never upscale small images.
  const scale = Math.min(
    maxW ? maxW / width  : 1,
    maxH ? maxH / height : 1,
    1,
  );
  width  = Math.round(width  * scale);
  height = Math.round(height * scale);

  // Prefer OffscreenCanvas when available (background thread safe + faster);
  // fall back to a detached <canvas> in browsers that don't expose it yet.
  const mime = FORMAT_MIME[format];
  let blob: Blob;
  try {
    if (typeof OffscreenCanvas !== "undefined") {
      const canvas = new OffscreenCanvas(width, height);
      const ctx = canvas.getContext("2d");
      if (!ctx) throw new Error("2d context unavailable on OffscreenCanvas");
      ctx.drawImage(bitmap, 0, 0, width, height);
      blob = await canvas.convertToBlob({ type: mime, quality });
    } else {
      const canvas = document.createElement("canvas");
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext("2d");
      if (!ctx) throw new Error("2d context unavailable on HTMLCanvasElement");
      ctx.drawImage(bitmap, 0, 0, width, height);
      blob = await new Promise<Blob>((resolve, reject) => {
        canvas.toBlob(
          (b) => (b ? resolve(b) : reject(new Error("canvas.toBlob returned null"))),
          mime,
          quality,
        );
      });
    }
  } finally {
    // ImageBitmap holds a decoded-image buffer; release it so the GC
    // doesn't have to chase it down later.
    (bitmap as any).close?.();
  }

  return new File([blob], swapExtension(file.name, FORMAT_EXT[format]), {
    type: mime,
    lastModified: file.lastModified,
  });
}
