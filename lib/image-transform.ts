export type RasterTransform = {
  format?: "webp" | "jpeg" | "png";
  quality?: number;
  width?: number;
  height?: number;
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
    console.warn(`[image-transform] createImageBitmap failed for ${file.name}; uploading original.`, err);
    return file;
  }

  let { width, height } = bitmap;
  const maxW = cfg.width;
  const maxH = cfg.height;

  const scale = Math.min(
    maxW ? maxW / width  : 1,
    maxH ? maxH / height : 1,
    1,
  );
  width  = Math.round(width  * scale);
  height = Math.round(height * scale);

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
    (bitmap as any).close?.();
  }

  return new File([blob], swapExtension(file.name, FORMAT_EXT[format]), {
    type: mime,
    lastModified: file.lastModified,
  });
}
