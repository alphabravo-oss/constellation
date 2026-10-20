import type { Asset, AssetImageDetail, ImageScanResult } from "@/api/client";

const digestOnly = /^(?:sha(?:256|384|512):|[a-f0-9]{64}$)/i;
export const imageReferenceName = (value?: string) => {
  const ref = value?.trim().split("@")[0] ?? "";
  return ref && !digestOnly.test(ref) ? ref : "";
};

interface ImageNameFields {
  references?: (string | undefined)[];
  repository?: string;
  registry?: string;
  tag?: string;
  name?: string;
}

function imageDisplayName(image: ImageNameFields): string {
  for (const value of image.references ?? []) {
    const ref = imageReferenceName(value);
    if (ref) return ref;
  }
  let repository = imageReferenceName(image.repository);
  if (repository) {
    const registry = (image.registry || "").replace(/\/$/, "");
    const first = repository.split("/")[0];
    const qualified = repository.includes("/") && (/[.:]/.test(first) || first === "localhost" || repository.startsWith(`${registry}/`));
    if (registry && !qualified) repository = `${registry}/${repository}`;
    if (image.tag && repository.lastIndexOf(":") <= repository.lastIndexOf("/")) repository += `:${image.tag}`;
    return repository;
  }
  return imageReferenceName(image.name) || "Unnamed image";
}

/** Keep immutable digest identity separate from the human-readable image name. */
export function assetDisplayName(asset: Asset, image?: AssetImageDetail): string {
  if (asset.kind !== "image") return asset.name;
  if (asset.display_name) return asset.display_name;
  const labels = asset.labels ?? {};
  return imageDisplayName({
    references: [labels.image_ref_normalized, labels.image_ref],
    repository: image?.repository || asset.repository || labels.image_repository,
    registry: image?.registry || asset.registry,
    tag: image?.tag || asset.tag || labels.image_tag,
    name: asset.name,
  });
}

/** Scan results use their reported repository/tag before falling back to a named reference. */
export function imageScanDisplayName(image: Pick<ImageScanResult, "image_repository" | "image_tag" | "image_ref_normalized" | "image_ref">): string {
  return imageDisplayName({
    repository: image.image_repository,
    tag: image.image_tag,
    name: imageReferenceName(image.image_ref_normalized) || image.image_ref,
  });
}

/** Use a reported normalized name when the raw workload reference is digest-only. */
export function imageReferenceDisplayName(...references: (string | undefined)[]): string {
  return imageDisplayName({ references });
}

/** Extract exact immutable identity without turning it into the displayed name. */
export function imageReferenceDigest(...references: (string | undefined)[]): string | undefined {
  for (const value of references) {
    const reference = value?.trim();
    if (!reference) continue;
    if (digestOnly.test(reference)) return reference;
    const suffix = reference.split("@")[1];
    if (suffix && digestOnly.test(suffix)) return suffix;
  }
}
