import type { Asset, AssetImageDetail } from "@/api/client";

const digestOnly = /^(?:sha(?:256|384|512):|[a-f0-9]{64}$)/i;
const namedReference = (value?: string) => {
  const ref = value?.trim().split("@")[0] ?? "";
  return ref && !digestOnly.test(ref) ? ref : "";
};

/** Keep immutable digest identity separate from the human-readable image name. */
export function assetDisplayName(asset: Asset, image?: AssetImageDetail): string {
  if (asset.kind !== "image") return asset.name;
  if (asset.display_name) return asset.display_name;
  const labels = asset.labels ?? {};
  for (const value of [labels.image_ref_normalized, labels.image_ref]) {
    const ref = namedReference(value);
    if (ref) return ref;
  }
  let repository = namedReference(image?.repository || asset.repository || labels.image_repository);
  if (repository) {
    const registry = (image?.registry || asset.registry || "").replace(/\/$/, "");
    const first = repository.split("/")[0];
    const qualified = repository.includes("/") && (/[.:]/.test(first) || first === "localhost" || repository.startsWith(`${registry}/`));
    if (registry && !qualified) repository = `${registry}/${repository}`;
    const tag = image?.tag || asset.tag || labels.image_tag;
    if (tag && repository.lastIndexOf(":") <= repository.lastIndexOf("/")) repository += `:${tag}`;
    return repository;
  }
  return namedReference(asset.name) || "Unnamed image";
}
