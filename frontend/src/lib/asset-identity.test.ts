import { describe, expect, it } from "vitest";
import type { Asset, ImageScanResult } from "@/api/client";
import { assetDisplayName, imageReferenceName, imageReferenceDisplayName, imageReferenceDigest, imageScanDisplayName } from "./asset-identity";
const asset = (fields: Partial<Asset> = {}): Asset => ({ id: "image", kind: "image", name: "sha256:abcdef", labels: {}, ...fields } as Asset);
describe("image asset identity", () => {
  it("prefers the server display name while preserving workload names", () => {
    expect(assetDisplayName(asset({ display_name: "registry/team/api:v2" }))).toBe("registry/team/api:v2");
    expect(assetDisplayName(asset({ kind: "workload", name: "payments/api" }))).toBe("payments/api");
  });
  it("shows named references without their digest suffix", () => {
    expect(assetDisplayName(asset({ labels: { image_ref_normalized: "docker.io/pgvector/pgvector:pg16@sha256:abcdef" } }))).toBe("docker.io/pgvector/pgvector:pg16");
  });
  it.each([
    [{ registry: "docker.io", repository: "team/api", tag: "v2" }, "docker.io/team/api:v2"],
    [{ registry: "docker.io", repository: "docker.io/team/api", tag: "v2" }, "docker.io/team/api:v2"],
    [{ registry: "registry:5000", repository: "registry:5000/team/api", tag: "v2" }, "registry:5000/team/api:v2"],
    [{ repository: "team/api" }, "team/api"],
    [{ repository: "team/api:v1", tag: "v2" }, "team/api:v1"],
  ])("uses reported repository/tag without duplicate registry or invented tags", (fields, expected) => {
    expect(assetDisplayName(asset(fields))).toBe(expected);
  });
  it("does not promote a bare digest to the display name", () => {
    expect(assetDisplayName(asset({ labels: { image_ref: "sha256:abcdef" } }))).toBe("Unnamed image");
    expect(assetDisplayName(asset({ name: "a".repeat(64) }))).toBe("Unnamed image");
  });
});

describe("image scan identity", () => {
  it.each([
    ["repository tag", { image_repository: "registry:5000/team/app", image_tag: "v2", image_ref: "sha256:raw", image_ref_normalized: "sha256:raw" }, "registry:5000/team/app:v2"],
    ["repository digest suffix", { image_repository: "registry/team/app@sha256:raw", image_tag: "v2", image_ref: "sha256:raw" }, "registry/team/app:v2"],
    ["tag already reported", { image_repository: "registry/team/app:v1", image_tag: "v2" }, "registry/team/app:v1"],
    ["reference digest suffix", { image_ref: "registry/team/app:v2@sha256:raw" }, "registry/team/app:v2"],
    ["normalized reference", { image_ref: "sha256:raw", image_ref_normalized: "registry/team/app:v2@sha256:raw" }, "registry/team/app:v2"],
    ["raw named fallback", { image_ref_normalized: "sha256:raw", image_ref: "registry/team/app:v2@sha256:raw" }, "registry/team/app:v2"],
    ["digest only", { image_repository: "sha256:raw", image_ref: "sha256:raw", image_ref_normalized: "sha256:raw" }, "Unnamed image"],
    ["bare digest", { image_ref: "a".repeat(64) }, "Unnamed image"],
  ])("formats %s without exposing its immutable digest", (_label, fields, expected) => {
    expect(imageScanDisplayName(fields as ImageScanResult)).toBe(expected);
  });
  it("cleans identity metadata without promoting digest-only fields", () => {
    const reference = "registry/team/app:v2@sha256:raw";
    expect(imageReferenceName(reference)).toBe("registry/team/app:v2");
    expect(imageReferenceName("sha256:raw")).toBe("");
  });
});


it.each([
  ["registry/team/app:v2@sha256:exact", "sha256:exact"],
  ["sha256:exact", "sha256:exact"],
  ["a".repeat(64), "a".repeat(64)],
  ["registry/team/app:v2", undefined],
])("separates immutable digest identity from reference %s", (reference, expected) => {
  expect(imageReferenceDigest(reference)).toBe(expected);
  expect(imageReferenceDisplayName("sha256:exact", "registry/team/app:v2@sha256:exact")).toBe("registry/team/app:v2");
});
