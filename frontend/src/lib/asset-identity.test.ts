import { describe, expect, it } from "vitest";
import type { Asset } from "@/api/client";
import { assetDisplayName } from "./asset-identity";
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
