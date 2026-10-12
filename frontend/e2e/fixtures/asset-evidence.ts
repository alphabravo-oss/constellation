import { expect, type Page } from "@playwright/test";
import type { AssetDetail, ImageAcceptance } from "../../src/api/client";

export const assetEvidenceCluster = "11111111-1111-4111-8111-111111111111";
export const assetEvidenceID = "22222222-2222-4222-8222-222222222222";
export const assetEvidencePath = `/clusters/${assetEvidenceCluster}/assets/${assetEvidenceID}`;

// This fixture intercepts every image-acceptance write; tests never mutate the
// running application's risk decisions.
export async function installAssetEvidenceFixture(page: Page) {
  const writes: string[] = [];
  let decision: ImageAcceptance | undefined;
  const digest = "sha256:reviewed-fixture";
  await page.route(/\/api\/v1\/clusters(?:\?.*)?$/, (route) => route.fulfill({ json: { clusters: [{ id: assetEvidenceCluster, name: "Asset evidence fixture", distro: "k3s", state: "connected" }] } }));
  await page.route(new RegExp(`/api/v1/assets/${assetEvidenceID}(?:\\?.*)?$`), async (route) => {
    expect(route.request().method()).toBe("GET");
    const data: AssetDetail = {
      asset: { id: assetEvidenceID, cluster_id: assetEvidenceCluster, name: "ghcr.io/demo/api", kind: "image", digest, criticality: "high", labels: { owner: "fixture-team" }, ai_workload: false, finding_count: 1, critical_findings: 0, high_findings: 1, open_findings: 1, sbom_count: 1, first_seen_at: "2026-10-12T12:00:00Z", last_seen_at: "2026-10-12T12:00:00Z" },
      image: { registry: "ghcr.io", repository: "demo/api", digest, tag: "v1", layers: [{ digest: "sha256:layer" }], architectures: ["amd64"], signed: true, signature_info: {}, pulled_at: "2026-10-12T12:00:00Z" },
      findings: [{ id: "finding-fixture", kind: "vulnerability", title: "glibc heap overflow", external_id: "CVE-fixture", severity: "high", risk_score: 70, lifecycle: "open", last_seen_at: "2026-10-12T12:00:00Z" }],
      sboms: [{ id: "sbom-fixture", format: "spdx-2.3", sha256: "sha256:inventory", created_at: "2026-10-12T12:00:00Z" }], image_acceptances: decision ? [decision] : [],
    };
    await route.fulfill({ json: data });
  });
  await page.route(/\/api\/v1\/assets\/[^/]+\/image-acceptances(?:\/[^/]+\/revoke)?(?:\?.*)?$/, async (route) => {
    const request = route.request();
    expect(request.method()).toBe("POST");
    const url = new URL(request.url());
    const body = request.postDataJSON();
    expect(body).toMatchObject({ expected_image_digest: digest, cluster_id: assetEvidenceCluster });
    expect(url.pathname).toContain(`/assets/${assetEvidenceID}/image-acceptances`);
    writes.push(url.pathname);
    const identity = { asset_id: assetEvidenceID, cluster_id: assetEvidenceCluster, image_digest: digest };
    if (url.pathname.endsWith("/revoke")) {
      expect(url.pathname).toContain(`/${decision?.id}/revoke`);
      decision = { ...decision!, status: "revoked", revoked_at: new Date().toISOString() };
      await route.fulfill({ json: { ...identity, status: "revoked", image_acceptances: [decision] } });
    } else {
      decision = { id: "33333333-3333-4333-8333-333333333333", image_digest: digest, rationale: body.rationale, accepted_until: body.accepted_until, status: "active", approver_id: "fixture-user", created_at: new Date().toISOString() };
      await route.fulfill({ status: 201, json: { ...identity, id: decision.id, image_acceptances: [decision] } });
    }
  });
  await page.route(/\/api\/v1\/vulnerability-exceptions(?:\?.*)?$/, async (route) => {
    expect(new URL(route.request().url()).searchParams.get("cluster_id")).toBe(assetEvidenceCluster);
    await route.fulfill({ json: { exceptions: decision ? [{ id: `image-${decision.id}`, title: "Image digest acceptance", reason: decision.rationale, status: decision.status === "active" ? "approved" : decision.status, requester: { id: "fixture-user", email: "fixture@example.test" }, expires_at: decision.accepted_until, cve_refs: [], finding_refs: [], scope: { clusters: [assetEvidenceCluster], namespaces: [], workloads: [], images: [digest] }, audit_events: decision.status === "revoked" ? [{ at: decision.revoked_at, actor: "fixture@example.test", action: "image.accept-risk.revoke" }] : [], notes: [] }] : [] } });
  });
  return writes;
}
