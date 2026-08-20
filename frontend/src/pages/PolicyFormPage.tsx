// Routes: /clusters/:id/policies/new (create) and
// /clusters/:id/policies/:policyId (edit).
//
// Dedicated form page (the Astronomer add/edit-as-a-page pattern, replacing the
// old drawer YAML editor). Edit an existing policy's mode + spec YAML, or author a
// new one. The AdmissionRule builder generates spec YAML for constellation-admission
// policies.
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft, FileJson } from "lucide-react";
import Editor from "@monaco-editor/react";

import { policies, type Policy } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";

export function PolicyFormPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  // cluster_id comes from the /clusters/:id parent route.
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const { policyId } = useParams<{ policyId: string }>();
  const isEdit = Boolean(policyId);
  const backTo = `/clusters/${clusterId ?? ""}/policies`;

  // No single-policy endpoint — load the list and find the one being edited.
  const q = useQuery({
    queryKey: ["policies", clusterId],
    queryFn: () => policies.list({ cluster_id: clusterId }),
    enabled: isEdit,
  });
  const active: Policy | null = q.data?.policies.find((p) => p.id === policyId) ?? null;

  // create-mode form state (edit mode reads from `active`).
  const [name, setName] = useState("");
  const [engine, setEngine] = useState("constellation-admission");
  const [category, setCategory] = useState("");
  const [createMode, setCreateMode] = useState<"monitor" | "enforce">("monitor");
  const [yaml, setYaml] = useState("");

  useEffect(() => {
    if (isEdit && active) setYaml(active.spec_yaml);
  }, [isEdit, active?.id, active?.spec_yaml, active]);

  // Live-update of mode on an existing policy (mirrors the old drawer's inline toggle).
  const modeUpdate = useMutation({
    mutationFn: (body: Partial<Policy>) => policies.update(active!.id, body),
    onSuccess: () => {
      toast.success("Policy updated");
      qc.invalidateQueries({ queryKey: ["policies", clusterId] });
    },
    onError: () => toast.error("Update failed"),
  });

  const save = useMutation({
    mutationFn: () => {
      if (isEdit) return policies.update(active!.id, { spec_yaml: yaml });
      return policies.create({
        name: name.trim(),
        engine: engine.trim(),
        category: category.trim() || undefined,
        mode: createMode,
        spec_yaml: yaml,
        enabled: true,
      });
    },
    onSuccess: () => {
      toast.success(isEdit ? "Policy updated" : "Policy created");
      qc.invalidateQueries({ queryKey: ["policies", clusterId] });
      qc.invalidateQueries({ queryKey: ["policies"] });
      navigate(backTo);
    },
    onError: () => toast.error("Save failed"),
  });

  const activeEngine = isEdit ? active?.engine : engine;
  const builderName = isEdit ? active?.name ?? "" : name;
  const saveDisabled = save.isPending || (isEdit ? yaml === active?.spec_yaml : !name.trim());
  const notFound = isEdit && !clusterLoading && !q.isLoading && !q.error && !active;

  return (
    <div className="space-y-6" data-testid="policies-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        backLink={
          <Link to={backTo} className="inline-flex items-center gap-1 hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Policies
          </Link>
        }
        title={isEdit ? active?.name ?? "Policy" : "Create Policy"}
        description={
          isEdit
            ? active?.description
            : "Author a policy — its engine, mode, and spec YAML. Run it in monitor mode before enforcing."
        }
      />

      {isEdit && (clusterLoading || q.isLoading) ? (
        <Card title="Policy">
          <div className="text-sm text-muted-foreground">Loading policy…</div>
        </Card>
      ) : notFound ? (
        <Card title="Policy">
          <div className="text-sm text-destructive">Policy not found.</div>
        </Card>
      ) : (
        <Card title="Policy" description="Mode, spec YAML, and (for admission policies) a guided rule builder.">
          <div data-testid="policy-editor">
            {!isEdit && (
              <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
                <label className="text-xs">
                  <div className="mb-1 text-muted-foreground">Name</div>
                  <input
                    className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    data-testid="policy-name-input"
                  />
                </label>
                <label className="text-xs">
                  <div className="mb-1 text-muted-foreground">Engine</div>
                  <input
                    className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
                    value={engine}
                    onChange={(e) => setEngine(e.target.value)}
                    data-testid="policy-engine-input"
                  />
                </label>
                <label className="text-xs">
                  <div className="mb-1 text-muted-foreground">Category</div>
                  <input
                    className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                    data-testid="policy-category-input"
                  />
                </label>
              </div>
            )}

            <div className="mb-3 flex items-center justify-end gap-2 text-xs">
              <label className="flex items-center gap-1">
                mode
                <select
                  value={isEdit ? active!.mode : createMode}
                  onChange={(e) => {
                    const mode = e.target.value as "monitor" | "enforce";
                    if (isEdit) modeUpdate.mutate({ mode });
                    else setCreateMode(mode);
                  }}
                  className="rounded-md border border-border bg-background px-1.5 py-0.5 text-xs"
                  data-testid="policy-mode-select"
                >
                  <option value="monitor">monitor</option>
                  <option value="enforce">enforce</option>
                </select>
              </label>
              <button
                type="button"
                disabled={saveDisabled}
                onClick={() => save.mutate()}
                className="rounded-md bg-foreground px-2.5 py-1 text-xs text-background hover:opacity-90 disabled:opacity-40"
                data-testid="policy-save"
              >
                {isEdit ? "Save YAML" : "Create policy"}
              </button>
            </div>
            {activeEngine === "constellation-admission" && (
              <AdmissionRuleBuilder
                policyName={builderName}
                onApply={setYaml}
              />
            )}
            <div className="overflow-hidden rounded-md border border-border">
              <Editor
                height="520px"
                language="yaml"
                theme="vs-dark"
                value={yaml}
                onChange={(v) => setYaml(v ?? "")}
                options={{
                  fontSize: 12,
                  minimap: { enabled: false },
                  tabSize: 2,
                  automaticLayout: true,
                }}
              />
            </div>

            <div className="mt-4 flex justify-end">
              <button
                type="button"
                onClick={() => navigate(backTo)}
                className="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-accent"
              >
                Cancel
              </button>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}

function AdmissionRuleBuilder({
  policyName,
  onApply,
}: {
  policyName: string;
  onApply: (yaml: string) => void;
}) {
  const [ruleName, setRuleName] = useState(policyName.split("/").pop() || policyName || "image-evidence-gate");
  const [maxSeverity, setMaxSeverity] = useState<"medium" | "high" | "critical">("high");
  const [maxAge, setMaxAge] = useState("24h");
  const [canonicalEngine, setCanonicalEngine] = useState("vulndb");
  const [sourceType, setSourceType] = useState<AdmissionEvidenceSource>("repository");
  const [requireDigestMatch, setRequireDigestMatch] = useState(true);
  const [requireKnown, setRequireKnown] = useState(true);
  const [requireBundle, setRequireBundle] = useState(true);
  const [requireFix, setRequireFix] = useState(false);
  const [requireTrustedAttestation, setRequireTrustedAttestation] = useState(false);
  const [attestationPredicateType, setAttestationPredicateType] = useState("https://slsa.dev/provenance/v1");
  const [attestationIdentity, setAttestationIdentity] = useState("");
  const [attestationIssuer, setAttestationIssuer] = useState("https://token.actions.githubusercontent.com");
  const [requireTrustedSignature, setRequireTrustedSignature] = useState(false);
  const [requireVerifierIdentity, setRequireVerifierIdentity] = useState(false);
  const [verifierIdentity, setVerifierIdentity] = useState("");

  return (
    <section className="mb-3 rounded-md border border-border bg-background p-3" data-testid="admission-rule-builder">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <FileJson className="h-4 w-4 text-muted-foreground" aria-hidden />
          <div>
            <h3 className="text-xs font-semibold">AdmissionRule Builder</h3>
          </div>
        </div>
        <button
          type="button"
          onClick={() => onApply(buildAdmissionRuleYAML({
            ruleName,
            maxSeverity,
            maxAge,
            canonicalEngine,
            sourceType,
            requireDigestMatch,
            requireKnown,
            requireBundle,
            requireFix,
            requireTrustedAttestation,
            attestationPredicateType,
            attestationIdentity,
            attestationIssuer,
            requireTrustedSignature,
            requireVerifierIdentity,
            verifierIdentity,
          }))}
          className="inline-flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1.5 text-xs hover:bg-accent/40"
          data-testid="admission-rule-builder-apply"
        >
          <FileJson className="h-3.5 w-3.5" aria-hidden />
          Apply YAML
        </button>
      </div>

      <div className="grid grid-cols-1 gap-2 md:grid-cols-4">
        <label className="space-y-1 text-xs">
          <span className="text-muted-foreground">Rule name</span>
          <input
            value={ruleName}
            onChange={(e) => setRuleName(e.target.value)}
            className="h-8 w-full rounded-md border border-border bg-card px-2 text-xs"
            data-testid="admission-rule-builder-name"
          />
        </label>
        <label className="space-y-1 text-xs">
          <span className="text-muted-foreground">Max severity</span>
          <select
            value={maxSeverity}
            onChange={(e) => setMaxSeverity(e.target.value as "medium" | "high" | "critical")}
            className="h-8 w-full rounded-md border border-border bg-card px-2 text-xs"
            data-testid="admission-rule-builder-severity"
          >
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="critical">critical</option>
          </select>
        </label>
        <label className="space-y-1 text-xs">
          <span className="text-muted-foreground">Max scan age</span>
          <input
            value={maxAge}
            onChange={(e) => setMaxAge(e.target.value)}
            className="h-8 w-full rounded-md border border-border bg-card px-2 text-xs"
            data-testid="admission-rule-builder-max-age"
          />
        </label>
        <label className="space-y-1 text-xs">
          <span className="text-muted-foreground">Canonical engine</span>
          <input
            value={canonicalEngine}
            onChange={(e) => setCanonicalEngine(e.target.value)}
            className="h-8 w-full rounded-md border border-border bg-card px-2 text-xs"
            data-testid="admission-rule-builder-engine"
          />
        </label>
      </div>

      <div className="mt-3 grid grid-cols-1 gap-2 text-xs md:grid-cols-3">
        <label className="space-y-1">
          <span className="text-muted-foreground">Evidence source</span>
          <select
            value={sourceType}
            onChange={(e) => setSourceType(e.target.value as AdmissionEvidenceSource)}
            className="h-8 w-full rounded-md border border-border bg-card px-2 text-xs"
            data-testid="admission-rule-builder-source"
          >
            <option value="repository">Repository / CI</option>
            <option value="runtime-agent">Runtime agent</option>
            <option value="registry">Registry</option>
            <option value="manual">Manual</option>
            <option value="any">Any source</option>
          </select>
        </label>
        <Toggle checked={requireDigestMatch} onChange={setRequireDigestMatch} label="Require digest match" testId="admission-rule-builder-digest-match" />
        <Toggle checked={requireKnown} onChange={setRequireKnown} label="Require known scan result" testId="admission-rule-builder-known" />
        <Toggle checked={requireBundle} onChange={setRequireBundle} label="Require VulnDB bundle" testId="admission-rule-builder-bundle" />
        <Toggle checked={requireFix} onChange={setRequireFix} label="Require fix available" testId="admission-rule-builder-fix" />
        <Toggle checked={requireTrustedAttestation} onChange={setRequireTrustedAttestation} label="Require trusted attestation" testId="admission-rule-builder-attestation" />
        <label className="space-y-1">
          <span className="text-muted-foreground">Attestation predicate</span>
          <input
            value={attestationPredicateType}
            onChange={(e) => setAttestationPredicateType(e.target.value)}
            disabled={!requireTrustedAttestation}
            className="h-8 w-full rounded-md border border-border bg-card px-2 text-xs disabled:opacity-50"
            data-testid="admission-rule-builder-attestation-predicate"
          />
        </label>
        <label className="space-y-1">
          <span className="text-muted-foreground">Attestation identity</span>
          <input
            value={attestationIdentity}
            onChange={(e) => setAttestationIdentity(e.target.value)}
            disabled={!requireTrustedAttestation}
            className="h-8 w-full rounded-md border border-border bg-card px-2 text-xs disabled:opacity-50"
            data-testid="admission-rule-builder-attestation-identity"
          />
        </label>
        <label className="space-y-1">
          <span className="text-muted-foreground">Attestation issuer</span>
          <input
            value={attestationIssuer}
            onChange={(e) => setAttestationIssuer(e.target.value)}
            disabled={!requireTrustedAttestation}
            className="h-8 w-full rounded-md border border-border bg-card px-2 text-xs disabled:opacity-50"
            data-testid="admission-rule-builder-attestation-issuer"
          />
        </label>
        <Toggle checked={requireTrustedSignature} onChange={setRequireTrustedSignature} label="Require trusted signature" testId="admission-rule-builder-signature" />
        <Toggle checked={requireVerifierIdentity} onChange={setRequireVerifierIdentity} label="Require verifier identity" testId="admission-rule-builder-identity-required" />
        <label className="space-y-1">
          <span className="text-muted-foreground">Allowed identity</span>
          <input
            value={verifierIdentity}
            onChange={(e) => setVerifierIdentity(e.target.value)}
            disabled={!requireVerifierIdentity}
            className="h-8 w-full rounded-md border border-border bg-card px-2 text-xs disabled:opacity-50"
            data-testid="admission-rule-builder-identity"
          />
        </label>
      </div>
    </section>
  );
}

type AdmissionEvidenceSource = "repository" | "runtime-agent" | "registry" | "manual" | "any";

function Toggle({
  checked,
  onChange,
  label,
  testId,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  testId: string;
}) {
  return (
    <label className="flex min-h-8 items-center gap-2 rounded-md border border-border bg-card px-2">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        data-testid={testId}
      />
      <span>{label}</span>
    </label>
  );
}

function buildAdmissionRuleYAML({
  ruleName,
  maxSeverity,
  maxAge,
  canonicalEngine,
  sourceType,
  requireDigestMatch,
  requireKnown,
  requireBundle,
  requireFix,
  requireTrustedAttestation,
  attestationPredicateType,
  attestationIdentity,
  attestationIssuer,
  requireTrustedSignature,
  requireVerifierIdentity,
  verifierIdentity,
}: {
  ruleName: string;
  maxSeverity: "medium" | "high" | "critical";
  maxAge: string;
  canonicalEngine: string;
  sourceType: AdmissionEvidenceSource;
  requireDigestMatch: boolean;
  requireKnown: boolean;
  requireBundle: boolean;
  requireFix: boolean;
  requireTrustedAttestation: boolean;
  attestationPredicateType: string;
  attestationIdentity: string;
  attestationIssuer: string;
  requireTrustedSignature: boolean;
  requireVerifierIdentity: boolean;
  verifierIdentity: string;
}) {
  const name = ruleName.trim() || "image-evidence-gate";
  const lines = [
    "apiVersion: constellation.alphabravo.io/v1alpha1",
    "kind: AdmissionRule",
    "metadata:",
    `  name: ${yamlString(name)}`,
    "spec:",
    "  match:",
    '    kinds: ["Pod"]',
    "  scanEvidence:",
    `    maxAge: ${yamlString(maxAge.trim() || "24h")}`,
    `    requireVulnDBBundle: ${requireBundle}`,
  ];
  if (sourceType !== "any") lines.push(`    sourceTypes: [${yamlString(sourceType)}]`);
  lines.push(`    requireDigestMatch: ${requireDigestMatch}`);
  if (requireTrustedAttestation) {
    lines.push("    requireTrustedAttestation: true");
    const predicate = attestationPredicateType.trim();
    const identity = attestationIdentity.trim();
    const issuer = attestationIssuer.trim();
    if (predicate) lines.push(`    attestationPredicateTypes: [${yamlString(predicate)}]`);
    if (identity) lines.push(`    allowedAttestationIdentities: [${yamlString(identity)}]`);
    if (issuer) lines.push(`    allowedAttestationIssuers: [${yamlString(issuer)}]`);
  }
  const engine = canonicalEngine.trim();
  if (engine) lines.push(`    canonicalEngines: [${yamlString(engine)}]`);
  lines.push(
    "  vulnerability:",
    `    maxAllowedSeverity: ${maxSeverity}`,
    `    requireKnownScanResult: ${requireKnown}`,
    `    requireFixAvailable: ${requireFix}`,
  );
  if (requireTrustedSignature || requireVerifierIdentity || verifierIdentity.trim()) {
    lines.push(
      "  imageArtifacts:",
      "    signature:",
      `      requireTrusted: ${requireTrustedSignature}`,
      `      requireVerifierIdentity: ${requireVerifierIdentity}`,
    );
    const identity = verifierIdentity.trim();
    if (identity) lines.push(`      allowedIdentities: [${yamlString(identity)}]`);
  }
  lines.push("  action: deny");
  return `${lines.join("\n")}\n`;
}

function yamlString(value: string) {
  return JSON.stringify(value);
}
