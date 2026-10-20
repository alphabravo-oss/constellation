// Existing policies are edited here; /policies/new uses PolicyWizardPage.
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { FileJson } from "lucide-react";
import Editor from "@monaco-editor/react";
import "@/lib/monaco";
import { policies, type Policy } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useEditorVisit } from "@/hooks/useEditorVisit";
import { useRouteSearchParams } from "@/lib/route-search";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, Select } from "@/components/ui/form";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";

export function PolicyFormPage() {
  const { clusterId } = useCluster();
  const { policyId } = useParams({ strict: false });
  const { visit } = useEditorVisit(["policy", clusterId, policyId]);
  const [params] = useRouteSearchParams();
  const fromAdmission = params.get("from") === "admission";
  const backTo = clusterId ? `/clusters/${clusterId}/${fromAdmission ? "admission" : "policies"}` : "/clusters";
  const q = useQuery({ queryKey: ["policy-editor", clusterId, policyId], queryFn: () => policies.list({ cluster_id: clusterId }), enabled: !!clusterId && !!policyId, gcTime: 0 });
  const active = q.data?.policies.find((policy) => policy.id === policyId);
  return <div className="space-y-6" data-testid="policies-page" data-cluster-id={clusterId ?? ""}>
    <PageHeader title={active?.name ?? "Edit policy"} description="Review the policy mode and YAML. Both changes apply when you save."
      backLink={<Link to="." href={backTo}>Back to {fromAdmission ? "Admission Control" : "Policies"}</Link>} />
    {!clusterId || !policyId ? <ErrorState title="Select a policy in its cluster." />
      : q.isPending ? <LoadingState label="Loading policy…" />
      : !active ? <ErrorState title="This policy could not be loaded for the selected cluster." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />
      : <>
        {q.isError && <p role="alert" className="text-sm text-status-error">Could not refresh this policy. Your draft is preserved.</p>}
        <PolicyEditor key={visit.context} editorContext={visit.context} initial={active} backTo={backTo} />
      </>}
  </div>;
}

function PolicyEditor({ editorContext, initial, backTo }: { editorContext: string; initial: Policy; backTo: string }) {
  const { isCurrent } = useEditorVisit([editorContext]);
  const [yaml, setYaml] = useState(initial.spec_yaml);
  const [mode, setMode] = useState(initial.mode);
  const qc = useQueryClient();
  const navigate = useNavigate();
  const changed = yaml !== initial.spec_yaml || mode !== initial.mode;
  const save = useMutation({
    mutationFn: () => policies.update(initial.id, { spec_yaml: yaml, mode }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["policies"] }); void qc.invalidateQueries({ queryKey: ["admission-rules"] }); if (isCurrent()) void navigate({ href: backTo }); },
  });
  return <Card title="Policy" description="Monitor records policy decisions. Enforce can block matching workloads.">
    <form data-testid="policy-editor" onSubmit={(event) => { event.preventDefault(); if (changed && yaml.trim() && !save.isPending) save.mutate(); }}>
      <fieldset disabled={save.isPending} className="space-y-5">
        <Field label="Mode" htmlFor="policy-mode"><Select id="policy-mode" data-testid="policy-mode-select" value={mode} onChange={(e) => setMode(e.target.value as Policy["mode"])}><option value="monitor">Monitor</option><option value="enforce">Enforce</option></Select></Field>
        {initial.engine === "constellation-admission" && <Collapse label="Advanced rule builder"><AdmissionRuleBuilder policyName={initial.name} onApply={setYaml} /></Collapse>}
        <div className="overflow-hidden rounded-md border border-border">
          <Editor height="520px" language="yaml" theme="vs-dark" value={yaml} onChange={(value) => setYaml(value ?? "")}
            options={{ fontSize: 12, minimap: { enabled: false }, tabSize: 2, automaticLayout: true, readOnly: save.isPending, ariaLabel: "Policy YAML" }} />
        </div>
        {save.isError && <p role="alert" className="text-sm text-status-error">Could not save this policy. Your draft is preserved. Check the YAML and try again.</p>}
        <div className="flex gap-3"><Button type="submit" variant="primary" disabled={!changed || !yaml.trim()} data-testid="policy-save">{save.isPending ? "Saving…" : "Save changes"}</Button><Button type="button" variant="ghost" onClick={() => navigate({ href: backTo })}>Cancel</Button></div>
      </fieldset>
    </form>
  </Card>;
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
