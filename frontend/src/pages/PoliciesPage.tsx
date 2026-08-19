// Policy catalog UI.
//
// Layout: a category-grouped list of policies on the left; each policy has an enable
// toggle + monitor/enforce mode selector. Clicking a policy opens its YAML in a Monaco
// editor on the right with a "Save" action. This mirrors StackRox's policy management
// pane + NeuVector's "Admission Rules" catalog feel.
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import Editor from "@monaco-editor/react";
import { CheckCircle2, Download, Eye, FileJson, GitCompare, ListChecks, Pencil, Play, Plus, Power, ShieldCheck, UploadCloud } from "lucide-react";

import {
  policies,
  type AdmissionProfile,
  type AdmissionProfileBundle,
  type AdmissionProfileImportResponse,
  type PolicySimulation,
  type Policy,
} from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { Drawer } from "@/components/ui/drawer";
import { DataTable, type Column } from "@/components/ui/data-table";

const SAMPLE_ADMISSION_MANIFEST = `apiVersion: v1
kind: Pod
metadata:
  name: privileged-debug
  namespace: default
spec:
  containers:
    - name: shell
      image: busybox:latest
      securityContext:
        privileged: true
        runAsUser: 0
`;

export function PoliciesPage() {
  const qc = useQueryClient();
  // Cluster-scoped: policies with cluster_id matching the active cluster OR
  // NULL (org-wide) are shown — the latter cover org-default admission rules.
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const q = useQuery({
    queryKey: ["policies", clusterId],
    queryFn: () => policies.list({ cluster_id: clusterId }),
  });
  const profilesQ = useQuery({
    queryKey: ["admission-profiles"],
    queryFn: () => policies.admissionProfiles(),
  });

  const [tab, setTab] = useTabParam("tab", "catalog");
  const [activeID, setActiveID] = useState<string | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const active: Policy | undefined = useMemo(
    () => q.data?.policies.find((p) => p.id === activeID) ?? q.data?.policies[0],
    [q.data, activeID],
  );

  const [yaml, setYaml] = useState<string>("");
  const [manifest, setManifest] = useState(SAMPLE_ADMISSION_MANIFEST);
  const [profileSource, setProfileSource] = useState<"catalog" | "bundle">("catalog");
  const [selectedProfileID, setSelectedProfileID] = useState("");
  const [profileMode, setProfileMode] = useState<"" | "monitor" | "enforce">("");
  const [profileEnabled, setProfileEnabled] = useState<"" | "enabled" | "disabled">("");
  const [bundleText, setBundleText] = useState("");
  const [profilePreview, setProfilePreview] = useState<AdmissionProfileImportResponse | null>(null);
  useEffect(() => {
    if (active) setYaml(active.spec_yaml);
  }, [active?.id, active?.spec_yaml, active]);
  useEffect(() => {
    if (!selectedProfileID && profilesQ.data?.profiles.length) {
      setSelectedProfileID(profilesQ.data.profiles[0].id);
    }
  }, [profilesQ.data?.profiles, selectedProfileID]);

  const update = useMutation({
    mutationFn: (body: Partial<Policy>) => policies.update(active!.id, body),
    onSuccess: () => {
      toast.success("Policy updated");
      qc.invalidateQueries({ queryKey: ["policies", clusterId] });
    },
    onError: () => toast.error("Update failed"),
  });

  const simulation = useMutation({
    mutationFn: () => policies.simulate({ manifest }, { cluster_id: clusterId }),
    onSuccess: (data) => toast.success(`Admission simulation: ${data.decision}`),
    onError: () => toast.error("Simulation failed"),
  });

  const exportProfile = useMutation({
    mutationFn: () => policies.exportAdmissionProfile(selectedProfileID),
    onSuccess: (bundle) => {
      setBundleText(JSON.stringify(bundle, null, 2));
      setProfileSource("bundle");
      toast.success("Profile exported");
    },
    onError: () => toast.error("Export failed"),
  });

  const dryRunProfile = useMutation({
    mutationFn: () => policies.importAdmissionProfile(buildProfileImportBody({
      source: profileSource,
      profileID: selectedProfileID,
      bundleText,
      mode: profileMode,
      enabled: profileEnabled,
      dryRun: true,
    })),
    onSuccess: (data) => {
      setProfilePreview(data);
      toast.success(`Previewed ${data.policies.length} rules`);
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Preview failed"),
  });

  const importProfile = useMutation({
    mutationFn: () => policies.importAdmissionProfile(buildProfileImportBody({
      source: profileSource,
      profileID: selectedProfileID,
      bundleText,
      mode: profileMode,
      enabled: profileEnabled,
      dryRun: false,
    })),
    onSuccess: (data) => {
      setProfilePreview(data);
      toast.success(`Imported ${data.imported} rules`);
      qc.invalidateQueries({ queryKey: ["policies", clusterId] });
      qc.invalidateQueries({ queryKey: ["policies"] });
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Import failed"),
  });

  if (clusterLoading) return <p className="text-sm text-muted-foreground" data-testid="policies-loading">Loading cluster…</p>;
  if (q.isPending) return <p className="text-sm text-muted-foreground">Loading policies…</p>;

  const list = q.data?.policies ?? [];
  const byCategory = groupBy(list, (p) => p.category || "general");
  const enabledCount = list.filter((p) => p.enabled).length;
  const enforceCount = list.filter((p) => p.mode === "enforce").length;
  const profileCount = profilesQ.data?.profiles.length ?? 0;

  const openEditor = (id: string) => { setActiveID(id); setEditorOpen(true); };

  const catalogTab = (
    <div className="space-y-4" data-testid="policies-layout">
      <section className="space-y-4" data-testid="policy-rail">
        {Object.entries(byCategory).map(([cat, ps]) => (
          <section key={cat}>
            <h2 className="mb-2 text-xs font-semibold uppercase text-muted-foreground">{cat}</h2>
            <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {ps.map((p) => (
                <li
                  key={p.id}
                  className={`group rounded-md border bg-card p-3 transition-colors ${
                    active?.id === p.id && editorOpen ? "border-[color:var(--color-primary)] ring-1 ring-[color:var(--color-primary)]/30" : "border-border hover:border-[color-mix(in_oklab,var(--color-primary)_30%,var(--color-border))]"
                  }`}
                  data-testid={`policy-row-${p.name}`}
                >
                  <button
                    type="button"
                    onClick={() => openEditor(p.id)}
                    className="flex w-full items-center justify-between gap-2 text-left"
                  >
                    <span className="truncate text-sm font-medium">{p.name}</span>
                    <span
                      className={`shrink-0 rounded-md px-1.5 py-0.5 text-[10px] ${
                        p.mode === "enforce"
                          ? "bg-[color:var(--color-severity-high)]/15 text-[color:var(--color-severity-high)]"
                          : "bg-[color:var(--color-severity-medium)]/15 text-[color:var(--color-severity-medium)]"
                      }`}
                    >
                      {p.mode}
                    </span>
                  </button>
                  <div className="mt-2 flex items-center justify-between gap-2 text-[11px] text-muted-foreground">
                    <label className="flex items-center gap-1">
                      <input
                        type="checkbox"
                        checked={p.enabled}
                        onChange={(e) =>
                          policies.update(p.id, { enabled: e.target.checked }).then(() => {
                            qc.invalidateQueries({ queryKey: ["policies"] });
                          })
                        }
                        data-testid={`policy-toggle-${p.name}`}
                      />
                      enabled
                    </label>
                    <span className="inline-flex items-center gap-1">
                      <span className="truncate">{p.engine}</span>
                      <Pencil className="h-3 w-3 opacity-0 transition-opacity group-hover:opacity-100" aria-hidden />
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          </section>
        ))}
        {list.length === 0 && (
          <p className="text-xs text-muted-foreground">
            No policies yet. Seed one via the admission webhook engine catalog or POST
            <code> /api/v1/policies</code>.
          </p>
        )}
      </section>
    </div>
  );

  const simulatorTab = (
    <div className="space-y-4 rounded-lg border border-border bg-card p-4" data-testid="policy-simulator">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">Admission Simulator</h2>
          <p className="mt-1 text-xs text-muted-foreground">
            Dry-run Kubernetes manifests against enabled policies before switching to enforce.
          </p>
        </div>
        <ShieldCheck className="h-4 w-4 text-muted-foreground" aria-hidden />
      </div>

      <textarea
        value={manifest}
        onChange={(e) => setManifest(e.target.value)}
        spellCheck={false}
        className="h-72 w-full resize-y rounded-md border border-border bg-background p-3 font-mono text-xs"
        data-testid="policy-simulator-manifest"
      />

      <button
        type="button"
        onClick={() => simulation.mutate()}
        disabled={simulation.isPending}
        className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-foreground px-3 py-2 text-xs text-background hover:opacity-90 disabled:opacity-50"
        data-testid="policy-simulator-run"
      >
        <Play className="h-3.5 w-3.5" aria-hidden />
        Run dry-run admission review
      </button>

      {simulation.data && (
        <div className="space-y-3" data-testid="policy-simulator-results">
          <div className="rounded-md border border-border p-3">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs text-muted-foreground">Decision</span>
              <Status value={simulation.data.decision} />
            </div>
            <dl className="mt-3 grid grid-cols-2 gap-2 text-xs md:grid-cols-3">
              <Info label="Workload" value={`${simulation.data.workload.kind}/${simulation.data.workload.name}`} />
              <Info label="Namespace" value={simulation.data.workload.namespace} />
              <Info label="Mode" value={simulation.data.enforcement_mode} />
              <Info label="Dry run" value={simulation.data.admission_review.dry_run ? "yes" : "no"} />
              <Info label="Sends webhook" value={simulation.data.admission_review.sends_webhook ? "yes" : "no"} />
              <Info label="Persists decision" value={simulation.data.admission_review.persists_decision ? "yes" : "no"} />
            </dl>
          </div>

          <div className="space-y-2">
            {simulation.data.matches.map((match) => (
              <SimulationMatchCard key={match.policy_id} match={match} />
            ))}
            {simulation.data.matches.length === 0 && (
              <p className="rounded-md bg-muted p-3 text-xs text-muted-foreground">No enabled policy matched this manifest.</p>
            )}
          </div>

          <div className="rounded-md border border-border p-3 text-xs" data-testid="policy-simulator-guardrails">
            <div className="font-medium">Guardrails</div>
            <div className="mt-2 space-y-2">
              {simulation.data.guardrails.map((guardrail) => (
                <div key={guardrail.id} className="flex items-start justify-between gap-2">
                  <span className="text-muted-foreground">{guardrail.name}</span>
                  <Status value={guardrail.status} />
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div className="space-y-6" data-testid="policies-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Policies"
        description="Rules that gate what's allowed to run: admission, signature, license, and runtime policies. Toggle each on or off, and run it in monitor mode before enforcing."
        actions={
          <Link
            to="/policies/new"
            className="inline-flex items-center gap-1 rounded-md bg-foreground px-3 py-1.5 text-xs text-background hover:opacity-90"
            data-testid="policies-create-cta"
          >
            <Plus className="h-3.5 w-3.5" /> Create Policy
          </Link>
        }
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Policies" value={list.length} icon={<ListChecks className="h-3.5 w-3.5" />} />
        <StatCard label="Enabled" value={enabledCount} icon={<Power className="h-3.5 w-3.5" />} />
        <StatCard label="Enforcing" value={enforceCount} icon={<ShieldCheck className="h-3.5 w-3.5" />} tone={enforceCount > 0 ? "high" : "neutral"} />
        <StatCard label="Admission profiles" value={profileCount} icon={<FileJson className="h-3.5 w-3.5" />} />
      </section>

      <Tabs
        value={tab}
        onValueChange={setTab}
        items={[
          { value: "catalog", label: "Policy catalog", count: list.length, content: catalogTab },
          {
            value: "profiles",
            label: "Admission profiles",
            count: profileCount,
            content: (
              <AdmissionProfilePanel
                profiles={profilesQ.data?.profiles ?? []}
                policies={list}
                loading={profilesQ.isPending}
                source={profileSource}
                setSource={(source) => {
                  setProfileSource(source);
                  setProfilePreview(null);
                }}
                selectedProfileID={selectedProfileID}
                setSelectedProfileID={(id) => {
                  setSelectedProfileID(id);
                  setProfilePreview(null);
                }}
                mode={profileMode}
                setMode={setProfileMode}
                enabled={profileEnabled}
                setEnabled={setProfileEnabled}
                bundleText={bundleText}
                setBundleText={(text) => {
                  setBundleText(text);
                  setProfilePreview(null);
                }}
                preview={profilePreview}
                onExport={() => exportProfile.mutate()}
                onDryRun={() => dryRunProfile.mutate()}
                onImport={() => importProfile.mutate()}
                busy={exportProfile.isPending || dryRunProfile.isPending || importProfile.isPending}
              />
            ),
          },
          { value: "simulator", label: "Admission simulator", content: simulatorTab },
        ]}
      />

      <Drawer
        open={editorOpen}
        onOpenChange={setEditorOpen}
        width="xl"
        title={active ? active.name : "Policy"}
        description={active?.description}
      >
        {active && (
          <div data-testid="policy-editor">
            <div className="mb-3 flex items-center justify-end gap-2 text-xs">
              <label className="flex items-center gap-1">
                mode
                <select
                  value={active.mode}
                  onChange={(e) =>
                    update.mutate({ mode: e.target.value as "monitor" | "enforce" })
                  }
                  className="rounded-md border border-border bg-background px-1.5 py-0.5 text-xs"
                  data-testid="policy-mode-select"
                >
                  <option value="monitor">monitor</option>
                  <option value="enforce">enforce</option>
                </select>
              </label>
              <button
                type="button"
                disabled={update.isPending || yaml === active.spec_yaml}
                onClick={() => update.mutate({ spec_yaml: yaml })}
                className="rounded-md bg-foreground px-2.5 py-1 text-xs text-background hover:opacity-90 disabled:opacity-40"
                data-testid="policy-save"
              >
                Save YAML
              </button>
            </div>
            {active.engine === "constellation-admission" && (
              <AdmissionRuleBuilder
                policyName={active.name}
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
          </div>
        )}
      </Drawer>
    </div>
  );
}

function AdmissionProfilePanel({
  profiles,
  policies: installedPolicies,
  loading,
  source,
  setSource,
  selectedProfileID,
  setSelectedProfileID,
  mode,
  setMode,
  enabled,
  setEnabled,
  bundleText,
  setBundleText,
  preview,
  onExport,
  onDryRun,
  onImport,
  busy,
}: {
  profiles: AdmissionProfile[];
  policies: Policy[];
  loading: boolean;
  source: "catalog" | "bundle";
  setSource: (source: "catalog" | "bundle") => void;
  selectedProfileID: string;
  setSelectedProfileID: (id: string) => void;
  mode: "" | "monitor" | "enforce";
  setMode: (mode: "" | "monitor" | "enforce") => void;
  enabled: "" | "enabled" | "disabled";
  setEnabled: (enabled: "" | "enabled" | "disabled") => void;
  bundleText: string;
  setBundleText: (text: string) => void;
  preview: AdmissionProfileImportResponse | null;
  onExport: () => void;
  onDryRun: () => void;
  onImport: () => void;
  busy: boolean;
}) {
  const selected = profiles.find((profile) => profile.id === selectedProfileID) ?? profiles[0];
  const catalogRows = selected ? profileRowsFor(selected, mode, enabled) : [];
  const rows = preview?.policies ?? (source === "catalog" ? catalogRows : []);
  const compareRows = compareProfileRows(rows, installedPolicies);

  const compareColumns: Column<CompareRow>[] = [
    {
      id: "rule",
      header: "Rule",
      cell: (row) => (
        <>
          <div className="font-medium">{row.policy.rule_name}</div>
          <div className="mt-0.5 max-w-[280px] truncate text-muted-foreground">{row.policy.description}</div>
        </>
      ),
    },
    { id: "engine", header: "Engine", cell: (row) => <span className="text-muted-foreground">{row.policy.engine}</span> },
    { id: "mode", header: "Mode", cell: (row) => <Status value={row.policy.mode} /> },
    {
      id: "evidence",
      header: "Evidence",
      cell: (row) => {
        const evidence = evidenceBadges(row.policy.spec_yaml);
        return (
          <div className="flex max-w-[220px] flex-wrap gap-1">
            {evidence.length ? evidence.map((item) => <Badge key={item}>{item}</Badge>) : <span className="text-muted-foreground">-</span>}
          </div>
        );
      },
    },
    { id: "state", header: "State", cell: (row) => (row.policy.enabled ? "enabled" : "disabled") },
    { id: "compare", header: "Compare", cell: (row) => <Status value={row.status} /> },
  ];

  return (
    <section className="rounded-lg border border-border bg-card p-4" data-testid="admission-profile-panel">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-muted-foreground" aria-hidden />
          <div>
            <h2 className="text-sm font-semibold">Admission Profiles</h2>
            <p className="text-xs text-muted-foreground">Built-in and portable admission rule bundles.</p>
          </div>
        </div>
        <div className="inline-flex rounded-md border border-border bg-background p-0.5" data-testid="admission-profile-source">
          {(["catalog", "bundle"] as const).map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => setSource(value)}
              className={`rounded px-2.5 py-1 text-xs ${source === value ? "bg-foreground text-background" : "text-muted-foreground hover:text-foreground"}`}
            >
              {value === "catalog" ? "Catalog" : "Bundle JSON"}
            </button>
          ))}
        </div>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,420px)_minmax(0,1fr)]">
        <div className="space-y-3">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            <label className="space-y-1 text-xs">
              <span className="text-muted-foreground">Profile</span>
              <select
                value={selected?.id ?? ""}
                onChange={(e) => setSelectedProfileID(e.target.value)}
                disabled={source === "bundle" || loading}
                className="h-9 w-full rounded-md border border-border bg-background px-2 text-xs"
                data-testid="admission-profile-select"
              >
                {profiles.map((profile) => (
                  <option key={profile.id} value={profile.id}>{profile.name}</option>
                ))}
              </select>
            </label>
            <label className="space-y-1 text-xs">
              <span className="text-muted-foreground">Mode</span>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value as "" | "monitor" | "enforce")}
                className="h-9 w-full rounded-md border border-border bg-background px-2 text-xs"
                data-testid="admission-profile-mode"
              >
                <option value="">profile</option>
                <option value="monitor">monitor</option>
                <option value="enforce">enforce</option>
              </select>
            </label>
            <label className="space-y-1 text-xs">
              <span className="text-muted-foreground">Enabled</span>
              <select
                value={enabled}
                onChange={(e) => setEnabled(e.target.value as "" | "enabled" | "disabled")}
                className="h-9 w-full rounded-md border border-border bg-background px-2 text-xs"
                data-testid="admission-profile-enabled"
              >
                <option value="">profile</option>
                <option value="enabled">enabled</option>
                <option value="disabled">disabled</option>
              </select>
            </label>
          </div>

          {source === "bundle" && (
            <div className="space-y-2" data-testid="admission-profile-bundle-upload">
              <label className="inline-flex items-center gap-2 rounded-md border border-border bg-background px-2.5 py-1.5 text-xs hover:bg-accent/40">
                <UploadCloud className="h-3.5 w-3.5" aria-hidden />
                Bundle file
                <input
                  type="file"
                  accept="application/json,.json"
                  className="sr-only"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (!file) return;
                    void file.text().then(setBundleText);
                  }}
                  data-testid="admission-profile-bundle-file"
                />
              </label>
              <textarea
                value={bundleText}
                onChange={(e) => setBundleText(e.target.value)}
                spellCheck={false}
                className="h-40 w-full resize-y rounded-md border border-border bg-background p-3 font-mono text-xs"
                data-testid="admission-profile-bundle-text"
              />
            </div>
          )}

          {selected && source === "catalog" && (
            <div className="grid grid-cols-2 gap-2 text-xs" data-testid="admission-profile-summary">
              <Info label="Failure policy" value={selected.failure_policy} />
              <Info label="Rules" value={String(selected.rules.length)} />
            </div>
          )}

          {preview && (
            <div className="rounded-md border border-border p-3 text-xs" data-testid="admission-profile-preview-summary">
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">Preview</span>
                <Status value={preview.dry_run ? "dry-run" : "imported"} />
              </div>
              <div className="mt-2 grid grid-cols-2 gap-2">
                <Info label="Profile" value={preview.profile_id} />
                <Info label="Rows" value={String(preview.policies.length)} />
              </div>
            </div>
          )}
        </div>

        <div className="min-w-0 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <GitCompare className="h-3.5 w-3.5" aria-hidden />
              <span>{compareRows.length} policy rows</span>
            </div>
            <div className="flex flex-wrap gap-2">
              <IconButton label="Export" icon={Download} onClick={onExport} disabled={busy || source === "bundle" || !selectedProfileID} testId="admission-profile-export" />
              <IconButton label="Preview" icon={Eye} onClick={onDryRun} disabled={busy || (source === "bundle" && !bundleText.trim())} testId="admission-profile-preview" />
              <IconButton label="Import" icon={CheckCircle2} onClick={onImport} disabled={busy || (source === "bundle" && !bundleText.trim())} testId="admission-profile-import" />
            </div>
          </div>

          <div data-testid="admission-profile-compare">
            <DataTable<CompareRow>
              rows={compareRows}
              columns={compareColumns}
              rowKey={(row) => row.policy.policy_name}
              showDensityToggle={false}
              className="max-h-72 overflow-auto"
              emptyState={
                <div className="px-3 py-8 text-center text-muted-foreground">
                  <FileJson className="mx-auto mb-2 h-5 w-5" aria-hidden />
                  No profile preview
                </div>
              }
            />
          </div>
        </div>
      </div>
    </section>
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

function SimulationMatchCard({ match }: { match: PolicySimulation["matches"][number] }) {
  const details = match.evidence_details ?? [];
  return (
    <article className="rounded-md bg-muted p-3 text-xs">
      <div className="flex items-center justify-between gap-2">
        <div className="font-medium">{match.policy_name}</div>
        <Status value={match.action} />
      </div>
      <p className="mt-1 text-muted-foreground">{match.reason}</p>
      <div className="mt-2 flex flex-wrap gap-1">
        {match.evidence.map((item) => <Badge key={item}>{item}</Badge>)}
      </div>
      {details.length > 0 && (
        <div className="mt-3 space-y-1" data-testid="policy-simulator-evidence-details">
          {details.map((detail, index) => {
            const href = safeInternalHref(detail.href);
            const label = detail.label || detail.finding?.external_id || detail.finding?.title || detail.artifact?.title || detail.scan_result?.id || "Scan evidence";
            const findingPackage = [detail.finding?.package_ecosystem, detail.finding?.package_name, detail.finding?.package_version]
              .filter(Boolean)
              .join(" / ");
            const meta = [
              detail.finding?.severity || detail.artifact?.severity,
              detail.finding?.external_id || detail.artifact?.rule_id,
              detail.finding?.canonical_engine,
              detail.artifact?.type,
              detail.artifact?.status,
              detail.scan_result?.vulndb_bundle_version ? `bundle ${detail.scan_result.vulndb_bundle_version}` : undefined,
            ].filter(Boolean).join(" · ");
            const imageRef = detail.image?.ref || detail.scan_result?.image_ref;
            const scanSource = scanSourceLabel(detail.scan_result?.source_type, detail.scan_result?.source_ref);
            return (
              <div key={`${label}-${index}`} className="rounded-md border border-border bg-background px-2 py-1.5">
                {href ? (
                  <Link to={href} className="font-medium hover:underline" data-testid="policy-simulator-evidence-detail-link">
                    {label}
                  </Link>
                ) : (
                  <span className="font-medium">{label}</span>
                )}
                {meta && <div className="mt-0.5 text-[11px] text-muted-foreground">{meta}</div>}
                {findingPackage && <div className="mt-0.5 text-[11px] text-muted-foreground">{findingPackage}</div>}
                {detail.finding?.fixed_version && <div className="mt-0.5 text-[11px] text-muted-foreground">fixed in {detail.finding.fixed_version}</div>}
                {scanSource && <div className="mt-0.5 break-all text-[11px] text-muted-foreground">{scanSource}</div>}
                {detail.artifact?.path && <div className="mt-0.5 break-all font-mono text-[10px] text-muted-foreground">{detail.artifact.path}</div>}
                {imageRef && <div className="mt-0.5 break-all font-mono text-[10px] text-muted-foreground">{imageRef}</div>}
              </div>
            );
          })}
        </div>
      )}
    </article>
  );
}

function scanSourceLabel(sourceType?: string, sourceRef?: string) {
  if (!sourceType) return undefined;
  const label = sourceLabel(sourceType);
  return sourceRef ? `${label}: ${sourceRef}` : label;
}

function sourceLabel(sourceType: string) {
  switch (sourceType) {
    case "repository":
      return "Repository / CI";
    case "runtime-agent":
      return "Runtime agent";
    case "registry":
      return "Registry";
    case "discoverer":
      return "Discoverer";
    case "platform":
      return "Platform";
    case "host":
      return "Host";
    case "serverless":
      return "Serverless";
    default:
      return sourceType;
  }
}

function safeInternalHref(href?: string) {
  if (!href || !href.startsWith("/") || href.startsWith("//")) return undefined;
  return href;
}

function groupBy<T>(items: T[], key: (t: T) => string): Record<string, T[]> {
  const out: Record<string, T[]> = {};
  for (const item of items) {
    const k = key(item);
    (out[k] ||= []).push(item);
  }
  return out;
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md bg-muted p-2">
      <div className="text-[10px] uppercase text-muted-foreground">{label}</div>
      <div className="mt-1 truncate font-medium">{value}</div>
    </div>
  );
}

function Badge({ children }: { children: string }) {
  return <span className="rounded-md bg-background px-1.5 py-0.5 text-[10px] text-muted-foreground">{children}</span>;
}

function Status({ value }: { value: string }) {
  const cls = value === "allow" || value === "enforced"
    ? "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]"
    : value === "warn"
      ? "bg-[color:var(--color-status-warning)]/15 text-[color:var(--color-status-warning)]"
      : value === "deny"
        ? "bg-[color:var(--color-status-error)]/15 text-[color:var(--color-status-error)]"
        : "bg-muted text-muted-foreground";
  return <span className={`rounded-md px-2 py-1 text-xs ${cls}`}>{value}</span>;
}

function IconButton({
  label,
  icon: Icon,
  onClick,
  disabled,
  testId,
}: {
  label: string;
  icon: typeof Download;
  onClick: () => void;
  disabled?: boolean;
  testId: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-2.5 py-1.5 text-xs hover:bg-accent/40 disabled:opacity-50"
      data-testid={testId}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden />
      {label}
    </button>
  );
}

function buildProfileImportBody({
  source,
  profileID,
  bundleText,
  mode,
  enabled,
  dryRun,
}: {
  source: "catalog" | "bundle";
  profileID: string;
  bundleText: string;
  mode: "" | "monitor" | "enforce";
  enabled: "" | "enabled" | "disabled";
  dryRun: boolean;
}) {
  const body: {
    profile_id?: string;
    bundle?: AdmissionProfileBundle;
    mode?: "monitor" | "enforce";
    enabled?: boolean;
    dry_run?: boolean;
  } = { dry_run: dryRun };
  if (source === "bundle") {
    try {
      body.bundle = JSON.parse(bundleText) as AdmissionProfileBundle;
    } catch {
      throw new Error("Bundle JSON is invalid");
    }
  } else {
    if (!profileID) throw new Error("Select an admission profile");
    body.profile_id = profileID;
  }
  if (mode) body.mode = mode;
  if (enabled) body.enabled = enabled === "enabled";
  return body;
}

type AdmissionProfilePolicyRow = AdmissionProfileImportResponse["policies"][number];

function profileRowsFor(
  profile: AdmissionProfile,
  mode: "" | "monitor" | "enforce",
  enabled: "" | "enabled" | "disabled",
): AdmissionProfilePolicyRow[] {
  return profile.rules.map((rule) => ({
    policy_name: `${profile.id}/${rule.name}`,
    rule_name: rule.name,
    description: rule.description,
    engine: rule.engine,
    category: rule.category,
    mode: mode || rule.mode,
    enabled: enabled ? enabled === "enabled" : rule.enabled,
    spec_yaml: rule.spec_yaml,
  }));
}

type CompareRow = ReturnType<typeof compareProfileRows>[number];

function compareProfileRows(rows: AdmissionProfilePolicyRow[], installedPolicies: Policy[]) {
  const installed = new Map(installedPolicies.map((policy) => [policy.name, policy]));
  return rows.map((policy) => {
    const current = installed.get(policy.policy_name);
    let status: "new" | "installed" | "changed" = "new";
    if (current) {
      status =
        current.spec_yaml === policy.spec_yaml &&
        current.mode === policy.mode &&
        current.enabled === policy.enabled
          ? "installed"
          : "changed";
    }
    return { policy, status };
  });
}

function evidenceBadges(specYaml: string) {
  const spec = specYaml.toLowerCase();
  const badges: string[] = [];
  if (spec.includes("maxage:") || spec.includes("maxscanage:")) badges.push("fresh scan");
  if (spec.includes("requirevulndbbundle: true")) badges.push("VulnDB");
  if (spec.includes("canonicalengine")) badges.push("canonical");
  if (spec.includes("sourcetypes:") || spec.includes("sourcetype:")) badges.push(spec.includes("repository") ? "Repository / CI" : "source");
  if (spec.includes("requiredigestmatch: true")) badges.push("digest match");
  if (spec.includes("requirefixavailable: true")) badges.push("fixable");
  if (spec.includes("requireverifieridentity: true")) badges.push("verifier");
  return badges;
}
