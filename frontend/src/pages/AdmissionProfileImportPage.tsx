import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { ArrowLeft, Download, Eye, UploadCloud } from "lucide-react";
import { policies, type AdmissionProfile, type AdmissionProfileBundle, type AdmissionProfileImportResponse, type Policy } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useRouteSearchParams } from "@/lib/route-search";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Collapse } from "@/components/ui/collapse";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { DataTable, type Column } from "@/components/ui/data-table";
import { ErrorState, LoadingState } from "@/components/ui/states";

type ImportBody = Parameters<typeof policies.importAdmissionProfile>[0];

export function AdmissionProfileImportPage() {
  const { clusterId, cluster, isLoading } = useCluster();
  const backTo = clusterId ? `/clusters/${clusterId}/admission` : "/clusters";
  return <div className="space-y-6" data-testid="admission-profile-import-page">
    <PageHeader title="Import admission profile" description="Preview an organization-wide rule bundle and compare it with installed policies before importing."
      backLink={<Link to="." href={backTo} className="inline-flex items-center gap-2 hover:text-foreground"><ArrowLeft className="h-4 w-4" /> Admission</Link>} />
    {isLoading ? <LoadingState label="Loading cluster…" /> : !clusterId || !cluster ? <ErrorState title="The selected cluster could not be loaded. Return to the cluster list and try again." /> : <AdmissionProfileImporter key={clusterId} backTo={backTo} />}
  </div>;
}

function AdmissionProfileImporter({ backTo }: { backTo: string }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [search] = useRouteSearchParams();
  const [rawSource, setSource] = useTabParam("tab", search.get("source") === "bundle" ? "bundle" : "catalog");
  const source = rawSource === "bundle" ? "bundle" : "catalog";
  const [profileSelection, setProfileSelection] = useState(search.get("profile") ?? "");
  const [mode, setMode] = useState<"" | "monitor" | "enforce">(search.get("mode") === "enforce" ? "enforce" : search.get("mode") === "monitor" ? "monitor" : "");
  const [enabled, setEnabled] = useState<"" | "enabled" | "disabled">(search.get("enabled") === "disabled" ? "disabled" : search.get("enabled") === "enabled" ? "enabled" : "");
  const [bundleText, setBundleText] = useState("");
  const [fileError, setFileError] = useState("");
  const fileRead = useRef(0);
  const [fileLoading, setFileLoading] = useState(false);
  const profilesQ = useQuery({ queryKey: ["admission-profiles"], queryFn: () => policies.admissionProfiles() });
  // Import creates organization-wide policies; compare against organization-wide
  // installed policies rather than the cluster catalog subset.
  const installedQ = useQuery({ queryKey: ["policies", "organization-import-comparison"], queryFn: () => policies.list() });
  const profiles = profilesQ.data?.profiles ?? [];
  const selectedID = profileSelection || profiles[0]?.id || "";
  const selected = profiles.find((p) => p.id === selectedID);
  const inputKey = JSON.stringify({ source, selectedID, mode, enabled, bundleText, catalog: source === "catalog" ? selected : undefined });
  let body: ImportBody | null = null;
  let validation = "";
  if (source === "catalog") {
    if (selected && !profilesQ.isError) body = { profile_id: selectedID };
  } else if (bundleText.trim()) {
    try {
      const parsed = JSON.parse(bundleText) as AdmissionProfileBundle;
      if (!parsed || typeof parsed !== "object" || parsed.api_version !== "constellation.alphabravo.io/v1alpha1" || parsed.kind !== "AdmissionProfileBundle" || !parsed.profile || !parsed.profile.id || !parsed.profile.name || !Array.isArray(parsed.profile.rules) || !parsed.profile.rules.length) validation = "Choose a valid AdmissionProfileBundle with at least one rule.";
      else body = { bundle: parsed };
    } catch { validation = "Bundle JSON is invalid. Correct it before previewing."; }
  }
  if (body && mode) body.mode = mode;
  if (body && enabled) body.enabled = enabled === "enabled";
  const preview = useMutation({ mutationFn: async (input: { body: ImportBody; key: string }) => {
    const result = await policies.importAdmissionProfile({ ...input.body, dry_run: true });
    if (!result.dry_run) throw new Error("Preview was not a dry run");
    return { result, key: input.key };
  } });
  const matchingPreview = preview.isSuccess && preview.data.key === inputKey ? preview.data.result : undefined;
  const importProfile = useMutation({
    mutationFn: (input: { body: ImportBody; key: string }) => policies.importAdmissionProfile({ ...input.body, dry_run: false }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["policies"] });
      void qc.invalidateQueries({ queryKey: ["admission-rules"] });
      void qc.invalidateQueries({ queryKey: ["admission-state"] });
      void navigate({ href: backTo });
    },
  });
  const exportProfile = useMutation({
    mutationFn: (profileID: string) => policies.exportAdmissionProfile(profileID),
    onSuccess: (bundle) => {
      const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" }));
      const link = document.createElement("a"); link.href = url; link.download = `${bundle.profile.id.replace(/[^a-zA-Z0-9_-]/g, "_")}.json`; link.click(); URL.revokeObjectURL(url);
    },
  });
  const busy = preview.isPending || importProfile.isPending || exportProfile.isPending || fileLoading;
  const canPreview = !!body && !busy && !installedQ.isError && installedQ.isSuccess && (source === "bundle" || profilesQ.isSuccess && !profilesQ.isFetching);
  const canImport = canPreview && !!matchingPreview && !installedQ.isFetching;
  const rows = matchingPreview?.policies ?? (source === "catalog" && selected ? profileRowsFor(selected, mode, enabled) : []);
  const compareRows = compareProfileRows(rows, installedQ.data?.policies ?? []);
  const columns: Column<CompareRow>[] = [
    { id: "rule", header: "Rule", hideable: false, cell: (row) => <div><span className="font-medium">{row.policy.rule_name}</span><p className="mt-1 text-xs text-muted-foreground">{row.policy.description}</p></div>, exportValue: (row) => row.policy.rule_name, sort: (a, b) => a.policy.rule_name.localeCompare(b.policy.rule_name) },
    { id: "engine", header: "Engine", cell: (row) => row.policy.engine },
    { id: "mode", header: "Mode", cell: (row) => row.policy.mode },
    { id: "evidence", header: "Evidence", cell: (row) => evidenceBadges(row.policy.spec_yaml).join(" · ") || "—" },
    { id: "enabled", header: "Rule status", cell: (row) => row.policy.enabled ? "Enabled" : "Disabled", exportValue: (row) => row.policy.enabled },
    { id: "comparison", header: "Compared with installed", cell: (row) => installedQ.isError || !installedQ.data ? "Unavailable" : row.status },
  ];
  const resetPreview = () => { preview.reset(); importProfile.reset(); };
  const chooseSource = (value: string) => { if (busy) return; resetPreview(); setSource(value); };
  return <>
    <VerdictBanner status="info" title="This import applies across the organization" detail="These rules are organization defaults shared across clusters. Import can replace matching profile policy names. Review every change before saving." />
    {profilesQ.isPending && source === "catalog" && <LoadingState label="Loading admission profiles…" />}
    {profilesQ.isError && source === "catalog" && <ErrorState title="Could not load admission profiles. Your draft is preserved." action={<Button onClick={() => void profilesQ.refetch()}>Retry</Button>} />}
    {installedQ.isPending && <LoadingState label="Loading installed policies for comparison…" />}
    {installedQ.isError && <ErrorState title="Could not load installed policies for comparison. Your draft is preserved. Refresh before importing." action={<Button onClick={() => void installedQ.refetch()}>Retry</Button>} />}
    <Card title="Choose an admission profile" description="Use a built-in profile or upload a portable JSON bundle. Preview is required before importing.">
      <form className="space-y-6" onSubmit={(event) => { event.preventDefault(); if (canImport && body) importProfile.mutate({ body, key: inputKey }); }}>
        <fieldset disabled={busy} className="space-y-5">
          <Tabs value={source} onValueChange={chooseSource} items={[
            { value: "catalog", label: "Catalog", content: <div className="space-y-4">
              <label className="block space-y-2 text-sm"><span className="font-medium">Profile</span><select id="admission-profile" data-testid="admission-profile-select" className="h-10 w-full rounded-md border border-border bg-background px-3" value={selectedID} onChange={(e) => { resetPreview(); setProfileSelection(e.target.value); }} disabled={profilesQ.isPending || profilesQ.isError}>
                {!profiles.length && <option value="">No admission profiles available</option>}{profileSelection && !selected && <option value={profileSelection}>Unavailable profile: {profileSelection}</option>}{profiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select></label>
              {selected && <p className="text-sm text-muted-foreground">{selected.description} · {selected.rules.length} rules · Failure policy: {selected.failure_policy}</p>}
              <Button type="button" disabled={!selected || profilesQ.isError || profilesQ.isPending} onClick={() => exportProfile.mutate(selectedID)} data-testid="admission-profile-export"><Download className="h-4 w-4" /> Export bundle</Button>
            </div> },
            { value: "bundle", label: "Bundle JSON", content: <div className="space-y-4">
              <label className="block space-y-2 text-sm"><span className="font-medium">Bundle file</span><input type="file" accept="application/json,.json" className="block w-full rounded-md border border-border p-3" data-testid="admission-profile-bundle-file" onChange={(event) => {
                const file = event.target.files?.[0]; if (!file) return;
                const readID = ++fileRead.current; setFileLoading(true); setFileError(""); resetPreview();
                void file.text().then((text) => { if (readID === fileRead.current) { setBundleText(text); resetPreview(); } }).catch(() => { if (readID === fileRead.current) setFileError("Could not read this bundle file. Your draft is preserved. Try another file."); }).finally(() => { if (readID === fileRead.current) setFileLoading(false); });
              }} /></label>
              <label className="block space-y-2 text-sm"><span className="font-medium">Bundle JSON</span><textarea className="h-64 w-full rounded-md border border-border bg-background p-3 font-mono text-sm" value={bundleText} spellCheck={false} data-testid="admission-profile-bundle-text" onChange={(e) => { resetPreview(); setFileError(""); setBundleText(e.target.value); }} /></label>
              {validation && <p role="alert" className="text-sm text-status-error">{validation}</p>}{fileError && <p role="alert" className="text-sm text-status-error">{fileError}</p>}
            </div> },
          ]} />
          <Collapse label="Advanced import overrides"><div className="grid grid-cols-1 gap-5 rounded-md border border-border p-4 sm:grid-cols-2">
            <label className="block space-y-2 text-sm"><span className="font-medium">Mode override</span><select id="admission-profile-mode" className="h-10 w-full rounded-md border border-border bg-background px-3" value={mode} onChange={(event) => { resetPreview(); setMode(event.target.value as typeof mode); }}><option value="">Keep profile modes</option><option value="monitor">Monitor</option><option value="enforce">Enforce</option></select></label>
            <label className="block space-y-2 text-sm"><span className="font-medium">Enabled override</span><select id="admission-profile-enabled" className="h-10 w-full rounded-md border border-border bg-background px-3" value={enabled} onChange={(event) => { resetPreview(); setEnabled(event.target.value as typeof enabled); }}><option value="">Keep profile status</option><option value="enabled">Enabled</option><option value="disabled">Disabled</option></select></label>
          </div></Collapse>
        </fieldset>
        {exportProfile.isError && <p role="alert" className="text-sm text-status-error">Could not export this profile. Try again.</p>}
        {preview.isError && preview.variables?.key === inputKey && <p role="alert" className="text-sm text-status-error">Could not preview this profile. Your draft is preserved. Try again.</p>}
        {importProfile.isError && <p role="alert" className="text-sm text-status-error">Could not import this profile. Your draft is preserved. Try again.</p>}
        <div className="space-y-3" data-testid="admission-profile-compare"><h3 className="text-sm font-semibold">{matchingPreview ? "Preview compared with installed policies" : "Profile rules compared with installed policies"}</h3><p className="text-xs text-muted-foreground">New rules are added. Changed rules replace the matching installed policy configuration. Installed rules already match. Comparison covers the loaded organization policies.</p><DataTable rows={compareRows} columns={columns} rowKey={(row) => row.policy.policy_name} preferencesKey="admission-profile-comparison" exportFileName="admission-profile-comparison.csv" emptyState={<p className="p-6 text-center text-sm text-muted-foreground">Choose a profile or preview a bundle to compare its rules.</p>} /></div>
        {matchingPreview && <p role="status" className="text-sm">Preview ready: {matchingPreview.policies.length} rules from {matchingPreview.profile_id}. Changing any input requires a new preview.</p>}
        <div className="flex flex-wrap justify-end gap-3 border-t border-border pt-5"><Button type="button" variant="ghost" disabled={busy} onClick={() => void navigate({ href: backTo })}>Cancel</Button><Button type="button" disabled={!canPreview} onClick={() => { if (body && canPreview) preview.mutate({ body, key: inputKey }); }} data-testid="admission-profile-preview"><Eye className="h-4 w-4" />{preview.isPending ? "Previewing…" : "Preview"}</Button><Button type="submit" variant="primary" disabled={!canImport} data-testid="admission-profile-import"><UploadCloud className="h-4 w-4" />{importProfile.isPending ? "Importing…" : "Import profile"}</Button></div>
      </form>
    </Card>
  </>;
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
