import { useRuntimePolicyScope, policyMatches, policyRevision, policyFingerprint, policyRules, rulesEqual } from "./runtime-policy-context";
import { exportQueryReady, useExportGuard } from "@/hooks/useExportGuard";
import { Button as ScopeButton } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
// Runtime policy add/edit as a DEDICATED PAGE (the Astronomer pattern —
// see frontend/CLAUDE.md "Forms & actions — DEDICATED PAGES, NOT DRAWERS").
// Replaces the old slide-in Drawer editor. Handles both create
// (/runtime-policies/new) and edit (/runtime-policies/:policyId). The
// cluster comes from the parent :id route param (query-string fallback for
// standalone routing). All data logic + testids are preserved verbatim from
// the former PolicyEditor.
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useRouteSearchParams } from "@/lib/route-search";
import { ArrowLeft } from "lucide-react";

import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page";
import { Collapse } from "@/components/ui/collapse";
import { useTabParam } from "@/components/ui/tabs";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/cn";

import {
  runtimePolicies,
  type GeneratePolicyResponse,
  type PolicyMatchStats,
  type RuntimePolicy,
  type RuntimePolicyRule,
} from "@/api/client";

export function RuntimePolicyFormPage() {
  const scope = useRuntimePolicyScope();
  const [search] = useRouteSearchParams();
  const { policyId } = useParams({ strict: false });
  const clusterID = scope.clusterId ?? "";
  const key = ["runtime-policy", scope.owner, clusterID, policyId];
  const existing = useQuery({ queryKey: key, queryFn: async () => {
    const policy = await runtimePolicies.get(policyId!);
    if (!policyMatches(policy, scope.org, clusterID, policyId)) throw new Error("Policy identity is unavailable");
    return policy;
  }, enabled: scope.ready && !!policyId, gcTime: 0, refetchOnMount: "always" });
  const context = JSON.stringify([scope.owner, clusterID, policyId]);
  const [snapshot, setSnapshot] = useState<{ context: string; policy: RuntimePolicy } | null>(null);
  const ready = scope.ready && (!policyId || existing.isSuccess && !existing.isFetching && exportQueryReady(scope.client, key) && policyMatches(existing.data, scope.org, clusterID, policyId));
  const [loadedContext, setLoadedContext] = useState<string | null>(null);
  if (ready && loadedContext !== context) setLoadedContext(context);
  if (policyId && ready && snapshot?.context !== context) setSnapshot({ context, policy: existing.data! });
  const initial = snapshot?.context === context ? snapshot.policy : undefined;
  const backTo = `/clusters/${clusterID}/runtime-policies${search.size ? `?${search}` : ""}`;
  const recheck = () => scope.recheck() && (!policyId || exportQueryReady(scope.client, key, existing.data) && policyMatches(scope.client.getQueryData(key), scope.org, clusterID, policyId));
  const refresh = async () => { if (!scope.recheck()) return undefined; const result = await existing.refetch(); return scope.recheck() && result.isSuccess && policyMatches(result.data, scope.org, clusterID, policyId) ? result.data : undefined; };
  const waitingHeader = <PageHeader title={policyId ? "Edit runtime policy" : "New runtime policy"} actions={<a className="text-sm underline" href={backTo}>Cancel</a>} />;
  if (!scope.ready && loadedContext !== context) return <div className="space-y-6">{waitingHeader}{scope.isLoading ? <LoadingState label="Resolving policy cluster…" /> : <ErrorState title="Resolve the selected cluster and operator before authoring policies." action={<Button onClick={scope.retry}>Retry cluster</Button>} />}</div>;
  if (policyId && !initial) return <div className="space-y-6">{waitingHeader}{existing.isPending || existing.isFetching ? <LoadingState label="Loading runtime policy…" /> : <ErrorState title="This policy could not be loaded for the selected cluster." action={<ScopeButton onClick={() => void existing.refetch()}>Retry</ScopeButton>} />}</div>;
  return <RuntimePolicyEditor key={context} clusterID={clusterID} policyID={policyId ?? null} initial={initial} latest={ready ? existing.data : undefined} unavailable={!ready} recheck={recheck} refresh={refresh} scope={scope} backTo={backTo} />;
}

function RuntimePolicyEditor({ clusterID, policyID, initial, latest, unavailable, recheck, refresh, scope, backTo }: { clusterID: string; policyID: string | null; initial?: RuntimePolicy; latest?: RuntimePolicy; unavailable: boolean; recheck: () => boolean; refresh: () => Promise<RuntimePolicy | undefined>; scope: ReturnType<typeof useRuntimePolicyScope>; backTo: string }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [workload, setWorkload] = useState(initial?.workload ?? "");
  const [namespace, setNamespace] = useState(initial?.namespace ?? "");
  const [name, setName] = useState(initial?.name ?? "");
  const [rulesText, setRulesText] = useState(typeof initial?.rules === "string" ? initial.rules : JSON.stringify(initial?.rules ?? [], null, 2));
  const [err, setErr] = useState<string | null>(null);

  const [reviewed, setReviewed] = useState(initial);
  const [conflict, setConflict] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const changed = !!policyID && (!latest || !reviewed || policyFingerprint(latest) !== policyFingerprint(reviewed));
  const blocked = unavailable || changed || conflict || uncertain;
  const context = JSON.stringify([scope.owner, clusterID, policyID]);
  const captureCurrent = useExportGuard(JSON.stringify([context, reviewed && policyFingerprint(reviewed)]), blocked, recheck);
  const captureContext = useExportGuard(context, false);
  const review = useMutation({ mutationFn: async () => { const current = captureContext(); const policy = await refresh(); if (!current() || !policy) throw new Error("Policy review unavailable"); return policy; }, onSuccess: policy => { setReviewed(policy); setConflict(false); setErr(null); } });
  const goBack = () => navigate({ href: backTo });

  const parseRules = (): RuntimePolicyRule[] => {
    const out = JSON.parse(rulesText);
    if (!Array.isArray(out)) throw new Error("rules must be an array");
    return out as RuntimePolicyRule[];
  };

  const save = useMutation({
    mutationFn: async () => {
      setErr(null);
      if (blocked || !recheck()) throw new Error("Refresh policy scope before saving");
      const current = captureCurrent(), parsedRules = parseRules();
      const candidate = { workload: workload.trim(), namespace: namespace.trim(), name: name.trim(), rules: parsedRules };
      const saved = policyID ? await runtimePolicies.updateReviewed(policyID, { cluster_id: clusterID, expected_version: policyRevision(reviewed!)!, name: candidate.name, rules: candidate.rules }) : await runtimePolicies.create({ cluster_id: clusterID, ...candidate, mode: "monitor" });
      if (!current()) { setUncertain(true); throw new Error("Response is no longer current"); }
      const matches = policyMatches(saved, scope.org, clusterID, policyID ?? undefined) && saved.workload === candidate.workload && saved.namespace === candidate.namespace && saved.name === candidate.name && rulesEqual(policyRules(saved), candidate.rules) && (policyID ? saved.mode === reviewed!.mode && saved.def_action === reviewed!.def_action && saved.apply_dir === reviewed!.apply_dir && BigInt(policyRevision(saved)!) > BigInt(policyRevision(reviewed)!) : saved.mode === "monitor");
      if (!matches) { setUncertain(true); throw new Error("Saved policy could not be confirmed"); }
      queryClient.setQueryData(["runtime-policy", scope.owner, clusterID, saved.id], saved);
      void queryClient.invalidateQueries({ queryKey: ["runtime-policies", scope.owner, clusterID] });
      goBack();
    },
    onError: error => { if ((error as { response?: { status?: number } }).response?.status === 409) setConflict(true); setErr("Could not save this policy. Your draft is preserved. Refresh its current review before retrying."); },
  });

  // Wave B3: Simulate the candidate ruleset against the workload's
  // observed flows over the last 24h. Requires an existing policy ID for
  // workload scoping (the route is /runtime-policies/{id}/simulate); the
  // new-policy path is a future enhancement.
  const [simStats, setSimStats] = useState<PolicyMatchStats | undefined>(undefined);
  const simulate = useMutation({
    mutationFn: async (): Promise<PolicyMatchStats> => {
      setErr(null);
      if (blocked || !recheck()) throw new Error("Refresh policy evidence first");
      let parsedRules: RuntimePolicyRule[];
      try {
        parsedRules = parseRules();
      } catch (e) {
        throw new Error("Rules JSON invalid: " + (e as Error).message, { cause: e });
      }
      if (!policyID) {
        throw new Error("Save the policy first; simulation runs against the workload it's bound to.");
      }
      const current = captureCurrent();
      const stats = await runtimePolicies.simulate(policyID, { rules: parsedRules, as_mode: "enforce" }, 24);
      if (!current() || stats.workload !== workload || stats.window_hours !== 24) throw new Error("Simulation is no longer current");
      return stats;
    },
    onMutate: () => setSimStats(undefined),
    onSuccess: setSimStats,
    onError: () => setErr("Simulation could not complete. Check the rules and try again."),
  });

  // Wave B4: Generate rules from observed traffic for the workload.
  // Excludes flows that tripped a threat signature. Result populates the
  // rules textarea — operator reviews, edits, saves.
  const [genResult, setGenResult] = useState<GeneratePolicyResponse | undefined>(undefined);
  const generate = useMutation({
    mutationFn: async (): Promise<GeneratePolicyResponse> => {
      setErr(null);
      if (blocked || !recheck()) throw new Error("Refresh policy evidence first");
      if (!workload) throw new Error("Workload is required to generate from observed traffic.");
      const current = captureCurrent();
      const result = await runtimePolicies.generate({
        cluster_id: clusterID,
        workload, namespace: namespace || undefined,
        hours: 24,
      });
      if (!current() || result.workload !== workload || result.window_hours !== 24) throw new Error("Generated evidence is no longer current");
      return result;
    },
    onSuccess: (g) => {
      setGenResult(g);
      setSimStats(undefined);
      // Prefill the editor with the generated rules so the operator can
      // review + tweak before saving. We DO NOT auto-save — auto-gen is
      // a draft, not a commit.
      setRulesText(JSON.stringify(g.rules, null, 2));
    },
    onError: () => setErr("Rules could not be generated. Check the workload and try again."),
  });

  const busy = save.isPending || simulate.isPending || generate.isPending;
  const rulesValid = Array.isArray(tryParse(rulesText));
  return (
    <div className="space-y-6">
      <PageHeader
        title={policyID ? "Edit runtime policy" : "New runtime policy"}
        description="Author the policy's rules, simulate them against observed traffic, or generate a ruleset from what's been seen. New policies always start in monitor mode — promote separately to enforce."
        backLink={<a href={backTo} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Runtime Policies</a>}
      />

      {unavailable && <ErrorState title="Current policy or cluster evidence is unavailable or refreshing. Your draft is preserved; actions are paused." action={<Button disabled={review.isPending || busy} onClick={() => { if (scope.ready) review.mutate(); else scope.retry(); }}>{scope.ready ? "Refresh policy" : "Retry cluster"}</Button>} />}
      {(changed || conflict) && !unavailable && <ErrorState title="The saved policy changed. Review its current mode and revision before applying your retained draft." action={<Button disabled={review.isPending || busy} onClick={() => review.mutate()}>Review latest policy</Button>} />}
      {review.isError && <ErrorState title="Current policy could not be reviewed. your draft is preserved." />}
      {uncertain && <ErrorState title="The saved policy could not be confirmed in this workspace. Reload before another write." />}
      <Card title="Policy" description="Review rules for this workload before saving. New policies observe traffic until promoted.">
        <form className="space-y-4" data-testid="runtime-policies-editor" onSubmit={(event) => { event.preventDefault(); if (!blocked && !busy && rulesValid && name.trim() && workload.trim() && namespace.trim()) save.mutate(); }}>
          <fieldset disabled={busy} className="space-y-4">
          <div className="space-y-3" data-testid="runtime-policies-editor-form">
            <Field label="Workload" value={workload} onChange={setWorkload} placeholder="namespace/deployment" disabled={!!policyID} />
            <Field label="Namespace" value={namespace} onChange={setNamespace} placeholder="default" disabled={!!policyID} />
            <Field label="Name" value={name} onChange={setName} placeholder="block-egress-to-internet" />
            <label htmlFor="runtime-policy-rules" className="text-sm text-muted-foreground">Rules (JSON)</label>
            <textarea id="runtime-policy-rules"
              className="h-[300px] w-full rounded border border-input bg-card p-2 font-mono text-micro outline-none focus:border-[color:var(--color-primary)]"
              value={rulesText}
              onChange={(e) => { setRulesText(e.target.value); setSimStats(undefined); setGenResult(undefined); }}
              spellCheck={false}
              data-testid="runtime-policies-editor-rules"
            />
            {!rulesValid && <p role="alert">Rules must be a valid JSON array.</p>}
            {err && (
              <div className="rounded border border-[color:var(--color-status-error)] bg-card p-2 text-micro text-[color:var(--color-status-error)]" role="alert" data-testid="runtime-policies-editor-error">
                {err}
              </div>
            )}
            <div className="flex items-center gap-2">
              <Button type="submit" disabled={blocked || busy || !rulesValid || !name.trim() || !workload.trim() || !namespace.trim()} data-testid="runtime-policies-editor-save">
                {policyID ? "Save changes" : "Create (in monitor mode)"}
              </Button>
              <Button
                type="button" variant="outline"
                onClick={() => simulate.mutate()}
                disabled={blocked || busy || !policyID || !rulesValid}
                data-testid="runtime-policies-editor-simulate"
                title={policyID ? "Run the current rules against the last 24h of observed flows for this workload" : "Save the policy first to enable simulation"}
              >
                {simulate.isPending ? "Simulating…" : "Simulate"}
              </Button>
              <Button
                type="button" variant="outline"
                onClick={() => generate.mutate()}
                disabled={blocked || busy || !workload}
                data-testid="runtime-policies-editor-generate"
                title="Synthesize a default-deny ruleset from the last 24h of observed traffic for this workload. Threat-tagged flows are excluded."
              >
                {generate.isPending ? "Generating…" : "Generate from traffic"}
              </Button>
              <Button type="button" variant="ghost" onClick={goBack}>Cancel</Button>
              <span className="text-micro text-muted-foreground">
                New policies always start in <b>monitor</b>. Promote separately to enforce.
              </span>
            </div>
          </div>
          <Collapse label="Advanced: request preview">
          <p className="mb-2 text-xs">Reviewed mode: {reviewed?.mode ?? "New · monitor"} · revision {policyRevision(reviewed) ?? "Not created"}</p>
          {reviewed && <div className="mb-3 space-y-2 text-xs"><p>Saved name: {reviewed.name}. Applying the retained draft replaces its name and rules.</p><pre className="max-h-56 overflow-auto rounded border border-border p-2">{JSON.stringify(policyRules(reviewed), null, 2)}</pre></div>}
          <div className="space-y-2" data-testid="runtime-policies-editor-preview">
            <div className="text-micro  text-muted-foreground">Live preview</div>
            <pre className="h-[280px] overflow-auto rounded border border-border bg-background/40 p-2 font-mono text-micro leading-snug">
              {JSON.stringify({ cluster_id: clusterID, workload, namespace, name, rules: tryParse(rulesText) }, null, 2)}
            </pre>
          </div>
          </Collapse>
            {simStats && (
              <>
                <div className="text-micro  text-muted-foreground">Simulation</div>
                <MatchStatsPane stats={simStats} />
              </>
            )}
            {genResult && <GenerateResultPane result={genResult} />}
          </fieldset>
        </form>
      </Card>
    </div>
  );
}

// GenerateResultPane shows what auto-gen produced: counts of flows it
// looked at, how many threat-tagged flows it deliberately skipped, and
// downloadable NetworkPolicy YAML in three flavors.
function GenerateResultPane({ result }: { result: GeneratePolicyResponse }) {
  const [requestedFormat, setYamlTab] = useTabParam("format", "native");
  const yamlTab = requestedFormat === "cilium" || requestedFormat === "calico" ? requestedFormat : "native";
  const yaml = result.yaml[yamlTab];
  const download = (flavor: string) => {
    const blob = new Blob([result.yaml[flavor as keyof typeof result.yaml]], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${result.workload.replace("/", "-")}-${flavor}.yaml`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };
  return (
    <div className="space-y-2" data-testid="runtime-policies-generate-result">
      <div className="text-micro  text-muted-foreground">Auto-generated from traffic</div>
      <div className="rounded border border-border bg-card/50 p-2 text-micro">
        <div>
          Window: <span className="text-mono">{result.window_hours}h</span> ·
          Flows seen: <span className="text-mono">{result.flows_seen}</span> ·
          Rules: <span className="text-mono">{result.rules.length}</span>
        </div>
        {result.threats_excluded > 0 && (
          <div className="mt-1 text-[color:var(--color-status-warning)]" data-testid="runtime-policies-generate-threats-excluded">
            {result.threats_excluded} flow(s) excluded because they tripped a threat signature — they stay alert/deny.
          </div>
        )}
      </div>
      <details className="text-micro">
        <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
          Rule summary ({result.summary.length})
        </summary>
        <ul className="mt-1 space-y-0.5 rounded border border-border bg-background/40 p-2 font-mono text-micro">
          {result.summary.map((s, i) => <li key={i}>{s}</li>)}
        </ul>
      </details>
      <div>
        <div className="mb-1 flex items-center gap-1.5 text-micro  text-muted-foreground">
          NetworkPolicy YAML
          {(["native", "cilium", "calico"] as const).map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => setYamlTab(f)}
              className={cn(
                "rounded border border-border bg-card px-1.5 py-0.5",
                yamlTab === f && "bg-accent text-foreground",
              )}
              data-testid={`runtime-policies-generate-yaml-tab-${f}`}
            >
              {f}
            </button>
          ))}
          <button
            type="button"
            onClick={() => download(yamlTab)}
            className="ml-auto rounded border border-border bg-card px-1.5 py-0.5 hover:bg-accent"
            data-testid={`runtime-policies-generate-yaml-download-${yamlTab}`}
          >
            Download
          </button>
        </div>
        <pre className="h-[180px] overflow-auto rounded border border-border bg-background/40 p-2 font-mono text-micro">
          {yaml}
        </pre>
      </div>
    </div>
  );
}

function tryParse(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return "<invalid JSON>";
  }
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  disabled,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  disabled?: boolean;
}) {
  return (
    <label className="block">
      <span className="text-sm text-muted-foreground">{label}</span>
      <input
        type="text"
        required
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        className={cn(
          "mt-0.5 w-full rounded border border-input bg-card px-2 py-1 text-xs outline-none focus:border-[color:var(--color-primary)]",
          disabled && "opacity-60",
        )}
      />
    </label>
  );
}

/** Wave B2/B3: shared component that visualises allow/monitor/deny counts
 *  from /match-stats or /simulate. The "deny" column is the one operators
 *  care about — that's what would be dropped if (or when) enforce is on. */
function MatchStatsPane({ stats, loading }: { stats?: PolicyMatchStats; loading?: boolean }) {
  if (loading) return <div className="mt-3 text-micro text-muted-foreground">Loading match preview…</div>;
  if (!stats) return null;
  const cards: Array<{ key: "allow" | "monitor" | "deny"; label: string; tone: string; n: number }> = [
    { key: "allow",   label: "Allow",        tone: "var(--color-status-success)", n: stats.allow },
    { key: "monitor", label: "Monitor-only", tone: "var(--color-status-warning)", n: stats.monitor },
    { key: "deny",    label: "Would block",  tone: "var(--color-status-error)",   n: stats.deny },
  ];
  return (
    <div className="mt-3 space-y-2" data-testid="runtime-policy-match-stats">
      <div className="text-micro  text-muted-foreground">
        Last {stats.window_hours}h · {stats.total} flows matched · workload <span className="text-mono text-foreground">{stats.workload}</span>
      </div>
      <div className="grid grid-cols-3 gap-2">
        {cards.map((c) => (
          <div
            key={c.key}
            className="rounded border border-border bg-card/50 p-2 text-center"
            data-testid={`match-stats-${c.key}`}
          >
            <div className="text-micro  text-muted-foreground">{c.label}</div>
            <div className="text-mono text-2xl font-semibold tabular-nums" style={{ color: c.tone }}>{c.n}</div>
          </div>
        ))}
      </div>
      {stats.deny > 0 && stats.samples?.deny && stats.samples.deny.length > 0 && (
        <details className="text-micro">
          <summary className="cursor-pointer text-muted-foreground hover:text-foreground" data-testid="runtime-policy-match-stats-samples-toggle">
            Sample of would-be-blocked flows ({stats.samples.deny.length})
          </summary>
          <ul className="mt-1 space-y-0.5 rounded border border-border bg-background/40 p-2 font-mono text-micro">
            {stats.samples.deny.map((s, i) => (
              <li key={i} className="truncate">
                {s.src} → {s.dst}:{s.dst_port} · {s.protocol.toUpperCase()}
                {s.l7_protocol ? ` · ${s.l7_protocol.toUpperCase()}` : ""}
                · {(s.bytes / 1024).toFixed(1)} KB
              </li>
            ))}
          </ul>
        </details>
      )}
      {stats.default > 0 && (
        <div className="text-micro text-muted-foreground">
          {stats.default} of these matched no rule and fell through to the policy's default action.
        </div>
      )}
    </div>
  );
}
