// Runtime policy add/edit as a DEDICATED PAGE (the Astronomer pattern —
// see frontend/CLAUDE.md "Forms & actions — DEDICATED PAGES, NOT DRAWERS").
// Replaces the old slide-in Drawer editor. Handles both create
// (/runtime-policies/new) and edit (/runtime-policies/:policyId). The
// cluster comes from the parent :id route param (query-string fallback for
// standalone routing). All data logic + testids are preserved verbatim from
// the former PolicyEditor.
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";

import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page";
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
  const navigate = useNavigate();
  const [search] = useSearchParams();
  const { id: pathClusterID, policyId } = useParams();
  const clusterID = pathClusterID ?? search.get("cluster_id") ?? "";
  const policyID = policyId ?? null;

  const queryClient = useQueryClient();
  const existing = useQuery({
    queryKey: ["runtime-policy", policyID],
    queryFn: () => runtimePolicies.get(policyID as string),
    enabled: !!policyID,
  });

  const [workload, setWorkload] = useState("");
  const [namespace, setNamespace] = useState("");
  const [name, setName] = useState("");
  const [rulesText, setRulesText] = useState("[]");
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (existing.data) {
      setWorkload(existing.data.workload);
      setNamespace(existing.data.namespace);
      setName(existing.data.name);
      setRulesText(JSON.stringify(Array.isArray(existing.data.rules) ? existing.data.rules : [], null, 2));
    } else if (!policyID) {
      setWorkload("");
      setNamespace("");
      setName("");
      setRulesText("[]");
    }
  }, [existing.data, policyID]);

  const backTo = { pathname: "..", search: search.toString() };
  const goBack = () => navigate(backTo);

  const parseRules = (): RuntimePolicyRule[] => {
    const out = JSON.parse(rulesText);
    if (!Array.isArray(out)) throw new Error("rules must be an array");
    return out as RuntimePolicyRule[];
  };

  const save = useMutation({
    mutationFn: async (): Promise<RuntimePolicy> => {
      setErr(null);
      let parsedRules: RuntimePolicyRule[];
      try {
        parsedRules = parseRules();
      } catch (e) {
        throw new Error("Rules JSON invalid: " + (e as Error).message);
      }
      if (policyID) {
        return runtimePolicies.update(policyID, { rules: parsedRules, name });
      }
      return runtimePolicies.create({
        cluster_id: clusterID,
        workload, namespace, name,
        mode: "monitor",
        rules: parsedRules,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["runtime-policies", clusterID] });
      goBack();
    },
    onError: (e) => setErr((e as Error).message),
  });

  // Wave B3: Simulate the candidate ruleset against the workload's
  // observed flows over the last 24h. Requires an existing policy ID for
  // workload scoping (the route is /runtime-policies/{id}/simulate); the
  // new-policy path is a future enhancement.
  const [simStats, setSimStats] = useState<PolicyMatchStats | undefined>(undefined);
  const simulate = useMutation({
    mutationFn: async (): Promise<PolicyMatchStats> => {
      setErr(null);
      let parsedRules: RuntimePolicyRule[];
      try {
        parsedRules = parseRules();
      } catch (e) {
        throw new Error("Rules JSON invalid: " + (e as Error).message);
      }
      if (!policyID) {
        throw new Error("Save the policy first; simulation runs against the workload it's bound to.");
      }
      return runtimePolicies.simulate(policyID, { rules: parsedRules, as_mode: "enforce" }, 24);
    },
    onSuccess: setSimStats,
    onError: (e) => setErr((e as Error).message),
  });

  // Wave B4: Generate rules from observed traffic for the workload.
  // Excludes flows that tripped a threat signature. Result populates the
  // rules textarea — operator reviews, edits, saves.
  const [genResult, setGenResult] = useState<GeneratePolicyResponse | undefined>(undefined);
  const generate = useMutation({
    mutationFn: async (): Promise<GeneratePolicyResponse> => {
      setErr(null);
      if (!workload) throw new Error("Workload is required to generate from observed traffic.");
      return runtimePolicies.generate({
        cluster_id: clusterID,
        workload, namespace: namespace || undefined,
        hours: 24,
      });
    },
    onSuccess: (g) => {
      setGenResult(g);
      // Prefill the editor with the generated rules so the operator can
      // review + tweak before saving. We DO NOT auto-save — auto-gen is
      // a draft, not a commit.
      setRulesText(JSON.stringify(g.rules, null, 2));
    },
    onError: (e) => setErr((e as Error).message),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={policyID ? "Edit runtime policy" : "New runtime policy"}
        description="Author the policy's rules, simulate them against observed traffic, or generate a ruleset from what's been seen. New policies always start in monitor mode — promote separately to enforce."
        backLink={<Link to={backTo} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Runtime Policies</Link>}
      />

      <Card title="Policy" description="Rules dp enforces for the selected workload.">
        <div className="space-y-4" data-testid="runtime-policies-editor">
          <div className="space-y-3" data-testid="runtime-policies-editor-form">
            <Field label="Workload" value={workload} onChange={setWorkload} placeholder="namespace/deployment" disabled={!!policyID} />
            <Field label="Namespace" value={namespace} onChange={setNamespace} placeholder="default" disabled={!!policyID} />
            <Field label="Name" value={name} onChange={setName} placeholder="block-egress-to-internet" />
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Rules (JSON)</div>
            <textarea
              className="h-[300px] w-full rounded border border-input bg-card p-2 font-mono text-[11px] outline-none focus:border-[color:var(--color-primary)]"
              value={rulesText}
              onChange={(e) => setRulesText(e.target.value)}
              spellCheck={false}
              data-testid="runtime-policies-editor-rules"
            />
            {err && (
              <div className="rounded border border-[color:var(--color-status-error)] bg-card p-2 text-[11px] text-[color:var(--color-status-error)]" data-testid="runtime-policies-editor-error">
                {err}
              </div>
            )}
            <div className="flex items-center gap-2">
              <Button onClick={() => save.mutate()} disabled={save.isPending} data-testid="runtime-policies-editor-save">
                {policyID ? "Save changes" : "Create (in monitor mode)"}
              </Button>
              <Button
                variant="outline"
                onClick={() => simulate.mutate()}
                disabled={simulate.isPending || !policyID}
                data-testid="runtime-policies-editor-simulate"
                title={policyID ? "Run the current rules against the last 24h of observed flows for this workload" : "Save the policy first to enable simulation"}
              >
                {simulate.isPending ? "Simulating…" : "Simulate"}
              </Button>
              <Button
                variant="outline"
                onClick={() => generate.mutate()}
                disabled={generate.isPending || !workload}
                data-testid="runtime-policies-editor-generate"
                title="Synthesize a default-deny ruleset from the last 24h of observed traffic for this workload. Threat-tagged flows are excluded."
              >
                {generate.isPending ? "Generating…" : "Generate from traffic"}
              </Button>
              <Button variant="ghost" onClick={goBack}>Cancel</Button>
              <span className="text-[10px] text-muted-foreground">
                New policies always start in <b>monitor</b>. Promote separately to enforce.
              </span>
            </div>
          </div>
          <div className="space-y-2" data-testid="runtime-policies-editor-preview">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Live preview</div>
            <pre className="h-[280px] overflow-auto rounded border border-border bg-background/40 p-2 font-mono text-[10px] leading-snug">
              {JSON.stringify({ cluster_id: clusterID, workload, namespace, name, rules: tryParse(rulesText) }, null, 2)}
            </pre>
            {simStats && (
              <>
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Simulation</div>
                <MatchStatsPane stats={simStats} />
              </>
            )}
            {genResult && <GenerateResultPane result={genResult} />}
          </div>
        </div>
      </Card>
    </div>
  );
}

// GenerateResultPane shows what auto-gen produced: counts of flows it
// looked at, how many threat-tagged flows it deliberately skipped, and
// downloadable NetworkPolicy YAML in three flavors.
function GenerateResultPane({ result }: { result: GeneratePolicyResponse }) {
  const [yamlTab, setYamlTab] = useState<"native" | "cilium" | "calico">("native");
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
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Auto-generated from traffic</div>
      <div className="rounded border border-border bg-card/50 p-2 text-[11px]">
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
      <details className="text-[11px]">
        <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
          Rule summary ({result.summary.length})
        </summary>
        <ul className="mt-1 space-y-0.5 rounded border border-border bg-background/40 p-2 font-mono text-[10px]">
          {result.summary.map((s, i) => <li key={i}>{s}</li>)}
        </ul>
      </details>
      <div>
        <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
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
        <pre className="h-[180px] overflow-auto rounded border border-border bg-background/40 p-2 font-mono text-[10px]">
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
    <div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        className={cn(
          "mt-0.5 w-full rounded border border-input bg-card px-2 py-1 text-xs outline-none focus:border-[color:var(--color-primary)]",
          disabled && "opacity-60",
        )}
      />
    </div>
  );
}

/** Wave B2/B3: shared component that visualises allow/monitor/deny counts
 *  from /match-stats or /simulate. The "deny" column is the one operators
 *  care about — that's what would be dropped if (or when) enforce is on. */
function MatchStatsPane({ stats, loading }: { stats?: PolicyMatchStats; loading?: boolean }) {
  if (loading) return <div className="mt-3 text-[11px] text-muted-foreground">Loading match preview…</div>;
  if (!stats) return null;
  const cards: Array<{ key: "allow" | "monitor" | "deny"; label: string; tone: string; n: number }> = [
    { key: "allow",   label: "Allow",        tone: "var(--color-status-success)", n: stats.allow },
    { key: "monitor", label: "Monitor-only", tone: "var(--color-status-warning)", n: stats.monitor },
    { key: "deny",    label: "Would block",  tone: "var(--color-status-error)",   n: stats.deny },
  ];
  return (
    <div className="mt-3 space-y-2" data-testid="runtime-policy-match-stats">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
        Last {stats.window_hours}h · {stats.total} flows matched · workload <span className="text-mono text-foreground">{stats.workload}</span>
      </div>
      <div className="grid grid-cols-3 gap-2">
        {cards.map((c) => (
          <div
            key={c.key}
            className="rounded border border-border bg-card/50 p-2 text-center"
            data-testid={`match-stats-${c.key}`}
          >
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{c.label}</div>
            <div className="text-mono text-2xl font-semibold tabular-nums" style={{ color: c.tone }}>{c.n}</div>
          </div>
        ))}
      </div>
      {stats.deny > 0 && stats.samples?.deny && stats.samples.deny.length > 0 && (
        <details className="text-[11px]">
          <summary className="cursor-pointer text-muted-foreground hover:text-foreground" data-testid="runtime-policy-match-stats-samples-toggle">
            Sample of would-be-blocked flows ({stats.samples.deny.length})
          </summary>
          <ul className="mt-1 space-y-0.5 rounded border border-border bg-background/40 p-2 font-mono text-[10px]">
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
        <div className="text-[10px] text-muted-foreground">
          {stats.default} of these matched no rule and fell through to the policy's default action.
        </div>
      )}
    </div>
  );
}
