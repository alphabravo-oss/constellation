// AdmissionPage — /clusters/:id/admission. NeuVector-parity Admission Control surface:
// the global state panel (enable, monitor/protect mode, default action, failure policy)
// that NV users flip first, plus a dry-run image assessor wired to POST /policies/assess.
// The declarative admission policies remain on the Policies page; this is the control
// plane NV surfaces on its Admission Control screen.
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";

import { policies as policiesApi, type AdmissionStateInput } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch, Field, Select, TextInput } from "@/components/ui/form";
import { VerdictBanner, type VerdictStatus } from "@/components/ui/verdict-banner";

export function AdmissionPage() {
  const { clusterId } = useCluster();
  const qc = useQueryClient();
  const params = { cluster_id: clusterId };
  const stateQ = useQuery({
    queryKey: ["admission-state", clusterId],
    queryFn: () => policiesApi.admissionState(params),
    enabled: !!clusterId,
  });
  const save = useMutation({
    mutationFn: (patch: Partial<AdmissionStateInput>) => policiesApi.updateAdmissionState(patch, params),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admission-state", clusterId] }),
  });

  const s = stateQ.data;
  const verdict: { status: VerdictStatus; title: string; detail: string } = !s
    ? { status: "info", title: "Loading admission state…", detail: "" }
    : !s.enabled
      ? { status: "degraded", title: "Admission control is disabled", detail: "The webhook is not gating deployments. Enable it to monitor or block workloads at admission time." }
      : s.mode === "protect"
        ? { status: "ok", title: "Protecting — admission is enforcing", detail: `Violating workloads are blocked at admission. Default action: ${s.default_action}, on webhook failure: ${s.failure_policy}.` }
        : { status: "info", title: "Monitoring — admission is observing", detail: `Violations are logged but not blocked. Switch to Protect to enforce. On webhook failure: ${s.failure_policy}.` };

  // dry-run assessor
  const [image, setImage] = useState("");
  const [namespace, setNamespace] = useState("");
  const assess = useMutation({
    mutationFn: () => policiesApi.assess({ image: image.trim(), namespace: namespace.trim() || undefined }, params),
  });

  return (
    <div className="space-y-5">
      <PageHeader
        title="Admission Control"
        description="Gate workloads at admission time. Monitor logs violations; Protect blocks them. Declarative rules live on the Policies page."
      />

      <VerdictBanner status={verdict.status} title={verdict.title} detail={verdict.detail} />

      <Card title="State" description="The global admission-control posture for this cluster.">
        {stateQ.isPending || !s ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : (
          <div className="space-y-4">
            <Switch
              checked={s.enabled}
              disabled={save.isPending}
              onCheckedChange={(v) => save.mutate({ enabled: v })}
              label="Enable admission control"
              description="When off, the webhook admits everything and only records evidence."
            />
            <div className="grid gap-4 sm:grid-cols-3">
              <Field label="Mode" hint="Protect blocks violations; Monitor only logs them.">
                <Select value={s.mode} disabled={!s.enabled || save.isPending} onChange={(e) => save.mutate({ mode: e.target.value as "monitor" | "protect" })}>
                  <option value="monitor">Monitor</option>
                  <option value="protect">Protect</option>
                </Select>
              </Field>
              <Field label="Default action" hint="Verdict when no rule matches.">
                <Select value={s.default_action} disabled={!s.enabled || save.isPending} onChange={(e) => save.mutate({ default_action: e.target.value as "allow" | "deny" })}>
                  <option value="allow">Allow</option>
                  <option value="deny">Deny</option>
                </Select>
              </Field>
              <Field label="Failure policy" hint="What the API server does if the webhook is unreachable.">
                <Select value={s.failure_policy} disabled={!s.enabled || save.isPending} onChange={(e) => save.mutate({ failure_policy: e.target.value as "ignore" | "fail" })}>
                  <option value="ignore">Ignore (fail-open)</option>
                  <option value="fail">Fail (fail-closed)</option>
                </Select>
              </Field>
            </div>
            {s.mode === "protect" && s.enabled && (
              <p className="text-xs text-[color:var(--color-severity-medium)]">Protect mode blocks deployments that match a deny rule — validate with the dry-run below before rollout.</p>
            )}
          </div>
        )}
      </Card>

      <Card title="Dry-run assessment" description="Test an image against the current admission ruleset without deploying — the same matcher the webhook runs.">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => { e.preventDefault(); if (image.trim()) assess.mutate(); }}
        >
          <div className="min-w-[260px] flex-1">
            <label className="mb-1 block text-[10px] uppercase tracking-wide text-muted-foreground">Image</label>
            <TextInput placeholder="ghcr.io/org/app:1.2.3" value={image} onChange={(e) => setImage(e.target.value)} />
          </div>
          <div className="w-[180px]">
            <label className="mb-1 block text-[10px] uppercase tracking-wide text-muted-foreground">Namespace</label>
            <TextInput placeholder="default" value={namespace} onChange={(e) => setNamespace(e.target.value)} />
          </div>
          <Button type="submit" variant="primary" size="sm" disabled={!image.trim() || assess.isPending}>
            {assess.isPending ? "Assessing…" : "Assess"}
          </Button>
        </form>
        {assess.data && (
          <div className="mt-4 space-y-2">
            <div className="flex items-center gap-2 text-sm">
              <ShieldCheck className="h-4 w-4 text-muted-foreground" />
              <span>Decision:</span>
              <span className="rounded px-1.5 py-0.5 text-xs font-semibold" style={
                assess.data.decision === "deny"
                  ? { background: "color-mix(in oklab, var(--color-severity-critical) 16%, transparent)", color: "var(--color-severity-critical)" }
                  : { background: "color-mix(in oklab, var(--color-severity-low) 16%, transparent)", color: "var(--color-severity-low)" }
              }>{assess.data.decision}</span>
              <span className="text-xs text-muted-foreground">(mode: {assess.data.enforcement_mode})</span>
            </div>
            {assess.data.matches.length === 0 ? (
              <p className="text-xs text-muted-foreground">No admission rules matched — the image would be admitted.</p>
            ) : (
              <table className="w-full text-sm">
                <thead className="text-[10px] uppercase tracking-wide text-muted-foreground">
                  <tr className="border-b border-border"><th className="px-2 py-1.5 text-left">Rule</th><th className="px-2 py-1.5 text-left">Action</th><th className="px-2 py-1.5 text-left">Reason</th></tr>
                </thead>
                <tbody>
                  {assess.data.matches.map((m, i) => (
                    <tr key={i} className="border-b border-border/60">
                      <td className="px-2 py-1.5 font-mono text-xs">{m.policy_name ?? m.rule_id ?? "—"}</td>
                      <td className="px-2 py-1.5 text-xs">{String(m.action ?? "—")}</td>
                      <td className="px-2 py-1.5 text-xs text-muted-foreground">{String(m.reason ?? "")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
        {assess.isError && <p className="mt-3 text-sm text-status-error">{(assess.error as Error).message}</p>}
      </Card>
    </div>
  );
}
