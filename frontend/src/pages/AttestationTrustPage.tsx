// Route: /settings/attestation-trust.
import { useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { toast } from "sonner";
import { BadgeCheck, CircleCheck, Pen, Plus, RefreshCw, ShieldCheck, Trash2 } from "lucide-react";

import { repositoryScanAttestationTrustPolicies, type RepositoryAttestationTrustPolicy, type RepositoryAttestationTrustPolicyInput } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { apiErrorText } from "@/lib/api-error";

export function AttestationTrustPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const policiesQ = useQuery({
    queryKey: ["attestation-trust-policies"],
    queryFn: () => repositoryScanAttestationTrustPolicies.list(),
  });
  const policies = useMemo(() => policiesQ.isSuccess ? policiesQ.data.policies : [], [policiesQ.data?.policies, policiesQ.isSuccess]);
  const stats = useMemo(() => summarizePolicies(policies), [policies]);

  const quickUpdate = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: Partial<RepositoryAttestationTrustPolicyInput> }) =>
      repositoryScanAttestationTrustPolicies.update(id, patch),
    onSuccess: () => {
      toast.success("Policy updated");
      void qc.invalidateQueries({ queryKey: ["attestation-trust-policies"] });
      void qc.invalidateQueries({ queryKey: ["repository-scans"] });
    },
    onError: (err: unknown) => toast.error(`Update failed: ${errorMessage(err)}`),
  });

  const removePolicy = useMutation({
    mutationFn: (id: string) => repositoryScanAttestationTrustPolicies.remove(id),
    onSuccess: () => {
      toast.success("Trust policy deleted");
      void qc.invalidateQueries({ queryKey: ["attestation-trust-policies"] });
      void qc.invalidateQueries({ queryKey: ["repository-scans"] });
    },
    onError: (err: unknown) => toast.error(`Delete failed: ${errorMessage(err)}`),
  });

  const verifyPending = useMutation({
    mutationFn: (id: string) => repositoryScanAttestationTrustPolicies.verifyPending(id, { limit: 50 }),
    onSuccess: (resp) => {
      toast.success(`Verified ${resp.verified} attestations; ${resp.trusted} trusted`);
      void qc.invalidateQueries({ queryKey: ["attestation-trust-policies"] });
      void qc.invalidateQueries({ queryKey: ["repository-scans"] });
    },
    onError: (err: unknown) => toast.error(`Verification failed: ${errorMessage(err)}`),
  });

  const busy = quickUpdate.isPending || removePolicy.isPending || verifyPending.isPending;
  const policyColumns: Column<RepositoryAttestationTrustPolicy>[] = [
    {
      id: "policy",
      header: "Policy", exportValue: (p) => `${p.name}; enabled=${p.enabled}; auto_verify=${p.auto_verify}; verifier=${p.verifier_mode}; rekor=${p.require_rekor}`, kind: "name", wrap: true,
      className: "align-top",
      cell: (policy) => (
        <>
          <div className="font-medium">{policy.name}</div>
          <div className="mt-1 break-words text-xs text-muted-foreground">{policy.description || "No description"}</div>
          <div className="mt-2 flex flex-wrap gap-1">
            <StatusPill active={policy.enabled} label={policy.enabled ? "enabled" : "disabled"} />
            <StatusPill active={policy.auto_verify} label={policy.auto_verify ? "auto" : "manual"} />
            <span className="rounded-md bg-muted px-1.5 py-0.5 text-micro">{policy.verifier_mode || "keyless"}</span>
            {policy.require_rekor ? <span className="rounded-md bg-muted px-1.5 py-0.5 text-micro">rekor</span> : null}
          </div>
        </>
      ),
    },
    {
      id: "scope",
      header: "Scope", exportValue: (p) => `${p.subject_kind}; sources=${p.source_types.join("|")}; repositories=${p.repository_ref_patterns.join("|")}`, kind: "text", size: 224, minSize: 160, maxSize: 320, wrap: true,
      className: "align-top text-xs",
      cell: (policy) => (
        <>
          <div className="font-mono">{policy.subject_kind}</div>
          <div className="mt-1 text-muted-foreground">{policy.source_types.length ? policy.source_types.join(", ") : "all sources"}</div>
          <div className="mt-1 text-muted-foreground">{policy.repository_ref_patterns.length} repo patterns</div>
        </>
      ),
    },
    {
      id: "trust",
      header: "Trust", exportValue: (p) => `predicates=${p.predicate_types.join("|")}; identities=${p.allowed_identities.join("|")}; issuers=${p.allowed_issuers.join("|")}`, kind: "text", size: 224, minSize: 160, maxSize: 320, wrap: true,
      className: "align-top text-xs",
      cell: (policy) => (
        <>
          <div>{firstOrCount(policy.predicate_types)}</div>
          {policy.verifier_mode === "public-key" ? (
            <div className="mt-1 text-muted-foreground">public key</div>
          ) : (
            <>
              <div className="mt-1 text-muted-foreground">{policy.allowed_identities.length} identities</div>
              <div className="mt-1 text-muted-foreground">{policy.allowed_issuers.length} issuers</div>
            </>
          )}
        </>
      ),
    },
    {
      id: "actions",
      header: "Actions", exportable: false, kind: "actions", size: 208, minSize: 192, maxSize: 240,
      className: "align-top text-right",
      cell: (policy) => (
        <div className="flex justify-end gap-1">
          <IconButton label={policy.enabled ? "Disable policy" : "Enable policy"} disabled={busy} onClick={() => quickUpdate.mutate({ id: policy.id, patch: { enabled: !policy.enabled } })}>
            <CircleCheck className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
          <IconButton label={policy.auto_verify ? "Disable auto verify" : "Enable auto verify"} disabled={busy} onClick={() => quickUpdate.mutate({ id: policy.id, patch: { auto_verify: !policy.auto_verify } })}>
            <BadgeCheck className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
          <IconButton label="Verify pending attestations" disabled={busy || !policy.enabled} onClick={() => verifyPending.mutate(policy.id)}>
            <RefreshCw className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
          <IconButton label="Edit policy" disabled={busy} onClick={() => navigate({ href: `/settings/attestation-trust/${policy.id}` })}>
            <Pen className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
          <IconButton label="Delete policy" disabled={busy} onClick={() => { if (window.confirm(`Delete "${policy.name}"? Existing attestation links will no longer satisfy admission.`)) { removePolicy.mutate(policy.id); } }}>
            <Trash2 className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6" data-testid="attestation-trust-page">
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" aria-hidden />
            Attestation trust
          </span>
        }
        description="Configure trusted signatures and provenance for repository attestations (Sigstore/cosign, SLSA). Admission profiles can require the resulting evidence."
        actions={
          <Button variant="primary" onClick={() => navigate({ href: "/settings/attestation-trust/new" })} data-testid="attestation-trust-new">
            <Plus className="h-4 w-4" aria-hidden />
            New policy
          </Button>
        }
      />

      <VerdictBanner
        status={policiesQ.isError ? "degraded" : "info"}
        title={policiesQ.isError ? "Trust policy inventory unavailable" : policiesQ.isPending ? "Loading trust policies" : stats.total === 0 ? "No attestation trust policies reported" : `${stats.enabled} enabled trust policies reported`}
        detail="Trust policies configure attestation verification. Admission enforcement depends on the admission profiles that require this evidence." numbers={[{ label: "Policies", value: policiesQ.isSuccess ? stats.total : "—" }, { label: "Enabled", value: policiesQ.isSuccess ? stats.enabled : "—" }, { label: "Auto verify", value: policiesQ.isSuccess ? stats.autoVerify : "—" }]} />

      

      <section data-testid="attestation-trust-table">
        <Card
          title="Trust policies"
          description="Which signatures and attestations are required, and where each policy applies."
          padded={false}
          action={
            <Button
              variant="outline"
              size="sm"
              onClick={() => policiesQ.refetch()}
              disabled={policiesQ.isFetching}
            >
              <RefreshCw className={`h-3.5 w-3.5 ${policiesQ.isFetching ? "animate-spin" : ""}`} aria-hidden />
              Refresh
            </Button>
          }
        >
          {policiesQ.isLoading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading policies…</div>
          ) : policiesQ.error ? (
            <div className="p-6 text-sm text-destructive">Failed to load trust policies.</div>
          ) : policies.length === 0 ? (
            <div className="p-6 text-sm text-muted-foreground">No attestation trust policies yet.</div>
          ) : (
            <DataTable rows={policies} columns={policyColumns} rowKey={(policy) => policy.id}
              rowTestId={() => "attestation-trust-row"} preferencesKey="attestation-trust"
              exportFileName="attestation-trust-policy-summary" exportLabel="Export policy summary CSV" />
          )}
        </Card>
      </section>
    </div>
  );
}

function StatusPill({ active, label }: { active: boolean; label: string }) {
  return (
    <span className={`rounded-md px-1.5 py-0.5 text-micro ${active ? "bg-status-success/10 text-status-success" : "bg-muted text-muted-foreground"}`}>
      {label}
    </span>
  );
}

function IconButton({
  label,
  disabled,
  onClick,
  children,
}: {
  label: string;
  disabled?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <Button
      variant="outline"
      size="icon"
      type="button"
      title={label}
      aria-label={label}
      disabled={disabled}
      onClick={onClick}
    >
      {children}
    </Button>
  );
}

function summarizePolicies(policies: RepositoryAttestationTrustPolicy[]) {
  return {
    total: policies.length,
    enabled: policies.filter((policy) => policy.enabled).length,
    autoVerify: policies.filter((policy) => policy.enabled && policy.auto_verify).length,
  };
}
function firstOrCount(values: string[]): string {
  if (values.length === 0) return "none";
  if (values.length === 1) return values[0];
  return `${values[0]} +${values.length - 1}`;
}

function errorMessage(err: unknown): string {
  return apiErrorText(err, String(err));
}
