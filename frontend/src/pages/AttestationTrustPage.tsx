// Route: /settings/attestation-trust.
import { useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import {
  ArrowLeft,
  BadgeCheck,
  CheckCircle2,
  Edit2,
  Fingerprint,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from "lucide-react";

import {
  repositoryScanAttestationTrustPolicies,
  type RepositoryAttestationTrustPolicy,
  type RepositoryAttestationTrustPolicyInput,
} from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { StatCard } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";

export function AttestationTrustPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const policiesQ = useQuery({
    queryKey: ["attestation-trust-policies"],
    queryFn: () => repositoryScanAttestationTrustPolicies.list(),
  });
  const policies = useMemo(() => policiesQ.data?.policies ?? [], [policiesQ.data?.policies]);
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
      header: "Policy",
      className: "align-top",
      cell: (policy) => (
        <>
          <div className="font-medium">{policy.name}</div>
          <div className="mt-1 break-words text-xs text-muted-foreground">{policy.description || "No description"}</div>
          <div className="mt-2 flex flex-wrap gap-1">
            <StatusPill active={policy.enabled} label={policy.enabled ? "enabled" : "disabled"} />
            <StatusPill active={policy.auto_verify} label={policy.auto_verify ? "auto" : "manual"} />
            <span className="rounded-md bg-muted px-1.5 py-0.5 text-[10px]">{policy.verifier_mode || "keyless"}</span>
            {policy.require_rekor ? <span className="rounded-md bg-muted px-1.5 py-0.5 text-[10px]">rekor</span> : null}
          </div>
        </>
      ),
    },
    {
      id: "scope",
      header: "Scope",
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
      header: "Trust",
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
      header: "Actions",
      className: "align-top text-right",
      cell: (policy) => (
        <div className="flex justify-end gap-1">
          <IconButton label={policy.enabled ? "Disable policy" : "Enable policy"} disabled={busy} onClick={() => quickUpdate.mutate({ id: policy.id, patch: { enabled: !policy.enabled } })}>
            <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
          <IconButton label={policy.auto_verify ? "Disable auto verify" : "Enable auto verify"} disabled={busy} onClick={() => quickUpdate.mutate({ id: policy.id, patch: { auto_verify: !policy.auto_verify } })}>
            <BadgeCheck className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
          <IconButton label="Verify pending attestations" disabled={busy || !policy.enabled} onClick={() => verifyPending.mutate(policy.id)}>
            <RefreshCw className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
          <IconButton label="Edit policy" disabled={busy} onClick={() => navigate(`/settings/attestation-trust/${policy.id}`)}>
            <Edit2 className="h-3.5 w-3.5" aria-hidden />
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
        eyebrow={
          <Link to="/settings" className="inline-flex items-center gap-1 hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Back to Settings
          </Link>
        }
        title={
          <span className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" aria-hidden />
            Attestation trust
          </span>
        }
        description="Verify that container images are signed by a source you trust before they're allowed to run (Sigstore/cosign, SLSA provenance)."
        actions={
          <Button variant="primary" onClick={() => navigate("/settings/attestation-trust/new")} data-testid="attestation-trust-new">
            <Plus className="h-4 w-4" aria-hidden />
            New policy
          </Button>
        }
      />

      <VerdictBanner
        status={stats.total === 0 ? "info" : stats.enabled === 0 ? "degraded" : "ok"}
        title={
          stats.total === 0
            ? "No trust policies yet — unsigned images run unchecked"
            : stats.enabled === 0
              ? "Trust policies exist but none are enabled"
              : `${stats.enabled} trust ${stats.enabled === 1 ? "policy" : "policies"} enforcing image provenance`
        }
        detail={
          stats.total === 0
            ? "Add a policy to require Sigstore/cosign signatures before images are allowed to run."
            : `${stats.autoVerify} verifying automatically as new attestations arrive.`
        }
      />

      <section className="grid gap-3 sm:grid-cols-3">
        <StatCard label="Policies" value={stats.total} icon={<Fingerprint className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Enabled" value={stats.enabled} tone="accent" icon={<CheckCircle2 className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Auto verify" value={stats.autoVerify} icon={<BadgeCheck className="h-3.5 w-3.5" aria-hidden />} />
      </section>

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
            <>
              <div className="divide-y divide-border md:hidden">
                {policies.map((policy) => (
                  <PolicyCard
                    key={policy.id}
                    policy={policy}
                    selected={false}
                    busy={quickUpdate.isPending || removePolicy.isPending || verifyPending.isPending}
                    onEdit={() => navigate(`/settings/attestation-trust/${policy.id}`)}
                    onToggleEnabled={() => quickUpdate.mutate({ id: policy.id, patch: { enabled: !policy.enabled } })}
                    onToggleAuto={() => quickUpdate.mutate({ id: policy.id, patch: { auto_verify: !policy.auto_verify } })}
                    onVerify={() => verifyPending.mutate(policy.id)}
                    onDelete={() => {
                      if (window.confirm(`Delete "${policy.name}"? Existing attestation links will no longer satisfy admission.`)) {
                        removePolicy.mutate(policy.id);
                      }
                    }}
                  />
                ))}
              </div>
              <div className="hidden md:block">
                <DataTable
                  rows={policies}
                  columns={policyColumns}
                  rowKey={(policy) => policy.id}
                />
              </div>
            </>
          )}
        </Card>
      </section>
    </div>
  );
}

function PolicyCard({
  policy,
  selected,
  busy,
  onEdit,
  onToggleEnabled,
  onToggleAuto,
  onVerify,
  onDelete,
}: {
  policy: RepositoryAttestationTrustPolicy;
  selected: boolean;
  busy: boolean;
  onEdit: () => void;
  onToggleEnabled: () => void;
  onToggleAuto: () => void;
  onVerify: () => void;
  onDelete: () => void;
}) {
  return (
    <article className={`space-y-3 p-4 ${selected ? "bg-accent/40" : ""}`} data-testid="attestation-trust-row">
      <div>
        <div className="font-medium">{policy.name}</div>
        <div className="mt-1 break-words text-xs text-muted-foreground">{policy.description || "No description"}</div>
      </div>
      <div className="grid grid-cols-2 gap-3 text-xs">
        <div>
          <div className="text-muted-foreground">Scope</div>
          <div className="mt-1 font-mono">{policy.subject_kind}</div>
          <div className="mt-1 break-words">{policy.source_types.length ? policy.source_types.join(", ") : "all sources"}</div>
        </div>
        <div>
          <div className="text-muted-foreground">Trust</div>
          <div className="mt-1 break-words">{firstOrCount(policy.predicate_types)}</div>
          <div className="mt-1 text-muted-foreground">
            {policy.verifier_mode === "public-key" ? "public key" : `${policy.allowed_identities.length} identities · ${policy.allowed_issuers.length} issuers`}
          </div>
        </div>
      </div>
      <div className="flex flex-wrap gap-1">
        <StatusPill active={policy.enabled} label={policy.enabled ? "enabled" : "disabled"} />
        <StatusPill active={policy.auto_verify} label={policy.auto_verify ? "auto" : "manual"} />
        <span className="rounded-md bg-muted px-1.5 py-0.5 text-[10px]">{policy.verifier_mode || "keyless"}</span>
        {policy.require_rekor ? <span className="rounded-md bg-muted px-1.5 py-0.5 text-[10px]">rekor</span> : null}
      </div>
      <div className="flex flex-wrap gap-1">
        <IconButton label={policy.enabled ? "Disable policy" : "Enable policy"} disabled={busy} onClick={onToggleEnabled}>
          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
        </IconButton>
        <IconButton label={policy.auto_verify ? "Disable auto verify" : "Enable auto verify"} disabled={busy} onClick={onToggleAuto}>
          <BadgeCheck className="h-3.5 w-3.5" aria-hidden />
        </IconButton>
        <IconButton label="Verify pending attestations" disabled={busy || !policy.enabled} onClick={onVerify}>
          <RefreshCw className="h-3.5 w-3.5" aria-hidden />
        </IconButton>
        <IconButton label="Edit policy" disabled={busy} onClick={onEdit}>
          <Edit2 className="h-3.5 w-3.5" aria-hidden />
        </IconButton>
        <IconButton label="Delete policy" disabled={busy} onClick={onDelete}>
          <Trash2 className="h-3.5 w-3.5" aria-hidden />
        </IconButton>
      </div>
    </article>
  );
}

function StatusPill({ active, label }: { active: boolean; label: string }) {
  return (
    <span className={`rounded-md px-1.5 py-0.5 text-[10px] ${active ? "bg-status-success/10 text-status-success" : "bg-muted text-muted-foreground"}`}>
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
  const typed = err as { response?: { data?: unknown }; message?: string };
  return String(typed.response?.data ?? typed.message ?? err);
}
