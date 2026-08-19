// ApiTokensPage — wave N4 self-service PAT management.
//
// Route: /settings/api-tokens (org-scoped, mirrors how StackRox / NeuVector ship token UX).
// The raw token value is only revealed exactly once, in the post-create/post-rotate "copy
// this now" dialog. Listing, rotating, and revoking are all idempotent against the
// /api/v1/api-tokens endpoint family; the scope-picker is driven by /api/v1/rbac/verbs.

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import {
  ArrowLeft,
  Check,
  ClipboardCopy,
  KeyRound,
  Plus,
  RefreshCw,
  ShieldAlert,
  Trash2,
} from "lucide-react";

import {
  apiTokens,
  type ApiTokenCreateResponse,
  type ApiTokenDTO,
  type VerbInfo,
} from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard } from "@/components/ui/stat-card";
import { Drawer } from "@/components/ui/drawer";

const EXPIRY_PRESETS: Array<{ id: string; label: string; durationHours: number | null; warn?: boolean }> = [
  { id: "24h", label: "24 hours", durationHours: 24 },
  { id: "7d", label: "7 days", durationHours: 24 * 7 },
  { id: "30d", label: "30 days", durationHours: 24 * 30 },
  { id: "90d", label: "90 days", durationHours: 24 * 90 },
  { id: "1y", label: "1 year", durationHours: 24 * 365 },
  { id: "never", label: "Never (warning)", durationHours: null, warn: true },
];

export function ApiTokensPage() {
  const qc = useQueryClient();
  const tokensQ = useQuery({
    queryKey: ["api-tokens"],
    queryFn: () => apiTokens.list(),
  });
  const verbsQ = useQuery({
    queryKey: ["rbac-verbs"],
    queryFn: () => apiTokens.verbCatalog(),
  });
  const [wizardOpen, setWizardOpen] = useState(false);
  const [revealed, setRevealed] = useState<ApiTokenCreateResponse | null>(null);

  const revokeMutation = useMutation({
    mutationFn: (id: string) => apiTokens.revoke(id),
    onSuccess: () => {
      toast.success("Token revoked");
      qc.invalidateQueries({ queryKey: ["api-tokens"] });
    },
    onError: (e: Error) => toast.error(`Revoke failed: ${e.message}`),
  });

  const rotateMutation = useMutation({
    mutationFn: (id: string) => apiTokens.rotate(id),
    onSuccess: (resp) => {
      toast.success("Token rotated");
      qc.invalidateQueries({ queryKey: ["api-tokens"] });
      setRevealed(resp);
    },
    onError: (e: Error) => toast.error(`Rotate failed: ${e.message}`),
  });

  const busy = rotateMutation.isPending || revokeMutation.isPending;
  const tokens = tokensQ.data ?? [];
  const activeCount = tokens.filter((t) => t.status === "active").length;
  const expiredCount = tokens.filter((t) => t.status === "expired").length;
  const revokedCount = tokens.filter((t) => t.status === "revoked").length;
  const columns: Column<ApiTokenDTO>[] = [
    { id: "name", header: "Name", cell: (t) => t.name, className: "font-medium" },
    {
      id: "scopes",
      header: "Scopes",
      cell: (t) => (
        <div className="flex flex-wrap gap-1">
          {t.scopes.map((s) => (
            <span key={s} className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-[10px]">{s}</span>
          ))}
        </div>
      ),
    },
    {
      id: "attached",
      header: "Attached to",
      cell: (t) => (
        <>
          <div>{t.attached_to_kind}</div>
          {t.attached_to_label && <div className="font-mono text-[10px]">{t.attached_to_label}</div>}
        </>
      ),
      className: "text-xs text-muted-foreground",
    },
    { id: "expires", header: "Expires", cell: (t) => (t.expires_at ? new Date(t.expires_at).toLocaleString() : "never"), className: "text-xs" },
    { id: "last_used", header: "Last used", cell: (t) => (t.last_used_at ? new Date(t.last_used_at).toLocaleString() : "—"), className: "text-xs" },
    {
      id: "status",
      header: "Status",
      cell: (t) => <span className={`rounded-md px-2 py-0.5 text-[10px] ${statusClasses(t.status)}`}>{t.status}</span>,
    },
    {
      id: "actions",
      header: "Actions",
      className: "text-right",
      cell: (t) => (
        <div className="inline-flex items-center gap-1">
          <button
            type="button"
            onClick={() => rotateMutation.mutate(t.id)}
            disabled={busy || t.status !== "active"}
            className="inline-flex items-center gap-1 rounded-md border border-border bg-card px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
            data-testid="api-token-rotate"
          >
            <RefreshCw className="h-3.5 w-3.5" aria-hidden /> Rotate
          </button>
          <button
            type="button"
            onClick={() => {
              if (window.confirm(`Revoke "${t.name}"? Any client using it will lose access.`)) {
                revokeMutation.mutate(t.id);
              }
            }}
            disabled={busy || t.status === "revoked"}
            className="inline-flex items-center gap-1 rounded-md border border-border bg-card px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
            data-testid="api-token-revoke"
          >
            <Trash2 className="h-3.5 w-3.5" aria-hidden /> Revoke
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6" data-testid="api-tokens-page">
      <PageHeader
        eyebrow={
          <Link to="/settings" className="inline-flex items-center gap-1 hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Back to Settings
          </Link>
        }
        title={
          <span className="flex items-center gap-2">
            <KeyRound className="h-5 w-5" aria-hidden />
            API tokens
          </span>
        }
        description="Long-lived bearer tokens for CI / scripts / external integrations. Tokens are scoped and inherit the privileges of the minting user (or attached service account)."
        actions={
          <button
            type="button"
            onClick={() => setWizardOpen(true)}
            className="inline-flex items-center gap-2 rounded-md border border-border bg-primary px-3 py-2 text-sm font-medium text-primary-foreground shadow-sm hover:bg-primary/90"
            data-testid="api-tokens-create-button"
          >
            <Plus className="h-4 w-4" aria-hidden /> Create token
          </button>
        }
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Tokens" value={tokens.length} icon={<KeyRound className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Active" value={activeCount} tone="accent" />
        <StatCard label="Expired" value={expiredCount} tone={expiredCount ? "medium" : "neutral"} />
        <StatCard label="Revoked" value={revokedCount} tone={revokedCount ? "high" : "neutral"} />
      </section>

      <section className="rounded-lg border border-border bg-card" data-testid="api-tokens-table">
        {tokensQ.isLoading ? (
          <div className="p-6 text-sm text-muted-foreground">Loading tokens…</div>
        ) : tokensQ.error ? (
          <div className="p-6 text-sm text-destructive">Failed to load tokens.</div>
        ) : (
          <DataTable
            rows={tokensQ.data ?? []}
            columns={columns}
            rowKey={(t) => t.id}
            emptyState={<div className="p-6 text-sm text-muted-foreground">No API tokens yet. Click "Create token" to mint your first one.</div>}
          />
        )}
      </section>

      {wizardOpen && (
        <CreateTokenWizard
          verbs={verbsQ.data ?? []}
          onCancel={() => setWizardOpen(false)}
          onCreated={(resp) => {
            setWizardOpen(false);
            setRevealed(resp);
            qc.invalidateQueries({ queryKey: ["api-tokens"] });
          }}
        />
      )}

      {revealed && (
        <RevealDialog
          response={revealed}
          onClose={() => setRevealed(null)}
        />
      )}
    </div>
  );
}

function statusClasses(status: ApiTokenDTO["status"]): string {
  switch (status) {
    case "active":
      return "bg-status-success/15 text-status-success";
    case "expired":
      return "bg-status-warning/15 text-status-warning";
    case "revoked":
      return "bg-destructive/15 text-destructive";
    default:
      return "bg-muted text-muted-foreground";
  }
}

// --- create wizard ---

type Step = 1 | 2 | 3 | 4;

function CreateTokenWizard({
  verbs,
  onCancel,
  onCreated,
}: {
  verbs: VerbInfo[];
  onCancel: () => void;
  onCreated: (resp: ApiTokenCreateResponse) => void;
}) {
  const [step, setStep] = useState<Step>(1);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [scopes, setScopes] = useState<Set<string>>(new Set());
  const [expiry, setExpiry] = useState<string>("30d");
  const [attachedTo, setAttachedTo] = useState<string>("user");

  const grantable = useMemo(() => verbs.filter((v) => v.user_grantable), [verbs]);
  const groups = useMemo(() => {
    const out = new Map<string, VerbInfo[]>();
    for (const v of grantable) {
      const arr = out.get(v.category) ?? [];
      arr.push(v);
      out.set(v.category, arr);
    }
    return Array.from(out.entries());
  }, [grantable]);

  const createMutation = useMutation({
    mutationFn: () => {
      const expiresAt = expiryToISO(expiry);
      return apiTokens.create({
        name: description ? `${name} — ${description}` : name,
        scopes: Array.from(scopes),
        expires_at: expiresAt ?? undefined,
        attached_to: attachedTo,
      });
    },
    onSuccess: (resp) => {
      toast.success("Token created");
      onCreated(resp);
    },
    onError: (e: Error) => toast.error(`Create failed: ${e.message}`),
  });

  const canAdvance =
    (step === 1 && name.trim().length > 0) ||
    (step === 2 && scopes.size > 0) ||
    (step === 3 && expiry !== "") ||
    step === 4;

  return (
    <Drawer
      open
      onOpenChange={(o) => { if (!o) onCancel(); }}
      title="Create API token"
      description="Scoped, long-lived bearer token for CI, scripts, or integrations."
      width="xl"
    >
      <div className="space-y-4">
        <StepBar step={step} />

        {step === 1 && (
          <div className="space-y-3">
            <label className="block text-xs font-medium">
              Name *
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="mt-1 block w-full rounded-md border border-border bg-background p-2 text-sm"
                placeholder="jenkins-prod"
                data-testid="wizard-name"
                autoFocus
              />
            </label>
            <label className="block text-xs font-medium">
              Description (optional)
              <input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="mt-1 block w-full rounded-md border border-border bg-background p-2 text-sm"
                placeholder="CI scanner for the main-prod cluster"
              />
            </label>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-3">
            <p className="text-xs text-muted-foreground">
              Select the verbs this token can perform. The token's effective verbs are the
              intersection of these scopes and the underlying user's role grants.
            </p>
            {groups.map(([category, items]) => (
              <fieldset key={category} className="rounded-md border border-border p-3">
                <legend className="px-1 text-xs font-medium uppercase text-muted-foreground">{category}</legend>
                <div className="space-y-2">
                  {items.map((v) => (
                    <label key={v.name} className="flex items-start gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={scopes.has(v.name)}
                        onChange={(e) => {
                          const next = new Set(scopes);
                          if (e.target.checked) next.add(v.name);
                          else next.delete(v.name);
                          setScopes(next);
                        }}
                        className="mt-1"
                        data-testid={`wizard-scope-${v.name}`}
                      />
                      <span>
                        <span className="font-mono text-xs">{v.name}</span>
                        <span className="ml-2 text-xs text-muted-foreground">{v.description}</span>
                      </span>
                    </label>
                  ))}
                </div>
              </fieldset>
            ))}
          </div>
        )}

        {step === 3 && (
          <div className="space-y-3">
            <p className="text-xs text-muted-foreground">
              Choose how long this token is valid. Short-lived tokens are recommended.
            </p>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
              {EXPIRY_PRESETS.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => setExpiry(p.id)}
                  className={`rounded-md border px-3 py-2 text-sm ${
                    expiry === p.id
                      ? "border-primary bg-primary/10"
                      : "border-border bg-card hover:bg-accent"
                  }`}
                  data-testid={`wizard-expiry-${p.id}`}
                >
                  {p.label}
                </button>
              ))}
            </div>
            {expiry === "never" && (
              <div className="flex items-start gap-2 rounded-md border border-status-warning/40 bg-status-warning/10 p-2 text-xs text-status-warning">
                <ShieldAlert className="mt-0.5 h-4 w-4" aria-hidden />
                Tokens without an expiry persist until manually revoked. Use only when an automated rotation cannot be configured.
              </div>
            )}
          </div>
        )}

        {step === 4 && (
          <div className="space-y-3">
            <p className="text-xs text-muted-foreground">
              Attach this token to the current user (default), or to a service account so it
              can outlive any individual.
            </p>
            <label className="flex items-start gap-2 text-sm">
              <input
                type="radio"
                name="attached"
                value="user"
                checked={attachedTo === "user"}
                onChange={() => setAttachedTo("user")}
                className="mt-1"
              />
              <span>
                <span>Current user</span>
                <span className="ml-2 block text-xs text-muted-foreground">Token is revoked if the user is deleted.</span>
              </span>
            </label>
            <label className="block text-xs font-medium">
              Or a service account id
              <input
                value={attachedTo.startsWith("service-account-") ? attachedTo.replace("service-account-", "") : ""}
                onChange={(e) => {
                  const v = e.target.value.trim();
                  setAttachedTo(v ? `service-account-${v}` : "user");
                }}
                placeholder="00000000-0000-0000-0000-000000000000"
                className="mt-1 block w-full rounded-md border border-border bg-background p-2 font-mono text-xs"
              />
            </label>

            <div className="rounded-md border border-border bg-muted p-3 text-xs">
              <div className="font-medium">Summary</div>
              <dl className="mt-2 grid grid-cols-[120px,1fr] gap-y-1">
                <dt className="text-muted-foreground">Name</dt><dd className="font-mono">{name}</dd>
                <dt className="text-muted-foreground">Scopes</dt><dd className="font-mono">{Array.from(scopes).join(", ")}</dd>
                <dt className="text-muted-foreground">Expiry</dt><dd>{expiry}</dd>
                <dt className="text-muted-foreground">Attached</dt><dd>{attachedTo}</dd>
              </dl>
            </div>
          </div>
        )}

        <div className="flex items-center justify-between pt-2">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-md border border-border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <div className="inline-flex gap-2">
            {step > 1 && (
              <button
                type="button"
                onClick={() => setStep((s) => (s - 1) as Step)}
                className="rounded-md border border-border px-3 py-1.5 text-sm hover:bg-accent"
              >
                Back
              </button>
            )}
            {step < 4 ? (
              <button
                type="button"
                disabled={!canAdvance}
                onClick={() => setStep((s) => (s + 1) as Step)}
                className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                data-testid="wizard-next"
              >
                Next
              </button>
            ) : (
              <button
                type="button"
                disabled={createMutation.isPending || scopes.size === 0 || name.trim() === ""}
                onClick={() => createMutation.mutate()}
                className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                data-testid="wizard-submit"
              >
                {createMutation.isPending ? "Creating…" : "Create token"}
              </button>
            )}
          </div>
        </div>
      </div>
    </Drawer>
  );
}

function StepBar({ step }: { step: Step }) {
  const labels = ["Name", "Scopes", "Expiry", "Attach"];
  return (
    <ol className="flex items-center gap-2 text-xs">
      {labels.map((l, i) => {
        const active = i + 1 === step;
        const done = i + 1 < step;
        return (
          <li key={l} className="flex items-center gap-1">
            <span
              className={`inline-flex h-5 w-5 items-center justify-center rounded-full text-[10px] ${
                active ? "bg-primary text-primary-foreground" : done ? "bg-status-success/30 text-status-success" : "bg-muted text-muted-foreground"
              }`}
            >
              {done ? <Check className="h-3 w-3" aria-hidden /> : i + 1}
            </span>
            <span className={active ? "font-medium" : "text-muted-foreground"}>{l}</span>
            {i < labels.length - 1 && <span className="text-muted-foreground">→</span>}
          </li>
        );
      })}
    </ol>
  );
}

// --- "copy this once" reveal ---

function RevealDialog({
  response,
  onClose,
}: {
  response: ApiTokenCreateResponse;
  onClose: () => void;
}) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [copied, setCopied] = useState(false);

  const copyToken = async () => {
    try {
      await navigator.clipboard.writeText(response.raw_token);
      setCopied(true);
      toast.success("Copied to clipboard");
    } catch {
      toast.error("Clipboard not available");
    }
  };

  return (
    <Modal title="Copy your token now" onClose={acknowledged ? onClose : undefined}>
      <div className="space-y-4" data-testid="reveal-dialog">
        <div className="rounded-md border border-status-warning/40 bg-status-warning/10 p-3 text-xs text-status-warning dark:text-status-warning">
          <div className="flex items-center gap-2 font-medium">
            <ShieldAlert className="h-4 w-4" aria-hidden />
            This is the only time the token will be shown.
          </div>
          <p className="mt-2">
            Constellation stores only a hash. If you lose this value you'll need to rotate or
            re-issue the token.
          </p>
        </div>

        <div className="rounded-md border border-border bg-muted p-3">
          <div className="flex items-center justify-between">
            <code className="break-all font-mono text-xs" data-testid="reveal-raw-token">{response.raw_token}</code>
            <button
              type="button"
              onClick={copyToken}
              className="ml-3 inline-flex shrink-0 items-center gap-1 rounded-md border border-border bg-card px-2 py-1 text-xs hover:bg-accent"
              data-testid="reveal-copy-button"
            >
              <ClipboardCopy className="h-3.5 w-3.5" aria-hidden /> {copied ? "Copied" : "Copy"}
            </button>
          </div>
        </div>

        {response.hint && <p className="text-xs text-muted-foreground">{response.hint}</p>}

        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
            data-testid="reveal-ack"
          />
          I've stored the token in a secret manager (or copied it somewhere safe).
        </label>

        <div className="flex justify-end">
          <button
            type="button"
            onClick={onClose}
            disabled={!acknowledged}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            data-testid="reveal-close"
          >
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
}

// --- modal shell ---

function Modal({
  title,
  children,
  onClose,
}: {
  title: string;
  children: React.ReactNode;
  onClose?: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm" role="dialog" aria-modal="true">
      <div className="w-full max-w-xl rounded-lg border border-border bg-card p-5 shadow-lg">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-base font-semibold">{title}</h2>
          {onClose && (
            <button
              type="button"
              onClick={onClose}
              className="rounded-md p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
              aria-label="Close"
            >
              ×
            </button>
          )}
        </div>
        {children}
      </div>
    </div>
  );
}

// --- expiry helper ---

function expiryToISO(preset: string): string | null {
  if (preset === "never" || preset === "") return null;
  const found = EXPIRY_PRESETS.find((p) => p.id === preset);
  if (!found || found.durationHours == null) return null;
  const d = new Date(Date.now() + found.durationHours * 3600 * 1000);
  return d.toISOString();
}
