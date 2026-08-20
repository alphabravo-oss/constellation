// ApiTokensPage — wave N4 self-service PAT management.
//
// Route: /settings/api-tokens (org-scoped, mirrors how StackRox / NeuVector ship token UX).
// The raw token value is only revealed exactly once — for create, on the dedicated
// /settings/api-tokens/new page; for rotate, in the post-rotate "copy this now" dialog.
// Listing, rotating, and revoking are all idempotent against the /api/v1/api-tokens
// endpoint family.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import {
  ArrowLeft,
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
} from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard } from "@/components/ui/stat-card";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export function ApiTokensPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const tokensQ = useQuery({
    queryKey: ["api-tokens"],
    queryFn: () => apiTokens.list(),
  });
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
          <Button
            variant="outline"
            size="sm"
            onClick={() => rotateMutation.mutate(t.id)}
            disabled={busy || t.status !== "active"}
            data-testid="api-token-rotate"
          >
            <RefreshCw className="h-3.5 w-3.5" aria-hidden /> Rotate
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              if (window.confirm(`Revoke "${t.name}"? Any client using it will lose access.`)) {
                revokeMutation.mutate(t.id);
              }
            }}
            disabled={busy || t.status === "revoked"}
            data-testid="api-token-revoke"
          >
            <Trash2 className="h-3.5 w-3.5" aria-hidden /> Revoke
          </Button>
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
          <Button
            variant="primary"
            size="lg"
            onClick={() => navigate("/settings/api-tokens/new")}
            data-testid="api-tokens-create-button"
          >
            <Plus className="h-4 w-4" aria-hidden /> Create token
          </Button>
        }
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Tokens" value={tokens.length} icon={<KeyRound className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Active" value={activeCount} tone="accent" />
        <StatCard label="Expired" value={expiredCount} tone={expiredCount ? "medium" : "neutral"} />
        <StatCard label="Revoked" value={revokedCount} tone={revokedCount ? "high" : "neutral"} />
      </section>

      <Card padded={false}>
        <div data-testid="api-tokens-table">
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
        </div>
      </Card>

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

// --- "copy this once" reveal (post-rotate) ---

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
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={copyToken}
              className="ml-3 shrink-0"
              data-testid="reveal-copy-button"
            >
              <ClipboardCopy className="h-3.5 w-3.5" aria-hidden /> {copied ? "Copied" : "Copy"}
            </Button>
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
          <Button
            type="button"
            variant="primary"
            size="lg"
            onClick={onClose}
            disabled={!acknowledged}
            data-testid="reveal-close"
          >
            Close
          </Button>
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
            <Button
              type="button"
              variant="ghost"
              size="icon"
              onClick={onClose}
              aria-label="Close"
            >
              ×
            </Button>
          )}
        </div>
        {children}
      </div>
    </div>
  );
}
