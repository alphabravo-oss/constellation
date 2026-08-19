// Wave D4: custom DPI signatures UI.
//
// Structurally identical to RuntimeDLPPage but bound to the signatures
// endpoints. Signatures default to bidirectional (apply_dir=3) on
// create; DLP rules default to egress (apply_dir=1).
//
// The shared backing table means a row authored here shows up in the same
// runtime_threats stream as DLP — only the threat row's row-of-origin
// (via the dp_rule_id → rule) tells operators what fired. We surface the
// distinction by giving signatures their own page so attack-pattern
// authoring doesn't collide visually with data-exfiltration authoring.
//
// Layout: full-width stat row + signatures table. Authoring/editing happens
// in a right-side Drawer opened by the "New signature" (+) button or a row's
// pencil.
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams, useSearchParams } from "react-router-dom";
import {
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  ListChecks,
  Plus,
  Edit3,
  Trash2,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { StatusPill } from "@/components/ui/status-pill";
import { Drawer } from "@/components/ui/drawer";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";
import { cn } from "@/lib/cn";

import {
  runtimeSignatures,
  type DLPMode,
  type DLPRule,
} from "@/api/client";

const MODE_BADGE: Record<DLPMode, { label: string; tone: "success" | "warning" | "neutral"; icon: React.ReactNode }> = {
  monitor:  { label: "Monitor",  tone: "warning", icon: <ShieldAlert className="h-3 w-3" aria-hidden /> },
  enforce:  { label: "Enforce",  tone: "success", icon: <ShieldCheck className="h-3 w-3" aria-hidden /> },
  disabled: { label: "Disabled", tone: "neutral", icon: <ShieldOff   className="h-3 w-3" aria-hidden /> },
};

const APPLY_DIR_LABEL: Record<number, string> = {
  1: "egress",
  2: "ingress",
  3: "both",
};

export function RuntimeSignaturesPage() {
  const [search] = useSearchParams();
  const { id: pathClusterID } = useParams();
  const clusterID = pathClusterID ?? search.get("cluster_id") ?? "";
  const queryClient = useQueryClient();

  const q = useQuery({
    queryKey: ["runtime-signatures", clusterID],
    queryFn: () => runtimeSignatures.list(clusterID),
    enabled: !!clusterID,
  });

  // null = drawer closed, "" = new signature, "<id>" = editing that signature.
  const [editingID, setEditingID] = useState<string | null>(null);
  const rules = useMemo(() => q.data ?? [], [q.data]);
  const enforceCount = rules.filter((r) => r.mode === "enforce").length;
  const monitorCount = rules.filter((r) => r.mode === "monitor").length;

  const columns: Column<DLPRule>[] = [
    { id: "name", header: "Name", cell: (r) => <span className="font-mono">{r.name}</span>, sort: (a, b) => a.name.localeCompare(b.name) },
    { id: "severity", header: "Sev", numeric: true, cell: (r) => r.severity, sort: (a, b) => a.severity - b.severity },
    {
      id: "direction",
      header: "Direction",
      cell: (r) => <span className="text-mono text-[10px] text-muted-foreground">{APPLY_DIR_LABEL[r.apply_dir] ?? "—"}</span>,
      sort: (a, b) => (APPLY_DIR_LABEL[a.apply_dir] ?? "").localeCompare(APPLY_DIR_LABEL[b.apply_dir] ?? ""),
    },
    {
      id: "mode",
      header: "Mode",
      cell: (r) => {
        const badge = MODE_BADGE[r.mode];
        return <StatusPill label={badge.label} tone={badge.tone} />;
      },
      sort: (a, b) => a.mode.localeCompare(b.mode),
    },
    {
      id: "patterns",
      header: "Patterns",
      numeric: true,
      cell: (r) => (Array.isArray(r.patterns) ? r.patterns.length : 0),
      sort: (a, b) => (Array.isArray(a.patterns) ? a.patterns.length : 0) - (Array.isArray(b.patterns) ? b.patterns.length : 0),
    },
    { id: "actions", header: "Actions", className: "text-right", cell: (r) => <SignatureActions r={r} onEdit={() => setEditingID(r.id)} /> },
  ];

  if (!clusterID) {
    return (
      <div className="flex h-[calc(100vh-72px)] items-center justify-center text-sm text-muted-foreground" data-testid="runtime-signatures-empty">
        Select a cluster (the URL needs <code>?cluster_id=&lt;uuid&gt;</code>).
      </div>
    );
  }
  return (
    <div className="space-y-6" data-testid="runtime-signatures-page">
      <PageHeader
        title="DPI Signatures"
        description="Attack-pattern PCRE rules dp matches against packet payloads (bidirectional by default). New signatures start in monitor mode; promote one to enforce to start blocking."
        actions={
          <Button size="sm" variant="outline" onClick={() => setEditingID("")} data-testid="runtime-signatures-new">
            <Plus className="mr-1 h-3.5 w-3.5" /> New signature
          </Button>
        }
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <StatCard label="Total signatures" value={rules.length} icon={<ListChecks className="h-3.5 w-3.5" />} />
        <StatCard label="Monitoring" value={monitorCount} icon={<ShieldAlert className="h-3.5 w-3.5" />} />
        <StatCard label="Enforcing" value={enforceCount} icon={<ShieldCheck className="h-3.5 w-3.5" />} tone={enforceCount > 0 ? "accent" : "neutral"} />
      </section>

      <div className="overflow-x-auto rounded-lg border border-border bg-card" data-testid="runtime-signatures-list">
        {q.isLoading && <LoadingState />}
        {q.isError && <ErrorState error={q.error} />}
        {q.data && (
          <DataTable
            rows={rules}
            columns={columns}
            rowKey={(r) => r.id}
            showDensityToggle={false}
            emptyState={<EmptyState title="No signatures yet" hint="Click New signature to author one." />}
          />
        )}
      </div>

      <Drawer
        open={editingID !== null}
        onOpenChange={(o) => { if (!o) setEditingID(null); }}
        title={editingID ? "Edit signature" : "New signature"}
        description="Attack-pattern PCRE patterns dp's hyperscan engine compiles and matches payloads against."
      >
        {editingID !== null && (
          <SignatureEditor
            clusterID={clusterID}
            ruleID={editingID || null}
            onSaved={() => {
              setEditingID(null);
              void queryClient.invalidateQueries({ queryKey: ["runtime-signatures", clusterID] });
            }}
          />
        )}
      </Drawer>
    </div>
  );
}

function SignatureActions({ r, onEdit }: { r: DLPRule; onEdit: () => void }) {
  const queryClient = useQueryClient();
  const promote = useMutation({
    mutationFn: () => runtimeSignatures.promote(r.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-signatures"] }),
  });
  const demote = useMutation({
    mutationFn: () => runtimeSignatures.demote(r.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-signatures"] }),
  });
  const remove = useMutation({
    mutationFn: () => runtimeSignatures.remove(r.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-signatures"] }),
  });
  return (
    <div className="inline-flex items-center gap-1" data-testid={`runtime-signature-row-${r.id}`}>
      {r.mode === "monitor" && (
        <Button size="sm" variant="outline" onClick={() => promote.mutate()} disabled={promote.isPending} data-testid={`runtime-signature-promote-${r.id}`}>
          Promote
        </Button>
      )}
      {r.mode === "enforce" && (
        <Button size="sm" variant="outline" onClick={() => demote.mutate()} disabled={demote.isPending} data-testid={`runtime-signature-demote-${r.id}`}>
          Demote
        </Button>
      )}
      <Button size="sm" variant="ghost" onClick={onEdit} data-testid={`runtime-signature-edit-${r.id}`}>
        <Edit3 className="h-3.5 w-3.5" />
      </Button>
      <Button
        size="sm"
        variant="ghost"
        onClick={() => {
          if (window.confirm(`Delete signature "${r.name}"?`)) remove.mutate();
        }}
        disabled={remove.isPending}
        data-testid={`runtime-signature-delete-${r.id}`}
      >
        <Trash2 className="h-3.5 w-3.5" />
      </Button>
    </div>
  );
}

function SignatureEditor({
  clusterID,
  ruleID,
  onSaved,
}: {
  clusterID: string;
  ruleID: string | null;
  onSaved: (r: DLPRule) => void;
}) {
  const existing = useQuery({
    queryKey: ["runtime-signature", ruleID],
    queryFn: () => runtimeSignatures.get(ruleID as string),
    enabled: !!ruleID,
  });

  const [name, setName] = useState("");
  const [severity, setSeverity] = useState(5);
  const [applyDir, setApplyDir] = useState(3); // both
  const [description, setDescription] = useState("");
  const [patternsText, setPatternsText] = useState("");
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (existing.data) {
      setName(existing.data.name);
      setSeverity(existing.data.severity);
      setApplyDir(existing.data.apply_dir || 3);
      setDescription(existing.data.description ?? "");
      setPatternsText((existing.data.patterns ?? []).join("\n"));
    } else if (!ruleID) {
      setName("");
      setSeverity(5);
      setApplyDir(3);
      setDescription("");
      setPatternsText("");
    }
  }, [existing.data, ruleID]);

  const save = useMutation({
    mutationFn: async (): Promise<DLPRule> => {
      setErr(null);
      const patterns = patternsText.split("\n").map((s) => s.trim()).filter(Boolean);
      if (patterns.length === 0) throw new Error("at least one pattern is required");
      if (ruleID) {
        return runtimeSignatures.update(ruleID, { patterns, severity, description });
      }
      if (!name) throw new Error("name is required");
      return runtimeSignatures.create({
        cluster_id: clusterID, name, severity, patterns,
        description, mode: "monitor", apply_dir: applyDir,
      });
    },
    onSuccess: onSaved,
    onError: (e) => setErr((e as Error).message),
  });

  return (
    <div className="flex flex-col gap-3" data-testid="runtime-signatures-editor">
      <SigField label="Name" value={name} onChange={setName} disabled={!!ruleID} placeholder="log4shell-jndi" />
      <div className="flex items-center gap-2">
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Severity</div>
        <input
          type="range"
          min={1}
          max={9}
          value={severity}
          onChange={(e) => setSeverity(Number(e.target.value))}
          className="flex-1"
          data-testid="runtime-signatures-editor-severity"
        />
        <span className="text-mono text-xs tabular-nums">{severity}</span>
      </div>
      <div className="flex items-center gap-2">
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Direction</div>
        <select
          value={applyDir}
          onChange={(e) => setApplyDir(Number(e.target.value))}
          disabled={!!ruleID /* dp doesn't re-key existing rules on direction change */}
          className="rounded border border-input bg-background px-2 py-1 text-xs outline-none focus:border-[color:var(--color-primary)]"
          data-testid="runtime-signatures-editor-direction"
        >
          <option value={3}>Both (default — catch attacks either way)</option>
          <option value={1}>Egress only</option>
          <option value={2}>Ingress only</option>
        </select>
      </div>
      <SigField label="Description" value={description} onChange={setDescription} placeholder="What does this catch?" />
      <div className="flex flex-col">
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Patterns (one PCRE per line)</div>
        <textarea
          className="mt-0.5 min-h-[220px] w-full rounded border border-input bg-background p-2 font-mono text-[11px] outline-none focus:border-[color:var(--color-primary)]"
          value={patternsText}
          onChange={(e) => setPatternsText(e.target.value)}
          spellCheck={false}
          placeholder={"\\$\\{jndi:(ldap|rmi|dns)://[^}]+\\}\n\\.\\.\\/\\.\\.\\/(etc|root)"}
          data-testid="runtime-signatures-editor-patterns"
        />
      </div>
      {err && (
        <div
          className="rounded border border-[color:var(--color-status-error)] bg-card p-2 text-[11px] text-[color:var(--color-status-error)]"
          data-testid="runtime-signatures-editor-error"
        >
          {err}
        </div>
      )}
      <div className="flex flex-col gap-2">
        <Button onClick={() => save.mutate()} disabled={save.isPending} data-testid="runtime-signatures-editor-save">
          {ruleID ? "Save changes" : "Create (in monitor mode)"}
        </Button>
        <span className="text-[10px] text-muted-foreground">
          Same dp hyperscan engine that runs the NeuVector built-ins (SQL injection, log4shell, etc.).
        </span>
      </div>
    </div>
  );
}

function SigField({
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
          "mt-0.5 w-full rounded border border-input bg-background px-2 py-1 text-xs outline-none focus:border-[color:var(--color-primary)]",
          disabled && "opacity-60",
        )}
      />
    </div>
  );
}
