// Wave C4: DLP regex rules UI.
//
// One page for the user to author / promote / demote / delete payload
// regex rules. Each rule has a name, severity (1–9), and a list of PCRE
// patterns dp's hyperscan engine compiles. Matches produce runtime_threats
// rows with dlp_name_hash set, which the threat drilldown already
// surfaces via the Wave 5b path.
//
// Layout: full-width stat row + rules table. Authoring/editing happens in a
// right-side Drawer opened by the "New rule" (+) button or a row's pencil —
// browsing the page shows only the verdict + list.
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
  runtimeDLP,
  type DLPMode,
  type DLPRule,
} from "@/api/client";

const MODE_BADGE: Record<DLPMode, { label: string; tone: "success" | "warning" | "neutral"; icon: React.ReactNode }> = {
  monitor:  { label: "Monitor",  tone: "warning", icon: <ShieldAlert className="h-3 w-3" aria-hidden /> },
  enforce:  { label: "Enforce",  tone: "success", icon: <ShieldCheck className="h-3 w-3" aria-hidden /> },
  disabled: { label: "Disabled", tone: "neutral", icon: <ShieldOff   className="h-3 w-3" aria-hidden /> },
};

export function RuntimeDLPPage() {
  const [search] = useSearchParams();
  const { id: pathClusterID } = useParams();
  const clusterID = pathClusterID ?? search.get("cluster_id") ?? "";

  const queryClient = useQueryClient();
  const q = useQuery({
    queryKey: ["runtime-dlp-rules", clusterID],
    queryFn: () => runtimeDLP.list(clusterID),
    enabled: !!clusterID,
  });

  // null = drawer closed, "" = new rule, "<id>" = editing that rule.
  const [editingID, setEditingID] = useState<string | null>(null);
  const rules = useMemo(() => q.data ?? [], [q.data]);
  const enforceCount = rules.filter((r) => r.mode === "enforce").length;
  const monitorCount = rules.filter((r) => r.mode === "monitor").length;

  const columns: Column<DLPRule>[] = [
    { id: "name", header: "Name", cell: (r) => <span className="font-mono">{r.name}</span>, sort: (a, b) => a.name.localeCompare(b.name) },
    { id: "severity", header: "Sev", numeric: true, cell: (r) => r.severity, sort: (a, b) => a.severity - b.severity },
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
    { id: "actions", header: "Actions", className: "text-right", cell: (r) => <DLPActions r={r} onEdit={() => setEditingID(r.id)} /> },
  ];

  if (!clusterID) {
    return (
      <div className="flex h-[calc(100vh-72px)] items-center justify-center text-sm text-muted-foreground" data-testid="runtime-dlp-empty">
        Select a cluster (the URL needs <code>?cluster_id=&lt;uuid&gt;</code>).
      </div>
    );
  }
  return (
    <div className="space-y-6" data-testid="runtime-dlp-page">
      <PageHeader
        title="DLP Rules"
        description="Data-loss-prevention patterns dp scans network payloads for. New rules start in monitor mode; promote one to enforce to start blocking matches."
        actions={
          <Button size="sm" variant="outline" onClick={() => setEditingID("")} data-testid="runtime-dlp-new">
            <Plus className="mr-1 h-3.5 w-3.5" /> New rule
          </Button>
        }
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <StatCard label="Total rules" value={rules.length} icon={<ListChecks className="h-3.5 w-3.5" />} />
        <StatCard label="Monitoring" value={monitorCount} icon={<ShieldAlert className="h-3.5 w-3.5" />} />
        <StatCard label="Enforcing" value={enforceCount} icon={<ShieldCheck className="h-3.5 w-3.5" />} tone={enforceCount > 0 ? "accent" : "neutral"} />
      </section>

      <div className="overflow-x-auto rounded-lg border border-border bg-card" data-testid="runtime-dlp-list">
        {q.isLoading && <LoadingState />}
        {q.isError && <ErrorState error={q.error} />}
        {q.data && (
          <DataTable
            rows={rules}
            columns={columns}
            rowKey={(r) => r.id}
            showDensityToggle={false}
            emptyState={<EmptyState title="No DLP rules yet" hint="Click New rule to author one." />}
          />
        )}
      </div>

      <Drawer
        open={editingID !== null}
        onOpenChange={(o) => { if (!o) setEditingID(null); }}
        title={editingID ? "Edit DLP rule" : "New DLP rule"}
        description="PCRE patterns dp's hyperscan engine compiles and scans payloads against."
      >
        {editingID !== null && (
          <DLPEditor
            clusterID={clusterID}
            ruleID={editingID || null}
            onSaved={() => {
              setEditingID(null);
              void queryClient.invalidateQueries({ queryKey: ["runtime-dlp-rules", clusterID] });
            }}
          />
        )}
      </Drawer>
    </div>
  );
}

function DLPActions({ r, onEdit }: { r: DLPRule; onEdit: () => void }) {
  const queryClient = useQueryClient();
  const promote = useMutation({
    mutationFn: () => runtimeDLP.promote(r.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-dlp-rules"] }),
  });
  const demote = useMutation({
    mutationFn: () => runtimeDLP.demote(r.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-dlp-rules"] }),
  });
  const remove = useMutation({
    mutationFn: () => runtimeDLP.remove(r.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-dlp-rules"] }),
  });
  return (
    <div className="inline-flex items-center gap-1" data-testid={`runtime-dlp-row-${r.id}`}>
      {r.mode === "monitor" && (
        <Button size="sm" variant="outline" onClick={() => promote.mutate()} disabled={promote.isPending} data-testid={`runtime-dlp-promote-${r.id}`}>
          Promote
        </Button>
      )}
      {r.mode === "enforce" && (
        <Button size="sm" variant="outline" onClick={() => demote.mutate()} disabled={demote.isPending} data-testid={`runtime-dlp-demote-${r.id}`}>
          Demote
        </Button>
      )}
      <Button size="sm" variant="ghost" onClick={onEdit} data-testid={`runtime-dlp-edit-${r.id}`}>
        <Edit3 className="h-3.5 w-3.5" />
      </Button>
      <Button
        size="sm"
        variant="ghost"
        onClick={() => {
          if (window.confirm(`Delete DLP rule "${r.name}"?`)) remove.mutate();
        }}
        disabled={remove.isPending}
        data-testid={`runtime-dlp-delete-${r.id}`}
      >
        <Trash2 className="h-3.5 w-3.5" />
      </Button>
    </div>
  );
}

function DLPEditor({
  clusterID,
  ruleID,
  onSaved,
}: {
  clusterID: string;
  ruleID: string | null;
  onSaved: (r: DLPRule) => void;
}) {
  const existing = useQuery({
    queryKey: ["runtime-dlp-rule", ruleID],
    queryFn: () => runtimeDLP.get(ruleID as string),
    enabled: !!ruleID,
  });

  const [name, setName] = useState("");
  const [severity, setSeverity] = useState(5);
  const [description, setDescription] = useState("");
  // One pattern per line for easy authoring. Empty lines are dropped on save.
  const [patternsText, setPatternsText] = useState("");
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (existing.data) {
      setName(existing.data.name);
      setSeverity(existing.data.severity);
      setDescription(existing.data.description ?? "");
      setPatternsText((existing.data.patterns ?? []).join("\n"));
    } else if (!ruleID) {
      setName("");
      setSeverity(5);
      setDescription("");
      setPatternsText("");
    }
  }, [existing.data, ruleID]);

  const parsedPatterns = (): string[] =>
    patternsText.split("\n").map((s) => s.trim()).filter(Boolean);

  const save = useMutation({
    mutationFn: async (): Promise<DLPRule> => {
      setErr(null);
      const patterns = parsedPatterns();
      if (patterns.length === 0) throw new Error("at least one pattern is required");
      if (ruleID) {
        return runtimeDLP.update(ruleID, { patterns, severity, description });
      }
      if (!name) throw new Error("name is required");
      return runtimeDLP.create({
        cluster_id: clusterID, name, severity, patterns, description,
        mode: "monitor",
      });
    },
    onSuccess: onSaved,
    onError: (e) => setErr((e as Error).message),
  });

  return (
    <div className="flex flex-col gap-3" data-testid="runtime-dlp-editor">
      <DLPField label="Name" value={name} onChange={setName} disabled={!!ruleID} placeholder="aws-keys" />
      <div className="flex items-center gap-2">
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Severity</div>
        <input
          type="range"
          min={1}
          max={9}
          value={severity}
          onChange={(e) => setSeverity(Number(e.target.value))}
          className="flex-1"
          data-testid="runtime-dlp-editor-severity"
        />
        <span className="text-mono text-xs tabular-nums">{severity}</span>
      </div>
      <DLPField label="Description" value={description} onChange={setDescription} placeholder="What does this catch?" />
      <div className="flex flex-col">
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Patterns (one PCRE per line)</div>
        <textarea
          className="mt-0.5 min-h-[220px] w-full rounded border border-input bg-background p-2 font-mono text-[11px] outline-none focus:border-[color:var(--color-primary)]"
          value={patternsText}
          onChange={(e) => setPatternsText(e.target.value)}
          spellCheck={false}
          placeholder={"AKIA[0-9A-Z]{16}\nAIza[0-9A-Za-z\\-_]{35}"}
          data-testid="runtime-dlp-editor-patterns"
        />
      </div>
      {err && (
        <div
          className="rounded border border-[color:var(--color-status-error)] bg-card p-2 text-[11px] text-[color:var(--color-status-error)]"
          data-testid="runtime-dlp-editor-error"
        >
          {err}
        </div>
      )}
      <div className="flex flex-col gap-2">
        <Button onClick={() => save.mutate()} disabled={save.isPending} data-testid="runtime-dlp-editor-save">
          {ruleID ? "Save changes" : "Create (in monitor mode)"}
        </Button>
        <span className="text-[10px] text-muted-foreground">
          dp's hyperscan validates each pattern on compile; bad regex = the rule fails to apply and an audit event records the error.
        </span>
      </div>
    </div>
  );
}

function DLPField({
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
