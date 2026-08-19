// ScopeBar — sticky scope chips (cluster / namespace / label).
//
// Persists to URL (shareable) and localStorage (sticky across refresh).
// Used by every page that lives in a multi-cluster fleet; keeps the
// "what part of my fleet am I looking at" answer always visible.
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams, type SetURLSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Filter, X, ChevronDown } from "lucide-react";

import { clusters } from "@/api/client";
import { cn } from "@/lib/cn";

const STORAGE_KEY = "constellation.scope.v1";

export type Scope = {
  clusters: string[];
  namespaces: string[];
  labels: string[];
};

function emptyScope(): Scope {
  return { clusters: [], namespaces: [], labels: [] };
}

function readURL(sp: URLSearchParams): Scope {
  const get = (k: string) =>
    sp.get(k)?.split(",").map((s) => s.trim()).filter(Boolean) ?? [];
  return { clusters: get("cluster"), namespaces: get("namespace"), labels: get("label") };
}

function isNonEmpty(s: Scope): boolean {
  return s.clusters.length + s.namespaces.length + s.labels.length > 0;
}

function readStorage(): Scope | null {
  if (typeof localStorage === "undefined") return null;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<Scope>;
    return {
      clusters: parsed.clusters ?? [],
      namespaces: parsed.namespaces ?? [],
      labels: parsed.labels ?? [],
    };
  } catch {
    return null;
  }
}

export function useScope(): [Scope, (next: Scope) => void] {
  const [sp, setSp] = useSearchParams();
  const initial = useMemo(() => {
    const fromURL = readURL(sp);
    if (isNonEmpty(fromURL)) return fromURL;
    return readStorage() ?? emptyScope();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const [scope, setScopeState] = useState<Scope>(initial);

  const didSync = useRef(false);
  useEffect(() => {
    if (didSync.current) return;
    didSync.current = true;
    if (isNonEmpty(initial)) syncURL(initial, sp, setSp);
  }, [initial, sp, setSp]);

  const update = (next: Scope) => {
    setScopeState(next);
    syncURL(next, sp, setSp);
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(next)); } catch { /* noop */ }
  };
  return [scope, update];
}

function syncURL(s: Scope, sp: URLSearchParams, setSp: SetURLSearchParams) {
  const next = new URLSearchParams(sp);
  for (const [k, v] of [["cluster", s.clusters], ["namespace", s.namespaces], ["label", s.labels]] as const) {
    if (v.length === 0) next.delete(k);
    else next.set(k, v.join(","));
  }
  setSp(next, { replace: true });
}

export function ScopeBar({ className }: { className?: string }) {
  const [scope, setScope] = useScope();
  const clustersQ = useQuery({ queryKey: ["clusters"], queryFn: () => clusters.list() });
  const knownClusters = clustersQ.data?.clusters.map((c) => c.name) ?? [];
  const nonEmpty = isNonEmpty(scope);

  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-1.5 rounded-md border border-border bg-card px-3 py-1.5",
        className,
      )}
      data-testid="scope-bar"
    >
      <span className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground">
        <Filter className="h-3 w-3" /> Scope
      </span>

      <Chip
        label="Cluster"
        values={scope.clusters}
        options={knownClusters}
        placeholder="all clusters"
        onAdd={(v) => setScope({ ...scope, clusters: dedupe([...scope.clusters, v]) })}
        onRemove={(v) => setScope({ ...scope, clusters: scope.clusters.filter((x) => x !== v) })}
      />
      <Chip
        label="Namespace"
        values={scope.namespaces}
        options={[]}
        placeholder="all namespaces"
        onAdd={(v) => setScope({ ...scope, namespaces: dedupe([...scope.namespaces, v]) })}
        onRemove={(v) => setScope({ ...scope, namespaces: scope.namespaces.filter((x) => x !== v) })}
      />
      <Chip
        label="Label"
        values={scope.labels}
        options={[]}
        placeholder="key=value"
        onAdd={(v) => setScope({ ...scope, labels: dedupe([...scope.labels, v]) })}
        onRemove={(v) => setScope({ ...scope, labels: scope.labels.filter((x) => x !== v) })}
      />

      {nonEmpty && (
        <button
          type="button"
          onClick={() => setScope(emptyScope())}
          className="ml-auto rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-muted-foreground hover:text-foreground hover:bg-accent"
        >
          clear all
        </button>
      )}
    </div>
  );
}

function Chip({
  label, values, options, placeholder, onAdd, onRemove,
}: {
  label: string;
  values: string[];
  options: string[];
  placeholder: string;
  onAdd: (v: string) => void;
  onRemove: (v: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState("");
  const active = values.length > 0;
  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className={cn(
          "flex items-center gap-1.5 rounded h-6 px-2 text-[11px] border transition-colors",
          active
            ? "bg-[color-mix(in_oklab,var(--color-primary)_18%,transparent)] border-[color-mix(in_oklab,var(--color-primary)_36%,transparent)] text-[color:var(--color-primary)]"
            : "bg-card border-border hover:bg-accent",
        )}
      >
        <span className="text-muted-foreground">{label}</span>
        {values.length === 0 ? (
          <span className="text-muted-foreground/60">{placeholder}</span>
        ) : (
          <span className="text-mono font-medium">{values.length}</span>
        )}
        <ChevronDown className="h-3 w-3 opacity-60" />
      </button>
      {open && (
        <div
          className="absolute left-0 top-full z-30 mt-1 min-w-[16rem] rounded-md border border-border bg-popover p-2 shadow-[var(--elev-popover)]"
          onMouseLeave={() => setOpen(false)}
        >
          {values.length > 0 && (
            <div className="mb-2 flex flex-wrap gap-1">
              {values.map((v) => (
                <span key={v} className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-[10px] text-mono">
                  {v}
                  <button type="button" onClick={() => onRemove(v)} aria-label={`remove ${v}`} className="hover:text-foreground">
                    <X className="h-2.5 w-2.5" />
                  </button>
                </span>
              ))}
            </div>
          )}
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && draft.trim()) {
                onAdd(draft.trim());
                setDraft("");
              }
            }}
            placeholder={placeholder}
            autoFocus
            className="mb-2 w-full rounded border border-input bg-card px-2 py-1 text-xs outline-none focus:border-[color:var(--color-primary)]"
          />
          {options.length > 0 && (
            <ul className="max-h-40 overflow-auto text-xs">
              {options
                .filter((o) => o.toLowerCase().includes(draft.toLowerCase()))
                .filter((o) => !values.includes(o))
                .slice(0, 20)
                .map((o) => (
                  <li key={o}>
                    <button
                      type="button"
                      onClick={() => { onAdd(o); setDraft(""); }}
                      className="block w-full rounded px-2 py-1 text-left hover:bg-accent text-mono"
                    >
                      {o}
                    </button>
                  </li>
                ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

function dedupe<T>(xs: T[]): T[] {
  return Array.from(new Set(xs));
}
