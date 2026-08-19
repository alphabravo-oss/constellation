// CrudPage is a generic list/create/edit/delete shell used by the Wave D pages
// (VulnProfile, Groups, WAF, DLP). It accepts a list query, a row renderer, and
// a JSON-editing form (Monaco-lite via plain textarea for simplicity).
//
// Wave J2 cluster-mode contract: when consumed under /clusters/:id/* the page
// passes the active cluster_id through `useCluster()` into list+create calls so
// the underlying handler can scope rows by cluster_id (with NULL=org-wide).
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Save, Trash2, X } from "lucide-react";

import { useCluster } from "@/hooks/useCluster";

export interface CrudAPI<T extends { id: string }, TBody> {
  list:   (params?: { cluster_id?: string }) => Promise<{ items: T[] }>;
  create: (body: TBody, params?: { cluster_id?: string }) => Promise<unknown>;
  update: (id: string, body: TBody) => Promise<unknown>;
  delete: (id: string) => Promise<unknown>;
}

export interface CrudPageProps<T extends { id: string }, TBody> {
  title: string;
  description: string;
  queryKey: string;
  api: CrudAPI<T, TBody>;
  emptyBody: () => TBody;
  toBody: (row: T) => TBody;
  columns: Array<{ header: string; render: (row: T) => React.ReactNode }>;
}

export function CrudPage<T extends { id: string }, TBody>({
  title,
  description,
  queryKey,
  api,
  emptyBody,
  toBody,
  columns,
}: CrudPageProps<T, TBody>) {
  const qc = useQueryClient();
  // Cluster-scoped per the cluster-first IA. clusterId is undefined when this
  // component is rendered outside a /clusters/:id/* route (legacy/admin views),
  // in which case the server defaults to "no filter" and returns org-wide rows.
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const q = useQuery({
    queryKey: [queryKey, clusterId],
    queryFn: () => api.list({ cluster_id: clusterId }),
  });
  const rows = useMemo(() => q.data?.items ?? [], [q.data]);

  const [editing, setEditing] = useState<{ id?: string; body: TBody; raw: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const saveMut = useMutation({
    mutationFn: async () => {
      if (!editing) return;
      let body: TBody;
      try {
        body = JSON.parse(editing.raw);
      } catch (e) {
        setError((e as Error).message);
        return;
      }
      setError(null);
      if (editing.id) await api.update(editing.id, body);
      else await api.create(body, { cluster_id: clusterId });
    },
    onSuccess: () => {
      setEditing(null);
      void qc.invalidateQueries({ queryKey: [queryKey, clusterId] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const delMut = useMutation({
    mutationFn: (id: string) => api.delete(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: [queryKey, clusterId] }),
  });

  const openCreate = () => {
    const body = emptyBody();
    setEditing({ body, raw: JSON.stringify(body, null, 2) });
    setError(null);
  };
  const openEdit = (row: T) => {
    const body = toBody(row);
    setEditing({ id: row.id, body, raw: JSON.stringify(body, null, 2) });
    setError(null);
  };

  if (clusterLoading) {
    return <p className="text-sm text-muted-foreground" data-testid={`${queryKey}-loading`}>Loading cluster…</p>;
  }

  return (
    <div className="space-y-4" data-testid={`${queryKey}-page`} data-cluster-id={clusterId ?? ""}>
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{title}</h1>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
        <button
          type="button"
          onClick={openCreate}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:opacity-90"
        >
          <Plus className="h-3.5 w-3.5" /> New
        </button>
      </header>

      <section className="rounded-lg border border-border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b border-border bg-muted/40 text-xs text-muted-foreground">
            <tr>
              {columns.map((c) => (
                <th key={c.header} className="px-3 py-2 text-left font-medium">{c.header}</th>
              ))}
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && !q.isPending && (
              <tr>
                <td colSpan={columns.length + 1} className="px-3 py-6 text-center text-xs text-muted-foreground">
                  None yet.
                </td>
              </tr>
            )}
            {rows.map((row) => (
              <tr key={row.id} className="border-b border-border last:border-b-0 hover:bg-accent/40">
                {columns.map((c, i) => (
                  <td key={i} className="px-3 py-2 align-top text-xs">{c.render(row)}</td>
                ))}
                <td className="px-3 py-2 text-right whitespace-nowrap">
                  <button onClick={() => openEdit(row)} className="rounded-md px-2 py-1 text-xs hover:bg-accent">
                    Edit
                  </button>
                  <button
                    onClick={() => {
                      if (window.confirm("Delete?")) delMut.mutate(row.id);
                    }}
                    className="rounded-md p-1 hover:bg-accent"
                    aria-label="Delete"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {editing && (
        <section className="rounded-lg border border-border bg-card p-4 space-y-3">
          <div className="flex items-start justify-between">
            <h2 className="text-base font-semibold">{editing.id ? "Edit" : "Create"}</h2>
            <button type="button" onClick={() => setEditing(null)} className="rounded-md p-1 hover:bg-accent" aria-label="Close">
              <X className="h-4 w-4" />
            </button>
          </div>
          <p className="text-xs text-muted-foreground">Edit the JSON body directly. The server validates on save.</p>
          <textarea
            className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs font-mono"
            rows={20}
            value={editing.raw}
            onChange={(e) => setEditing({ ...editing, raw: e.target.value })}
            spellCheck={false}
          />
          {error && <p className="text-xs text-status-error">{error}</p>}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setEditing(null)}
              className="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-accent"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => saveMut.mutate()}
              disabled={saveMut.isPending}
              className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
            >
              <Save className="h-3.5 w-3.5" /> {saveMut.isPending ? "Saving…" : "Save"}
            </button>
          </div>
        </section>
      )}
    </div>
  );
}
