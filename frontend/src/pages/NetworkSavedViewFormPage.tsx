import { useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { useIsFetching, useQueryClient } from "@tanstack/react-query";
import { useCluster } from "@/hooks/useCluster";
import { useSavedViews } from "@/hooks/useSavedViews";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useRouteSearchParams } from "@/lib/route-search";
import { networkViewHref, networkViewSnapshotFromParams } from "@/lib/network-saved-view-route";
import { isNetworkSavedView, mergeNetworkSavedViews, networkActivitySavedViewsStorageKey, previewNetworkSavedViewsImport, suggestNetworkSavedViewName, type NetworkSavedView, type NetworkSavedViewSnapshot } from "@/lib/network-saved-views";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Field, Textarea, TextInput } from "@/components/ui/form";
import { PageHeader } from "@/components/ui/page";
import { ErrorState, LoadingState } from "@/components/ui/states";

export function NetworkSavedViewFormPage() { return <NetworkViewForm mode="new" />; }
export function NetworkSavedViewImportPage() { return <NetworkViewForm mode="import" />; }
function NetworkViewForm({ mode }: { mode: "new" | "import" }) {
  const { clusterId, cluster, isLoading, error } = useCluster();
  const identity = useTablePreferencesIdentity();
  const [params] = useRouteSearchParams();
  const hash = useLocation({ select: location => location.hash });
  const qc = useQueryClient();
  const fetching = useIsFetching({ queryKey: ["clusters"], exact: true }) + useIsFetching({ queryKey: ["cluster", clusterId], exact: true });
  const cacheReady = () => {
    const registry = qc.getQueryState<{ clusters: Array<{ id: string }> }>(["clusters"]);
    const detail = qc.getQueryState<{ id: string }>(["cluster", clusterId]);
    if (registry && (registry.status !== "success" || registry.fetchStatus !== "idle")) return false;
    if (detail && (detail.status === "error" || detail.fetchStatus !== "idle")) return false;
    return (!registry && !detail) || (registry?.data?.clusters.find(item => item.id === clusterId) ?? detail?.data)?.id === clusterId;
  };
  const scopeKey = `${identity?.org_id}:${identity?.user_id}:${clusterId}:${mode}`;
  const ready = Boolean(clusterId && cluster?.id === clusterId && !isLoading && !error && !fetching && cacheReady());
  const [confirmed, setConfirmed] = useState("");
  if (ready && confirmed !== scopeKey) setConfirmed(scopeKey);
  const snapshot = networkViewSnapshotFromParams(params);
  const back = clusterId ? networkViewHref(clusterId, params, hash) : "/clusters";
  return <div className="space-y-6" data-testid="network-saved-view-form-page">
    <PageHeader title={mode === "new" ? "Save network view" : "Import network views"} description="Saved views store network filters in this browser for your organization and user. They do not change network policy or start packet capture." backLink={<a href={back}>Back to Network</a>} />
    {!clusterId || !identity?.org_id.trim() || !identity.user_id.trim() ? <ErrorState title="An available cluster and user session are required." />
      : !ready && confirmed !== scopeKey ? isLoading || fetching ? <LoadingState label="Loading cluster…" /> : <ErrorState title="The selected cluster could not be resolved." />
      : (mode === "new" || params.has("network_view")) && !snapshot ? <ErrorState title="The network snapshot is missing or invalid. Return to Network and open the form again." />
      : <>
        {!ready && <ErrorState title="Cluster scope is unavailable or refreshing. Your draft is preserved; saving is paused." />}
        <NetworkViewEditor key={scopeKey} mode={mode} clusterID={clusterId} snapshot={snapshot} back={back} unavailable={!ready} recheck={() => ready && cacheReady()} />
      </>}
  </div>;
}
const previewColumns: Column<NetworkSavedView>[] = [
  { id: "name", header: "View", kind: "name", cell: view => view.name },
  { id: "workspace", header: "Workspace", kind: "status", cell: view => view.filters.workspace_tab },
  { id: "scope", header: "Filters", kind: "text", wrap: true, grow: true, cell: view => suggestNetworkSavedViewName(view.filters) },
];
function NetworkViewEditor({ mode, clusterID, snapshot, back, unavailable, recheck }: { mode: "new" | "import"; clusterID: string; snapshot: NetworkSavedViewSnapshot | null; back: string; unavailable: boolean; recheck: () => boolean }) {
  const identity = useTablePreferencesIdentity()!;
  const navigate = useNavigate();
  const storageKey = networkActivitySavedViewsStorageKey(clusterID, identity.user_id);
  const { saveView, setViews, persistenceError, canPersist } = useSavedViews<NetworkSavedView>(storageKey, { legacyUserScopedKey: storageKey, validate: (value): value is NetworkSavedView => isNetworkSavedView(value, clusterID) });
  const [name, setName] = useState(snapshot ? suggestNetworkSavedViewName(snapshot) : "");
  const [text, setText] = useState("");
  const [fileError, setFileError] = useState<string | null>(null);
  const [reading, setReading] = useState(false);
  const [saved, setSaved] = useState(false);
  const writing = useRef(false);
  const readToken = useRef(0);
  useEffect(() => () => { readToken.current++; }, []);
  const preview = useMemo(() => {
    if (!text.trim()) return { result: null, error: null };
    try { return { result: previewNetworkSavedViewsImport(text, clusterID), error: null }; }
    catch (failure) { return { result: null, error: failure instanceof Error ? failure.message : "The import could not be validated." }; }
  }, [text, clusterID]);
  const valid = mode === "new" ? Boolean(snapshot && name.trim() && name.trim().length <= 120) : Boolean(preview.result?.views.length && !reading && !fileError);
  const loadFile = async (file: File) => {
    const token = ++readToken.current; setReading(true); setFileError(null);
    try {
      if (file.size > 2_000_000) throw new Error("Import files must be at most 2 MB.");
      const content = await file.text();
      if (token !== readToken.current) return;
      setText(content);
    } catch { if (token === readToken.current) setFileError("The file could not be read. Choose a JSON file of at most 2 MB or paste its contents."); }
    finally { if (token === readToken.current) setReading(false); }
  };
  return <Card title={mode === "new" ? "Saved view" : "Import preview"} description={mode === "new" ? "Name the exact current network filter snapshot." : "Choose or paste an export, review the valid views, then save them for the current cluster."}>
    <form className="space-y-6" onSubmit={event => {
      event.preventDefault();
      if (!valid || unavailable || !canPersist || writing.current || !recheck()) return;
      const result = mode === "new" && snapshot ? saveView(name, { cluster_id: clusterID, saved_at: new Date().toISOString(), filters: snapshot }) : setViews(current => mergeNetworkSavedViews(current, preview.result!.views));
      if (result.ok) { writing.current = true; setSaved(true); void navigate({ href: back }); }
    }}>
      {mode === "new" ? <>
        <Field label="View name" htmlFor="network-view-name" required hint="Use 1 to 120 characters."><TextInput id="network-view-name" required autoFocus maxLength={120} value={name} onChange={event => setName(event.target.value)} /></Field>
        <Collapse label="Advanced: captured filters"><pre className="overflow-auto rounded bg-muted p-3 text-xs" data-testid="network-view-snapshot">{JSON.stringify(snapshot, null, 2)}</pre></Collapse>
      </> : <>
        <Field label="Saved-view JSON file" htmlFor="network-view-file"><TextInput id="network-view-file" type="file" accept=".json,application/json" onChange={event => { const file = event.target.files?.[0]; if (file) void loadFile(file); event.target.value = ""; }} /></Field>
        <Field label="JSON contents" htmlFor="network-view-json" hint="Nothing is imported until you press Save."><Textarea id="network-view-json" rows={8} value={text} onChange={event => { readToken.current++; setReading(false); setFileError(null); setText(event.target.value); }} /></Field>
        {reading && <LoadingState label="Reading import file…" />}
        {(fileError || preview.error) && <ErrorState title={fileError || preview.error!} />}
        {preview.result && <>
          <p role="status">{preview.result.views.length} valid {preview.result.views.length === 1 ? "view" : "views"}; {preview.result.rejected} rejected records. Valid views will be saved for this cluster ({clusterID}).{preview.result.sourceCluster && preview.result.sourceCluster !== clusterID ? ` The export originated from cluster ${preview.result.sourceCluster}.` : ""} Existing views are retained; duplicate IDs receive new IDs.</p>
          {preview.result.views.length > 0 ? <DataTable columns={previewColumns} rows={preview.result.views} rowKey={view => `${view.id}:${preview.result!.views.indexOf(view)}`} /> : <ErrorState title="No valid network views were found. Correct the JSON before saving." />}
          <Collapse label="Advanced: validated import"><pre className="overflow-auto rounded bg-muted p-3 text-xs">{JSON.stringify(preview.result.views, null, 2)}</pre></Collapse>
        </>}
      </>}
      {persistenceError && <ErrorState title={persistenceError} />}
      <div className="flex gap-3"><Button type="submit" variant="primary" size="lg" disabled={!valid || unavailable || !canPersist || saved}>{saved ? "Saved" : "Save"}</Button><Button type="button" variant="ghost" size="lg" onClick={() => void navigate({ href: back })}>Cancel</Button></div>
    </form>
  </Card>;
}
