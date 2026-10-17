import { useRef, useState } from "react";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { useIsFetching, useQueryClient } from "@tanstack/react-query";
import { useCluster } from "@/hooks/useCluster";
import { useSavedViews, type SavedViewBase } from "@/hooks/useSavedViews";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useRouteSearchParams } from "@/lib/route-search";
import { FINDING_VIEWS_KEY, TIMELINE_VIEWS_KEY, findingViewPayload, timelineViewPayload, isFindingSavedView, isTimelineSavedView, inventoryViewHref, type InventoryViewKind, type FindingSavedView, type TimelineSavedView } from "@/lib/inventory-saved-views";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { Field, TextInput } from "@/components/ui/form";
import { PageHeader } from "@/components/ui/page";
import { ErrorState, LoadingState } from "@/components/ui/states";

type InventorySavedView = FindingSavedView | TimelineSavedView;
export function FindingSavedViewFormPage() { return <InventorySavedViewForm inventory="findings" />; }
export function TimelineSavedViewFormPage() { return <InventorySavedViewForm inventory="timeline" />; }
function InventorySavedViewForm({ inventory }: { inventory: InventoryViewKind }) {
  const { clusterId, cluster, isLoading, error } = useCluster();
  const identity = useTablePreferencesIdentity();
  const [params] = useRouteSearchParams();
  const hash = useLocation({ select: location => location.hash });
  const qc = useQueryClient();
  const registryFetching = useIsFetching({ queryKey: ["clusters"], exact: true });
  const detailFetching = useIsFetching({ queryKey: ["cluster", clusterId], exact: true });
  const cachedScopeReady = () => {
    const registry = qc.getQueryState<{ clusters: Array<{ id: string }> }>(["clusters"]);
    const detail = qc.getQueryState<{ id: string }>(["cluster", clusterId]);
    if (registry && (registry.status !== "success" || registry.fetchStatus !== "idle")) return false;
    if (detail && (detail.status === "error" || detail.fetchStatus !== "idle")) return false;
    return (!registry && !detail) || (registry?.data?.clusters.find(item => item.id === clusterId) ?? detail?.data)?.id === clusterId;
  };
  const scopeReady = Boolean(clusterId && cluster?.id === clusterId && !isLoading && !error && !registryFetching && !detailFetching && cachedScopeReady());
  const [confirmed, setConfirmed] = useState(false);
  if (scopeReady && !confirmed) setConfirmed(true);
  const payload = inventory === "findings" ? findingViewPayload(params) : timelineViewPayload(params);
  const returnHref = clusterId ? inventoryViewHref(clusterId, inventory, params, hash) : `/${inventory}`;
  return <div className="space-y-6" data-testid="inventory-saved-view-form-page">
    <PageHeader title={`Save ${inventory === "findings" ? "findings" : "timeline"} view`} description="Name the current filter configuration. Saved views are stored in this browser for your organization and user."
      backLink={<a href={returnHref}>Back to {inventory}</a>} />
    {!clusterId || !identity ? <ErrorState title="An available cluster and user session are required to save a view." />
      : !scopeReady && !confirmed ? isLoading || registryFetching || detailFetching ? <LoadingState label="Loading cluster…" /> : <ErrorState title="The selected cluster could not be resolved." />
      : !payload ? <ErrorState title="The current filters are invalid. Return to the inventory and correct them before saving a view." />
      : <>
          {!scopeReady && <ErrorState title="Cluster scope is unavailable or refreshing. Your draft is preserved; saving is paused." />}
          <SavedViewEditor key={`${identity.org_id}:${identity.user_id}:${clusterId}:${inventory}`} inventory={inventory} payload={payload} returnHref={returnHref} unavailable={!scopeReady} recheck={() => scopeReady && cachedScopeReady()} />
        </>}
  </div>;
}
function SavedViewEditor({ inventory, payload, returnHref, unavailable, recheck }: { inventory: InventoryViewKind; payload: Omit<InventorySavedView, keyof SavedViewBase>; returnHref: string; unavailable: boolean; recheck: () => boolean }) {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [saved, setSaved] = useState(false);
  const writing = useRef(false);
  const validName = Boolean(name.trim()) && name.trim().length <= 120;
  const { saveView, persistenceError, canPersist } = useSavedViews<InventorySavedView>(inventory === "findings" ? FINDING_VIEWS_KEY : TIMELINE_VIEWS_KEY, { validate: inventory === "findings" ? isFindingSavedView : isTimelineSavedView });
  return <Card title="Saved view" description="The current search, filters and view settings are captured. Page and selected-row context are preserved for the return trip.">
    <form className="space-y-6" onSubmit={event => {
      event.preventDefault();
      if (!validName || unavailable || !canPersist || writing.current || !recheck()) return;
      const result = saveView(name, payload);
      if (result.ok) { writing.current = true; setSaved(true); void navigate({ href: returnHref }); }
    }}>
      <Field label="View name" htmlFor="saved-view-name" required hint="Use 1 to 120 characters."><TextInput id="saved-view-name" required autoFocus maxLength={120} value={name} onChange={event => setName(event.target.value)} /></Field>
      <Collapse label="Advanced: captured filters"><pre className="overflow-auto rounded-md bg-muted p-3 text-xs" data-testid="saved-view-payload">{JSON.stringify(payload, null, 2)}</pre></Collapse>
      {persistenceError && <ErrorState title={persistenceError} />}
      <div className="flex gap-3"><Button type="submit" variant="primary" size="lg" disabled={!validName || unavailable || !canPersist || saved}>{saved ? "Saved" : "Save"}</Button><Button type="button" variant="ghost" size="lg" onClick={() => void navigate({ href: returnHref })}>Cancel</Button></div>
    </form>
  </Card>;
}
