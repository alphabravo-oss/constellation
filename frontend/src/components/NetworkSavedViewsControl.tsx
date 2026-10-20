import { useRef, useState } from "react";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useSavedViews } from "@/hooks/useSavedViews";
import { useRouteSearchParams } from "@/lib/route-search";
import { downloadJson } from "@/lib/download";
import { networkViewHref } from "@/lib/network-saved-view-route";
import { buildNetworkSavedViewsExport, isNetworkSavedView, networkActivitySavedViewsStorageKey, normalizeNetworkSavedView, type NetworkSavedView, type NetworkSavedViewSnapshot } from "@/lib/network-saved-views";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/form";

export function NetworkSavedViewsControl({ clusterID, snapshot, onApply, unavailable = false }: { clusterID: string; snapshot: NetworkSavedViewSnapshot; groupLabel?: string; onApply: (snapshot: NetworkSavedViewSnapshot) => void; unavailable?: boolean }) {
  const identity = useTablePreferencesIdentity();
  const [params] = useRouteSearchParams();
  const hash = useLocation({ select: location => location.hash });
  const navigate = useNavigate();
  const key = networkActivitySavedViewsStorageKey(clusterID, identity?.user_id);
  const { views, deleteView, persistenceError, canPersist } = useSavedViews<NetworkSavedView>(key, { legacyUserScopedKey: identity?.user_id ? key : undefined, validate: (value): value is NetworkSavedView => isNetworkSavedView(value, clusterID) });
  const owner = `${identity?.org_id}:${identity?.user_id}:${clusterID}`;
  const activeOwner = useRef(owner); activeOwner.current = owner;
  const [selection, setSelection] = useState({ owner, id: "" });
  const selectedView = selection.owner === owner ? views.find(view => view.id === selection.id) : undefined;
  const disabled = unavailable || !clusterID || !canPersist;
  return <div className="flex min-w-0 flex-wrap items-center gap-2" data-testid="network-saved-views">
    {persistenceError && <p role="alert" className="w-full text-xs text-destructive">{persistenceError}</p>}
    <Select aria-label="Saved network view" data-testid="network-saved-view-select" className="h-9 max-w-56 rounded border border-input bg-card px-2 text-sm" value={selectedView?.id ?? ""} onChange={event => setSelection({ owner, id: event.target.value })}>
      <option value="">Saved views</option>{views.map(view => <option key={view.id} value={view.id}>{view.name}</option>)}
    </Select>
    <Button data-testid="network-saved-view-save" disabled={disabled} onClick={() => void navigate({ href: networkViewHref(clusterID, params, hash, "new", snapshot) })}>Save view</Button>
    <Button data-testid="network-saved-view-apply" disabled={disabled || !selectedView} onClick={() => { const view = normalizeNetworkSavedView(selectedView); if (activeOwner.current === owner && !disabled && view?.cluster_id === clusterID) onApply(view.filters); }}>Apply</Button>
    <Button data-testid="network-saved-view-delete" disabled={disabled || !selectedView} onClick={() => { if (activeOwner.current === owner && !disabled && selectedView && window.confirm(`Delete saved view “${selectedView.name}” from this browser?`) && deleteView(selectedView.id).ok) setSelection({ owner, id: "" }); }}>Delete</Button>
    <Button data-testid="network-saved-view-import" disabled={disabled} onClick={() => void navigate({ href: networkViewHref(clusterID, params, hash, "import", snapshot) })}>Import</Button>
    <Button data-testid="network-saved-view-export" disabled={disabled || !views.length} onClick={() => downloadJson(`constellation-network-activity-views-${clusterID}.json`, buildNetworkSavedViewsExport(clusterID, views))}>Export</Button>

  </div>;
}
