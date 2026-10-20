import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Bookmark, ChevronDown } from "lucide-react";
import { ToolbarButton } from "@/ui";
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
  return <SavedViewsDisclosure label={selectedView?.name ?? "Views"} count={views.length}>
    <div className="space-y-3" data-testid="network-saved-views">
    {persistenceError && <p role="alert" className="text-meta text-status-error">{persistenceError}</p>}
    <Select aria-label="Saved network view" data-testid="network-saved-view-select" className="w-full" value={selectedView?.id ?? ""} onChange={event => setSelection({ owner, id: event.target.value })}>
      <option value="">Choose a saved view</option>{views.map(view => <option key={view.id} value={view.id}>{view.name}</option>)}
    </Select>
    <div className="flex flex-wrap gap-2">
      <Button size="sm" variant="primary" data-testid="network-saved-view-apply" disabled={disabled || !selectedView} onClick={() => { const view = normalizeNetworkSavedView(selectedView); if (activeOwner.current === owner && !disabled && view?.cluster_id === clusterID) onApply(view.filters); }}>Apply</Button>
      <Button size="sm" data-testid="network-saved-view-save" disabled={disabled} onClick={() => void navigate({ href: networkViewHref(clusterID, params, hash, "new", snapshot) })}>Save view</Button>
      <Button size="sm" variant="ghost" data-testid="network-saved-view-delete" disabled={disabled || !selectedView} onClick={() => { if (activeOwner.current === owner && !disabled && selectedView && window.confirm(`Delete saved view “${selectedView.name}” from this browser?`) && deleteView(selectedView.id).ok) setSelection({ owner, id: "" }); }}>Delete</Button>
    </div>
    <div className="flex flex-wrap gap-2 border-t border-border pt-3">
      <Button size="sm" variant="ghost" data-testid="network-saved-view-import" disabled={disabled} onClick={() => void navigate({ href: networkViewHref(clusterID, params, hash, "import", snapshot) })}>Import</Button>
      <Button size="sm" variant="ghost" data-testid="network-saved-view-export" disabled={disabled || !views.length} onClick={() => downloadJson(`constellation-network-activity-views-${clusterID}.json`, buildNetworkSavedViewsExport(clusterID, views))}>Export</Button>
    </div>
    </div>
  </SavedViewsDisclosure>;
}

/** Views ▾ toolbar button with a mounted panel (state survives open/close). */
function SavedViewsDisclosure({ label, count, children }: { label: string; count: number; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (event: MouseEvent) => { const target = event.target as HTMLElement; if (target.closest?.("[data-radix-popper-content-wrapper]")) return; if (ref.current && !ref.current.contains(target)) setOpen(false); };
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDown); document.removeEventListener("keydown", onKey); };
  }, [open]);
  return <div ref={ref} className="relative shrink-0">
    <ToolbarButton aria-expanded={open} aria-controls={id} onClick={() => setOpen(value => !value)} className="whitespace-nowrap">
      <Bookmark className="h-4 w-4" />
      <span className="max-w-40 truncate">{label}</span>
      {count > 0 ? <span className="tabular-nums text-muted-foreground">{count}</span> : null}
      <ChevronDown className="h-3 w-3 text-muted-foreground" aria-hidden />
    </ToolbarButton>
    <div id={id} hidden={!open} role="group" aria-label="Saved views" className="absolute right-0 top-full z-popover mt-1.5 w-80 rounded-md border border-border bg-popover p-3 text-popover-foreground shadow-elev-popover">
      {children}
    </div>
  </div>;
}
