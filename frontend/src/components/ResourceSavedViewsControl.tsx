import { useLocation, useNavigate } from "@tanstack/react-router";
import { useSavedViews } from "@/hooks/useSavedViews";
import { useRouteSearchParams } from "@/lib/route-search";
import {
  applyResourceView,
  captureResourceView,
  resourceViewHref,
  resourceViewKey,
  resourceViewLabel,
  resourceViewSummary,
  resourceViewValidator,
  resourceFilterEntries,
  type ResourceSavedView,
  type ResourceViewKind,
} from "@/lib/resource-saved-views";
import { SavedViewsMenu } from "@/components/SavedViewsMenu";
import { Button } from "@/components/ui/button";

export function ResourceSavedViewsControl({
  inventory,
  clusterId,
  ready,
  overrides = {},
}: {
  inventory: ResourceViewKind;
  clusterId?: string;
  ready: boolean;
  overrides?: Record<string, string>;
}) {
  const [params, setParams] = useRouteSearchParams();
  const navigate = useNavigate();
  const hash = useLocation({ select: (location) => location.hash });
  const { views, deleteView, persistenceError, canPersist } =
    useSavedViews<ResourceSavedView>(resourceViewKey(inventory), {
      validate: resourceViewValidator(inventory),
    });
  const payload = captureResourceView(inventory, params, overrides);
  const formParams = new URLSearchParams(params);
  for (const [key, value] of Object.entries(overrides))
    formParams.set(key, value);
  return (
    <div
      className="space-y-2"
      data-testid={`${inventory}-saved-views-controls`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <SavedViewsMenu
          views={views}
          onApply={(view) =>
            setParams((current) => applyResourceView(current, view))
          }
          onDelete={deleteView}
          summary={resourceViewSummary}
          testId={`${inventory}-saved-views-menu`}
        />
        <Button
          size="sm"
          variant="outline"
          disabled={!ready || !payload || !canPersist}
          onClick={() =>
            void navigate({
              href: resourceViewHref(
                inventory,
                clusterId,
                formParams,
                hash,
                true,
              ),
            })
          }
        >
          Save {resourceViewLabel[inventory]} view
        </Button>
      </div>
      {payload && (
        <div
          className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground"
          aria-label="Active inventory filters"
        >
          {resourceFilterEntries(payload).map(([key, value]) => (
            <span key={key} className="max-w-full break-all">
              <span className="font-medium text-foreground">{key}:</span>{" "}
              {value}
            </span>
          ))}
        </div>
      )}
      {persistenceError && (
        <p role="alert" className="text-xs text-destructive">
          {persistenceError}
        </p>
      )}
    </div>
  );
}
