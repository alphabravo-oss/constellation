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
      className="flex shrink-0 items-center gap-2"
      data-testid={`${inventory}-saved-views-controls`}
    >
      <div className="flex items-center gap-2">
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
          variant="ghost"
          aria-label={`Save ${resourceViewLabel[inventory]} view`}
          title={payload ? resourceFilterEntries(payload).map(([key, value]) => `${key}: ${value}`).join(" · ") : undefined}
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
          Save view
        </Button>
      </div>
      {payload && (
        <div
          className="sr-only"
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
        <p role="alert" className="text-meta text-status-error">
          {persistenceError}
        </p>
      )}
    </div>
  );
}
