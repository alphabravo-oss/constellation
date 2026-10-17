import { useRef, useState } from "react";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { useIsFetching, useQueryClient } from "@tanstack/react-query";
import { useCluster } from "@/hooks/useCluster";
import { useSavedViews } from "@/hooks/useSavedViews";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useRouteSearchParams } from "@/lib/route-search";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import {
  captureResourceView,
  resourceViewHref,
  resourceViewKey,
  resourceViewLabel,
  resourceViewValidator,
  type ResourceSavedView,
  type ResourceViewKind,
} from "@/lib/resource-saved-views";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { Field, TextInput } from "@/components/ui/form";
import { PageHeader } from "@/components/ui/page";
import { ErrorState, LoadingState } from "@/components/ui/states";

export function AssetSavedViewFormPage() {
  return <ResourceSavedViewForm inventory="assets" />;
}
export function DeploymentSavedViewFormPage() {
  return <ResourceSavedViewForm inventory="deployments" />;
}
export function RuntimeSavedViewFormPage() {
  return <ResourceSavedViewForm inventory="runtime" />;
}
export function ScannerSavedViewFormPage() {
  return <ResourceSavedViewForm inventory="scanner" />;
}
function ResourceSavedViewForm({ inventory }: { inventory: ResourceViewKind }) {
  const scope = useCluster();
  const identity = useTablePreferencesIdentity();
  const [params] = useRouteSearchParams();
  const hash = useLocation({ select: (location) => location.hash });
  const client = useQueryClient();
  const fetching =
    useIsFetching({ queryKey: ["clusters"], exact: true }) +
    useIsFetching({ queryKey: ["cluster", scope.clusterId], exact: true });
  const ownerReady = !!identity?.org_id.trim() && !!identity.user_id.trim();
  const clusterReady =
    !!scope.clusterId &&
    scope.cluster?.id === scope.clusterId &&
    !scope.isLoading &&
    !scope.error &&
    !fetching &&
    clusterCacheReady(client, scope.clusterId);
  const ready = ownerReady && (inventory === "scanner" || clusterReady);
  const confirmationKey = `${identity?.org_id}:${identity?.user_id}:${inventory === "scanner" ? "organization" : scope.clusterId}:${inventory}`;
  const [confirmed, setConfirmed] = useState("");
  if (ready && confirmed !== confirmationKey) setConfirmed(confirmationKey);
  const payload = captureResourceView(inventory, params);
  const returnHref = resourceViewHref(inventory, scope.clusterId, params, hash);
  const title = `Save ${resourceViewLabel[inventory]} view`;
  return (
    <div className="space-y-6" data-testid="resource-saved-view-form-page">
      <PageHeader
        title={title}
        description="Name this filter configuration for your organization and user in this browser."
        backLink={<a href={returnHref}>Back to inventory</a>}
      />
      {!ownerReady ? (
        <ErrorState title="An available organization and user session are required to save a view." />
      ) : !ready && confirmed !== confirmationKey ? (
        scope.isLoading || fetching ? (
          <LoadingState label="Loading cluster…" />
        ) : (
          <ErrorState title="The selected cluster could not be resolved." />
        )
      ) : !payload ? (
        <ErrorState title="The current inventory filters are invalid. Return and correct them before saving." />
      ) : (
        <>
          {!ready && (
            <ErrorState title="Cluster scope is unavailable or refreshing. Your draft is preserved; saving is paused." />
          )}
          <ResourceViewEditor
            key={`${confirmationKey}:${JSON.stringify(payload)}`}
            payload={payload}
            returnHref={returnHref}
            ready={ready}
            recheck={() =>
              ready &&
              (inventory === "scanner" ||
                (!!scope.clusterId &&
                  clusterCacheReady(client, scope.clusterId)))
            }
          />
        </>
      )}
    </div>
  );
}
function ResourceViewEditor({
  payload,
  returnHref,
  ready,
  recheck,
}: {
  payload: Omit<ResourceSavedView, "id" | "name">;
  returnHref: string;
  ready: boolean;
  recheck: () => boolean;
}) {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const writing = useRef(false);
  const [saved, setSaved] = useState(false);
  const { saveView, persistenceError, canPersist } =
    useSavedViews<ResourceSavedView>(resourceViewKey(payload.inventory), {
      validate: resourceViewValidator(payload.inventory),
    });
  const valid = !!name.trim() && name.trim().length <= 120;
  return (
    <Card
      title="Saved view"
      description="Filters are saved. Page, selection and navigation context are preserved for the return trip."
    >
      <form
        className="space-y-6"
        onSubmit={(event) => {
          event.preventDefault();
          if (!valid || !ready || !canPersist || writing.current || !recheck())
            return;
          const result = saveView(name, payload);
          if (result.ok) {
            writing.current = true;
            setSaved(true);
            void navigate({ href: returnHref });
          }
        }}
      >
        <Field
          label="View name"
          htmlFor="resource-view-name"
          required
          hint="Use 1 to 120 characters."
        >
          <TextInput
            id="resource-view-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            autoFocus
            required
            maxLength={120}
          />
        </Field>
        <Collapse label="Advanced: captured filters">
          <pre
            className="overflow-auto rounded-md bg-muted p-3 text-xs"
            data-testid="resource-saved-view-payload"
          >
            {JSON.stringify(payload.filters, null, 2)}
          </pre>
        </Collapse>
        {persistenceError && <ErrorState title={persistenceError} />}
        <div className="flex gap-3">
          <Button
            type="submit"
            variant="primary"
            size="lg"
            disabled={!valid || !ready || !canPersist || saved}
          >
            {saved ? "Saved" : "Save"}
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="lg"
            onClick={() => void navigate({ href: returnHref })}
          >
            Cancel
          </Button>
        </div>
      </form>
    </Card>
  );
}
