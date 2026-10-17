import { useQueryClient } from "@tanstack/react-query";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useEntityClusterScope } from "./entity-detail-scope";

export function useBenchmarkScope() {
  const scope = useEntityClusterScope();
  const qc = useQueryClient();
  const identity = useTablePreferencesIdentity();
  const recheck = () =>
    !!identity?.org_id &&
    !!identity?.user_id &&
    scope.recheck() &&
    !qc.getQueryState(["clusters"])?.isInvalidated &&
    !qc.getQueryState(["cluster", scope.clusterId])?.isInvalidated;
  return {
    ...scope,
    owner: `${identity?.org_id}:${identity?.user_id}`,
    ready: scope.ready && recheck(),
    recheck,
  };
}
