import { useEffect, useRef, useState } from "react";
import {
  useIsFetching,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { policies } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useRouteSearchParams } from "@/lib/route-search";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { Checkbox } from "@/components/ui/form";
import { networkReturn } from "./network-secondary";
type Settings = Awaited<ReturnType<typeof policies.dpiThreatSettings>>;
export function NetworkDpiSettingsFormPage() {
  const scope = useCluster();
  return <DpiSettingsScope key={scope.clusterId} scope={scope} />;
}
function DpiSettingsScope({ scope }: { scope: ReturnType<typeof useCluster> }) {
  const [params] = useRouteSearchParams();
  const qc = useQueryClient();
  const id = scope.clusterId;
  const registry = useIsFetching({ queryKey: ["clusters"], exact: true });
  const clusterFetch = useIsFetching({
    queryKey: ["cluster", id],
    exact: true,
  });
  const resolved =
    !!id &&
    scope.cluster?.id === id &&
    !scope.isLoading &&
    !scope.error &&
    !registry &&
    !clusterFetch &&
    clusterCacheReady(qc, id);
  const key = ["dpi-threat-settings", id];
  const q = useQuery({
    queryKey: key,
    enabled: resolved,
    queryFn: () => policies.dpiThreatSettings({ cluster_id: id! }),
  });
  const ready =
    resolved &&
    q.isSuccess &&
    !q.isFetching &&
    !q.isError &&
    q.data?.cluster_id === id &&
    typeof q.data.weak_tls_enabled === "boolean";
  const [initial, setInitial] = useState<Settings>();
  const [enabled, setEnabled] = useState(false);
  const [ack, setAck] = useState(false);
  const [result, setResult] = useState("");
  const [uncertain, setUncertain] = useState(false);
  useEffect(() => {
    if (ready && !initial) {
      setInitial(q.data);
      setEnabled(q.data!.weak_tls_enabled);
    }
  }, [ready, q.data, initial]);
  const active = useRef(true);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  const lock = useRef(false);
  const unknown = useRef(false);
  const owner = useRef(resolved);
  owner.current = resolved;
  const changed =
    !!initial && q.data?.weak_tls_enabled !== initial.weak_tls_enabled;
  const disabling = !!initial?.weak_tls_enabled && !enabled;
  const valid =
    ready &&
    !changed &&
    !!initial &&
    enabled !== initial.weak_tls_enabled &&
    (!disabling || ack) &&
    !uncertain &&
    !result;
  const current = () => {
    const state = qc.getQueryState<Settings>(key);
    if (
      !active.current ||
      !owner.current ||
      !id ||
      !clusterCacheReady(qc, id) ||
      state?.status !== "success" ||
      state.fetchStatus !== "idle" ||
      state.isInvalidated ||
      state.data?.cluster_id !== id ||
      typeof state.data.weak_tls_enabled !== "boolean" ||
      state.data.weak_tls_enabled !== initial?.weak_tls_enabled
    )
      throw new Error(
        "Refresh and review this exact cluster setting before saving. Your draft is preserved.",
      );
  };
  const save = useMutation({
    mutationFn: async () => {
      if (!valid || unknown.current)
        throw new Error(
          "Review the setting and acknowledge any evidence removal.",
        );
      current();
      const response = await policies.dpiThreatSettings({ cluster_id: id! });
      current();
      if (
        response.cluster_id !== id ||
        response.weak_tls_enabled !== initial!.weak_tls_enabled
      ) {
        qc.setQueryData(key, response);
        throw new Error(
          "The configured setting changed. Your draft is preserved; review the current state.",
        );
      }
      const updated = await policies.updateDpiThreatSettings(
        {
          weak_tls_enabled: enabled,
          expected_weak_tls_enabled: initial!.weak_tls_enabled,
        },
        { cluster_id: id! },
      );
      if (updated?.cluster_id !== id || updated.weak_tls_enabled !== enabled) {
        unknown.current = true;
        if (active.current) setUncertain(true);
        throw new Error(
          "The response did not confirm this cluster setting. Inspect configured state before submitting another change.",
        );
      }
      return `Weak-TLS detection configured ${enabled ? "on" : "off"}. Agent adoption and enforcement have not been confirmed.`;
    },
    onSuccess: (message) => {
      void qc.invalidateQueries({ queryKey: ["dpi-threat-settings"] });
      void qc.invalidateQueries({ queryKey: ["runtime-threats"] });
      void qc.invalidateQueries({ queryKey: ["network-map"] });
      if (active.current && owner.current && id && clusterCacheReady(qc, id))
        setResult(message);
    },
  });
  const retry = () =>
    resolved
      ? void q.refetch()
      : void qc.invalidateQueries({ queryKey: ["clusters"] });
  const back = id ? networkReturn(id, params) : "/clusters";
  return (
    <div className="space-y-5" data-testid="network-dpi-settings-page">
      <PageHeader
        title="Weak-TLS detection settings"
        description="Review the configured signature setting for this cluster before saving. Detection and blocking are separate."
        backLink={<a href={back}>Back to Network</a>}
      />
      {!initial ? (
        !resolved ? (
          scope.error ? (
            <ErrorState
              title="Could not resolve this cluster."
              action={<Button onClick={retry}>Retry</Button>}
            />
          ) : (
            <LoadingState label="Resolving cluster…" />
          )
        ) : q.isPending ? (
          <LoadingState label="Loading configured detection setting…" />
        ) : (
          <ErrorState
            title="Could not load the exact cluster setting."
            error={q.error}
            action={<Button onClick={retry}>Retry</Button>}
          />
        )
      ) : (
        <Card
          title="Configured detection"
          description={`Cluster ${id}. Saving records configuration; it does not acknowledge agent adoption.`}
        >
          <form
            className="space-y-5"
            onSubmit={async (e) => {
              e.preventDefault();
              if (lock.current || unknown.current || !valid) return;
              lock.current = true;
              try {
                await save.mutateAsync();
              } catch {
                /* Draft and error remain visible. */
              } finally {
                lock.current = false;
              }
            }}
          >
            {(!ready || changed) && !result && (
              <ErrorState
                title="Configured state is unavailable or changed. Your draft is preserved."
                action={
                  <>
                    <Button type="button" onClick={retry}>
                      Retry
                    </Button>
                    {ready && q.data && (
                      <Button
                        type="button"
                        onClick={() => {
                          setInitial(q.data);
                          setAck(false);
                        }}
                      >
                        Review current state
                      </Button>
                    )}
                  </>
                }
              />
            )}
            <label className="flex items-center gap-3 text-sm">
              <Checkbox
                checked={enabled}
                disabled={save.isPending || !!result}
                onChange={(e) => {
                  setEnabled(e.target.checked);
                  setAck(false);
                }}
              />{" "}
              Detect SSLv3 / TLS 1.0 / TLS 1.1 signatures
            </label>
            {disabling && (
              <div className="space-y-3 rounded border border-status-warning p-4 text-sm">
                <p role="alert">
                  Disabling removes stored weak-TLS threat evidence for this
                  cluster (signature IDs 2011, 2012, and 2027) and clears
                  related references in raw flows and flow rollups.
                </p>
                <label className="flex items-start gap-3">
                  <Checkbox
                    checked={ack}
                    disabled={save.isPending || !!result}
                    onChange={(e) => setAck(e.target.checked)}
                  />{" "}
                  I understand that existing weak-TLS evidence will be removed.
                </label>
              </div>
            )}
            <Collapse label="Advanced: detection and source limitations">
              <p className="text-sm text-muted-foreground">
                Passive capture can expose the legacy TLS record version and
                produce false positives on modern HTTPS. Agent polling applies
                configured settings asynchronously. This API supplies no agent
                acknowledgment or enforcement status.
              </p>
            </Collapse>
            {save.isError && (
              <ErrorState
                title="Could not confirm the settings change."
                error={save.error}
              />
            )}{" "}
            {uncertain && (
              <p role="alert">Inspect configured state before saving again.</p>
            )}
            {result && (
              <p role="status" data-testid="network-dpi-result">
                {result}
              </p>
            )}
            <div className="flex flex-wrap justify-end gap-3 border-t border-border pt-5">
              <a
                href={back}
                className="rounded border border-border px-3 py-2 text-sm"
              >
                {result ? "Back to Network" : "Cancel"}
              </a>
              <Button type="submit" disabled={!valid || save.isPending}>
                {save.isPending ? "Saving…" : "Save"}
              </Button>
            </div>
          </form>
        </Card>
      )}
    </div>
  );
}
