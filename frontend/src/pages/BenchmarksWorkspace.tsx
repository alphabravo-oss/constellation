import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useLocation, useNavigate } from "@tanstack/react-router";
import {
  compliance,
  type BenchmarkExecutionAttempt,
  type BenchmarkExecutionRequest,
} from "@/api/client";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useRouteSearchParams } from "@/lib/route-search";
import {
  benchmarkDetailValid,
  benchmarkPageValid,
  benchmarkRetryable,
  benchmarkUUID,
} from "@/lib/benchmark-executions";
import { exportQueryReady, useExportGuard } from "@/hooks/useExportGuard";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Pager } from "@/components/ui/pager";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { useBenchmarkScope } from "./benchmark-execution-scope";

export function BenchmarksWorkspace({ active }: { active: boolean }) {
  const scope = useBenchmarkScope();
  const identity = useTablePreferencesIdentity();
  const owner = `${identity?.org_id}:${identity?.user_id}`;
  const enabled =
    active && scope.ready && !!identity?.org_id && !!identity?.user_id;
  const clusterID = scope.clusterId ?? "";
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [params, setParams] = useRouteSearchParams();
  const hash = useLocation({ select: (location) => location.hash });
  const pageRaw = params.get("bench_page") ?? "1";
  const pageValid =
    params.getAll("bench_page").length <= 1 &&
    /^[1-9]\d*$/.test(pageRaw) &&
    Number.isSafeInteger(Number(pageRaw)) &&
    (Number(pageRaw) - 1) * 100 <= 2147483647;
  const page = pageValid ? Number(pageRaw) - 1 : 0;
  const selected = params.get("bench_request") ?? "";
  const selectionValid =
    params.getAll("bench_request").length <= 1 &&
    (!selected || benchmarkUUID(selected));
  const key = ["compliance-bench-requests", owner, clusterID, page];
  const q = useQuery({
    queryKey: key,
    queryFn: async () => {
      const result = await compliance.benchRequests({
        cluster_id: clusterID,
        limit: 100,
        offset: page * 100,
      });
      if (!benchmarkPageValid(result, clusterID, page * 100))
        throw new Error("Invalid benchmark inventory");
      return result;
    },
    enabled: enabled && pageValid,
    refetchOnMount: "always",
    refetchInterval: active ? 15000 : false,
  });
  const current = () =>
    enabled && scope.recheck() && exportQueryReady(qc, key, q.data);
  const ready =
    enabled &&
    q.isSuccess &&
    q.isFetchedAfterMount &&
    benchmarkPageValid(q.data, clusterID, page * 100);
  const fresh = ready && !q.isFetching && current();
  const capture = useExportGuard(
    JSON.stringify([owner, clusterID, page]),
    !fresh,
    current,
  );
  const context = `/clusters/${encodeURIComponent(clusterID)}/compliance?${params}`;
  const createHref = `/clusters/${encodeURIComponent(clusterID)}/compliance/benchmarks/new?return_to=${encodeURIComponent(context + (hash ? `#${hash}` : ""))}`;
  const columns: Column<BenchmarkExecutionRequest>[] = [
    {
      id: "benchmark",
      header: "Benchmark",
      kind: "name",
      minSize: 220,
      grow: true,
      wrap: true,
      cell: (row) => row.benchmark || "Automatic benchmark",
      exportValue: (row) => row.benchmark || "Automatic",
    },
    {
      id: "status",
      header: "Execution",
      kind: "status",
      minSize: 160,
      cell: (row) =>
        row.status === "succeeded" ? "Report received" : row.status,
      exportValue: (row) => row.status,
    },
    {
      id: "cluster",
      header: "Assignment",
      kind: "text",
      wrap: true,
      cell: (row) =>
        row.cluster_id ? "Selected cluster" : "Unassigned organization request",
      exportValue: (row) => row.cluster_id || "Unassigned",
    },
    {
      id: "attempts",
      header: "Attempts",
      kind: "count",
      cell: (row) => `${row.attempt_count} / 3`,
      exportValue: (row) => row.attempt_count,
    },
    {
      id: "requested",
      header: "Requested",
      kind: "date",
      cell: (row) => new Date(row.requested_at).toLocaleString(),
      exportValue: (row) => row.requested_at,
    },
    {
      id: "inspect",
      header: "Manage",
      kind: "actions",
      cell: (row) => (
        <Button
          disabled={!fresh}
          onClick={() => {
            if (current())
              setParams((old) => {
                old.set("bench_request", row.id);
                return old;
              });
          }}
        >
          Inspect
        </Button>
      ),
    },
  ];
  if (!active) return null;
  return (
    <section className="space-y-4" data-testid="benchmarks-workspace">
      <div className="flex flex-wrap items-center gap-3">
        <Button
          variant="primary"
          disabled={!enabled}
          onClick={() => {
            if (enabled && scope.recheck()) void navigate({ href: createHref });
          }}
        >
          Queue kube-bench
        </Button>
        <Button
          disabled={!enabled || q.isFetching}
          onClick={() => {
            if (enabled && scope.recheck()) void q.refetch();
          }}
        >
          Refresh executions
        </Button>
      </div>
      <Collapse label="Execution details">
        <p className="text-sm text-muted-foreground">
          Durable requests and up to three attempts per request. Queued requests
          do not prove a worker is available. Report received means a valid
          report was ingested; its controls may fail. A worker's node
          attribution is not fleet coverage. Scheduled reports are a separate
          history. The selected cluster also shows unassigned organization
          requests.
        </p>
      </Collapse>
      {!enabled ? (
        <ErrorState
          title="Resolve the selected cluster and operator before loading executions."
          action={<Button onClick={scope.retry}>Retry cluster</Button>}
        />
      ) : !pageValid ? (
        <ErrorState
          title="Choose a valid execution page."
          action={
            <Button
              onClick={() =>
                setParams((old) => {
                  old.delete("bench_page");
                  return old;
                })
              }
            >
              First execution page
            </Button>
          }
        />
      ) : q.isError ? (
        <ErrorState
          title="Benchmark executions could not be loaded or refreshed."
          action={
            <Button
              onClick={() => {
                if (scope.recheck()) void q.refetch();
              }}
            >
              Retry executions
            </Button>
          }
        />
      ) : !ready ? (
        <LoadingState label="Loading benchmark executions…" />
      ) : (
        <>
          {q.isFetching && (
            <p role="status" className="text-sm text-muted-foreground">
              Refreshing executions…
            </p>
          )}
          <p className="text-sm text-muted-foreground">
            {q.data!.total.toLocaleString()} durable requests · newest first.
            CSV contains this page only.
          </p>
          <DataTable
            rows={q.data!.requests}
            columns={columns}
            rowKey={(row) => row.id}
            pagination={false}
            preferencesKey="compliance-bench-executions"
            exportFileName="benchmark-executions-page.csv"
            exportLabel="Export page CSV"
            canExport={capture()}
            emptyState={<EmptyState title="No benchmark executions" />}
            testId="benchmarks-table"
          />
          {page > 0 && q.data!.requests.length === 0 && (
            <Button
              onClick={() =>
                setParams((old) => {
                  old.delete("bench_page");
                  return old;
                })
              }
            >
              First execution page
            </Button>
          )}
          <Pager
            page={page}
            pageSize={100}
            rowsOnPage={q.data!.requests.length}
            total={q.data!.total}
            onPage={(next) =>
              setParams((old) => {
                old.set("bench_page", String(next + 1));
                old.delete("bench_request");
                return old;
              })
            }
          />
        </>
      )}
      {!selectionValid ? (
        <ErrorState
          title="Choose one valid benchmark execution."
          action={
            <Button
              onClick={() =>
                setParams((old) => {
                  old.delete("bench_request");
                  return old;
                })
              }
            >
              Clear execution selection
            </Button>
          }
        />
      ) : (
        selected && (
          <BenchmarkExecutionDetails
            key={`${owner}:${clusterID}:${selected}`}
            id={selected}
            clusterID={clusterID}
            enabled={enabled}
            returnPath={context + (hash ? `#${hash}` : "")}
          />
        )
      )}
    </section>
  );
}

export function BenchmarkExecutionDetails({
  id,
  clusterID,
  enabled,
  returnPath,
}: {
  id: string;
  clusterID: string;
  enabled: boolean;
  returnPath: string;
}) {
  const identity = useTablePreferencesIdentity();
  const scope = useBenchmarkScope();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const key = [
    "compliance-bench-request",
    `${identity?.org_id}:${identity?.user_id}`,
    clusterID,
    id,
  ];
  const q = useQuery({
    queryKey: key,
    queryFn: async () => {
      const result = await compliance.benchRequest(id, clusterID);
      if (!benchmarkDetailValid(result, clusterID, id))
        throw new Error("Invalid benchmark detail");
      return result;
    },
    enabled,
    refetchOnMount: "always",
    refetchInterval: enabled ? 15000 : false,
  });
  const fresh = () =>
    enabled && scope.recheck() && exportQueryReady(qc, key, q.data);
  const capture = useExportGuard(
    JSON.stringify(key),
    !enabled || !q.isSuccess || q.isFetching || !q.isFetchedAfterMount,
    fresh,
  );
  if (!enabled) return null;
  if (q.isError)
    return (
      <ErrorState
        title="The selected execution could not be loaded or refreshed."
        action={
          <Button
            onClick={() => {
              if (scope.recheck()) void q.refetch();
            }}
          >
            Retry execution
          </Button>
        }
      />
    );
  if (
    !q.isSuccess ||
    !q.isFetchedAfterMount ||
    !benchmarkDetailValid(q.data, clusterID, id)
  )
    return <LoadingState label="Loading execution attempts…" />;
  const request = q.data.request;
  const attemptColumns: Column<BenchmarkExecutionAttempt>[] = [
    {
      id: "number",
      header: "Attempt",
      kind: "count",
      cell: (row) => row.number,
    },
    {
      id: "status",
      header: "Execution",
      kind: "status",
      cell: (row) =>
        row.status === "succeeded" ? "Report received" : row.status,
    },
    {
      id: "node",
      header: "Worker node",
      kind: "name",
      wrap: true,
      grow: true,
      cell: (row) => row.node || "Not reported",
    },
    {
      id: "outcome",
      header: "Outcome",
      kind: "text",
      wrap: true,
      cell: (row) => row.outcome || "Not reported",
    },
    {
      id: "total",
      header: "Controls",
      kind: "count",
      cell: (row) => row.controls.total,
    },
    {
      id: "fail",
      header: "Failed controls",
      kind: "count",
      cell: (row) => row.controls.fail,
    },
    {
      id: "started",
      header: "Started",
      kind: "date",
      cell: (row) => new Date(row.started_at).toLocaleString(),
      exportValue: (row) => row.started_at,
    },
  ];
  return (
    <Card
      title="Execution attempts"
      description={`${request.benchmark || "Automatic benchmark"} · ${request.status === "succeeded" ? "Report received" : request.status}`}
    >
      <div className="space-y-4">
        {q.isFetching && <p role="status">Refreshing execution…</p>}
        {benchmarkRetryable(request) && (
          <Button
            disabled={!fresh()}
            onClick={() => {
              if (fresh())
                void navigate({
                  href: `/clusters/${encodeURIComponent(clusterID)}/compliance/benchmarks/${id}/retry?return_to=${encodeURIComponent(returnPath)}`,
                });
            }}
          >
            Review retry
          </Button>
        )}
        <DataTable
          rows={q.data.attempts}
          columns={attemptColumns}
          rowKey={(row) => row.id}
          preferencesKey="compliance-bench-attempts"
          exportFileName="benchmark-execution-attempts.csv"
          exportLabel="Export attempts CSV"
          canExport={capture()}
          pagination={false}
          emptyState={
            <EmptyState title="No attempt has claimed this request" />
          }
        />
        <Collapse label="Request and report metadata">
          <dl className="space-y-2 break-all text-sm">
            <dt>Request ID</dt>
            <dd>{request.id}</dd>
            <dt>Request key</dt>
            <dd>{request.request_key}</dd>
            <dt>Revision</dt>
            <dd>{request.revision}</dd>
            {q.data.attempts.map((attempt) => (
              <div key={attempt.id}>
                <dt>Attempt {attempt.number}</dt>
                <dd>
                  {attempt.id} · runner {attempt.runner_id} · claim{" "}
                  {attempt.claim_key}
                </dd>
                <dt>Report SHA256</dt>
                <dd>{attempt.report_sha256 || "No report digest"}</dd>
                <dt>Controls</dt>
                <dd>
                  {attempt.controls.pass} pass · {attempt.controls.fail} fail ·{" "}
                  {attempt.controls.manual} manual ·{" "}
                  {attempt.controls.not_applicable} not applicable ·{" "}
                  {attempt.rows_ingested} evidence rows ingested
                </dd>
              </div>
            ))}
          </dl>
        </Collapse>
      </div>
    </Card>
  );
}
