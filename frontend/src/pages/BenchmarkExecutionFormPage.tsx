import { useRef, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { compliance, type BenchmarkExecutionDetail } from "@/api/client";
import {
  benchmarkDetailValid,
  confirmBenchmarkKey,
  benchmarkRequestValid,
  benchmarkRetryable,
  benchmarkUUID,
  benchmarkValid,
  pendingBenchmarkKey,
} from "@/lib/benchmark-executions";
import { useRouteSearchParams } from "@/lib/route-search";
import { exportQueryReady, useExportGuard } from "@/hooks/useExportGuard";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { Field, TextInput } from "@/components/ui/form";
import { PageHeader } from "@/components/ui/page";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { useBenchmarkScope } from "./benchmark-execution-scope";

type Action = "create" | "retry";

export function BenchmarkExecutionFormPage({
  action = "create",
}: {
  action?: Action;
}) {
  const scope = useBenchmarkScope();
  const { requestId } = useParams({ strict: false });
  const [params] = useRouteSearchParams();
  const clusterID = scope.clusterId ?? "";
  const canonical = `/clusters/${encodeURIComponent(clusterID)}/compliance`;
  const supplied = params.get("return_to") ?? "";
  let returnPath = `${canonical}?tab=benchmarks`;
  try {
    const parsed = new URL(supplied, window.location.origin);
    if (
      params.getAll("return_to").length === 1 &&
      parsed.origin === window.location.origin &&
      parsed.pathname === canonical
    ) {
      parsed.searchParams.set("tab", "benchmarks");
      returnPath = parsed.pathname + parsed.search + parsed.hash;
    }
  } catch {
    /* Invalid return contexts use the canonical cluster workspace. */
  }
  return (
    <div className="space-y-6">
      <PageHeader
        title={
          action === "create" ? "Queue kube-bench" : "Retry benchmark execution"
        }
        description={
          action === "create"
            ? "Request an execution in the selected cluster."
            : "Review the current terminal execution before another attempt."
        }
        backLink={<a href={returnPath}>Back to benchmarks</a>}
      />
      {!clusterID || (action === "retry" && !benchmarkUUID(requestId)) ? (
        <ErrorState title="Select an available cluster and valid execution." />
      ) : (
        <BenchmarkExecutionEditor
          key={`${scope.owner}:${clusterID}:${action}:${requestId}`}
          action={action}
          clusterID={clusterID}
          requestID={requestId ?? ""}
          returnPath={returnPath}
        />
      )}
    </div>
  );
}

function BenchmarkExecutionEditor({
  action,
  clusterID,
  requestID,
  returnPath,
}: {
  action: Action;
  clusterID: string;
  requestID: string;
  returnPath: string;
}) {
  const scope = useBenchmarkScope();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const key = ["compliance-bench-request", scope.owner, clusterID, requestID];
  const q = useQuery({
    queryKey: key,
    queryFn: async () => {
      const result = await compliance.benchRequest(requestID, clusterID);
      if (!benchmarkDetailValid(result, clusterID, requestID))
        throw new Error("Invalid benchmark execution");
      return result;
    },
    enabled: action === "retry" && scope.ready,
    refetchOnMount: "always",
    gcTime: 0,
  });
  const current = () =>
    scope.recheck() &&
    (action === "create" || exportQueryReady(qc, key, q.data));
  const ready =
    scope.ready &&
    (action === "create" ||
      (q.isSuccess &&
        !q.isFetching &&
        q.isFetchedAfterMount &&
        benchmarkDetailValid(q.data, clusterID, requestID) &&
        current()));
  const [confirmed, setConfirmed] = useState(false);
  const [reviewed, setReviewed] = useState<BenchmarkExecutionDetail | null>(
    null,
  );
  if (ready && !confirmed) {
    setConfirmed(true);
    if (action === "retry") setReviewed(q.data!);
  }
  const [benchmark, setBenchmark] = useState("");
  const [attempted, setAttempted] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [reviewRequired, setReviewRequired] = useState(false);
  const [message, setMessage] = useState("");
  const keyRef = useRef("");
  const trimmed = benchmark.trim();
  const capture = useExportGuard(
    JSON.stringify([scope.owner, clusterID, action, requestID]),
    !ready,
    current,
  );
  const captureReview = useExportGuard(
    JSON.stringify([scope.owner, clusterID, action, requestID]),
    !scope.ready,
    scope.recheck,
  );
  const reviewedCurrent =
    action === "create" ||
    (!!reviewed && reviewed.request.revision === q.data?.request.revision);
  const valid =
    action === "create"
      ? benchmarkValid(trimmed)
      : !!reviewed && benchmarkRetryable(reviewed.request) && reviewedCurrent;
  const save = useMutation({
    retry: false,
    mutationFn: async () => {
      if (
        !ready ||
        !current() ||
        !valid ||
        reviewRequired ||
        submitted ||
        conflict
      )
        throw new Error("Unavailable execution scope");
      const guard = capture();
      let receipt;
      if (action === "create") {
        try {
          keyRef.current = pendingBenchmarkKey(scope.owner, clusterID, trimmed);
        } catch {
          setMessage(
            "The request key could not be retained in browser storage. No execution was requested. Enable session storage and try again.",
          );
          throw new Error("Request key storage unavailable");
        }
        setAttempted(true);
        setMessage("");
        receipt = await compliance.createBenchRequest(clusterID, {
          request_key: keyRef.current,
          profile: "kube-bench",
          benchmark: trimmed,
        });
      } else {
        setReviewRequired(true);
        receipt = await compliance.retryBenchRequest(
          requestID,
          clusterID,
          reviewed!.request.revision,
        );
      }
      if (!guard()) throw new Error("Execution response no longer current");
      if (
        !benchmarkRequestValid(
          receipt?.request,
          clusterID,
          action === "retry" ? requestID : undefined,
        ) ||
        (action === "create" &&
          (receipt.request.request_key !== keyRef.current ||
            receipt.request.benchmark !== trimmed ||
            receipt.request.requested_cluster_id !== clusterID)) ||
        (action === "retry" &&
          (receipt.request.status !== "queued" ||
            BigInt(receipt.request.revision) <=
              BigInt(reviewed!.request.revision)))
      )
        throw new Error("Unconfirmed execution receipt");
      setSubmitted(true);
      if (action === "create")
        confirmBenchmarkKey(scope.owner, clusterID, trimmed, keyRef.current);
      void qc.invalidateQueries({
        queryKey: ["compliance-bench-requests", scope.owner],
      });
      void qc.invalidateQueries({
        queryKey: ["compliance-bench-request", scope.owner],
      });
      const destination = new URL(returnPath, window.location.origin);
      destination.searchParams.set("bench_request", receipt.request.id);
      void navigate({
        href: destination.pathname + destination.search + destination.hash,
      });
    },
    onError: (error) => {
      const status = (error as { response?: { status?: number } }).response
        ?.status;
      if (status === 403)
        setMessage(
          "Your permissions do not allow managing benchmark executions. Read-only history remains available.",
        );
      else if (action === "create" && status === 409) {
        setConflict(true);
        setMessage(
          "This request key identifies a different execution. Review benchmark history before creating another request.",
        );
      } else if (action === "retry")
        setMessage(
          status === 409
            ? "This execution changed or cannot be retried. Refresh and review its current state."
            : "The retry could not be confirmed. Refresh and review the execution before another attempt; it may already be queued.",
        );
      else if (
        error instanceof Error &&
        error.message === "Request key storage unavailable"
      )
        setMessage(
          "The request key could not be retained in browser storage. No execution was requested. Enable session storage and try again.",
        );
      else
        setMessage(
          "The execution could not be confirmed. Your selectors and request key are preserved. Save again to reconcile the same request; this does not create a second execution.",
        );
    },
  });
  const review = useMutation({
    retry: false,
    mutationFn: async () => {
      if (!scope.recheck()) throw new Error("Unavailable cluster");
      const guard = captureReview();
      const result = await q.refetch();
      if (
        !guard() ||
        !result.isSuccess ||
        !benchmarkDetailValid(result.data, clusterID, requestID) ||
        !exportQueryReady(qc, key, result.data)
      )
        throw new Error("Review unavailable");
      setReviewed(result.data);
      setReviewRequired(false);
      setMessage("");
    },
  });
  if (!confirmed && !ready)
    return scope.loading || (scope.ready && (q.isPending || q.isFetching)) ? (
      <LoadingState label="Loading execution and cluster scope…" />
    ) : (
      <ErrorState
        title="The selected cluster or execution could not be resolved."
        action={
          <Button
            onClick={() => {
              scope.retry();
              if (scope.recheck() && action === "retry") void q.refetch();
            }}
          >
            Retry scope
          </Button>
        }
      />
    );
  return (
    <Card
      title={
        action === "create"
          ? "Execution request"
          : reviewed?.request.benchmark || "Automatic benchmark"
      }
    >
      <form
        className="space-y-5"
        onSubmit={(event) => {
          event.preventDefault();
          if (
            !save.isPending &&
            ready &&
            valid &&
            !reviewRequired &&
            !submitted &&
            !conflict
          )
            save.mutate();
        }}
      >
        {!ready && (
          <ErrorState
            title="Cluster or execution scope is unavailable or refreshing. Your draft is preserved; saving is paused."
            action={
              <Button
                type="button"
                onClick={() => {
                  scope.retry();
                  if (scope.recheck() && action === "retry") void q.refetch();
                }}
              >
                Retry scope
              </Button>
            }
          />
        )}
        {action === "create" ? (
          <>
            <p className="text-sm text-muted-foreground">
              Profile: kube-bench. A queued request does not guarantee that a
              worker is available.
            </p>
            <Collapse label="Advanced: benchmark selection">
              <Field
                label="Benchmark (optional)"
                htmlFor="bench-selector"
                hint="Leave blank for automatic selection. Up to 128 letters, numbers, dots, underscores or hyphens; begin with a letter or number."
              >
                <TextInput
                  id="bench-selector"
                  value={benchmark}
                  disabled={attempted || save.isPending}
                  onChange={(event) => setBenchmark(event.target.value)}
                />
              </Field>
              {!benchmarkValid(trimmed) && (
                <p role="alert">Enter a valid benchmark identifier.</p>
              )}
            </Collapse>
          </>
        ) : (
          <>
            <p className="text-sm">
              Reviewed execution: {reviewed?.request.status} ·{" "}
              {reviewed?.request.attempt_count} of 3 attempts used.
            </p>
            <p className="text-sm text-muted-foreground">
              Only failed or interrupted executions with fewer than three
              attempts can be retried. Report received can include failed
              controls and is not eligible for retry.
            </p>
            {!valid && (
              <ErrorState title="This reviewed execution is not eligible for retry, or its revision changed." />
            )}
            <Collapse label="Reviewed attempt metadata">
              <div className="break-all text-sm">
                Request {requestID} · revision {reviewed?.request.revision}
                <br />
                Outcome:{" "}
                {reviewed?.request.active_attempt?.outcome || "Not reported"}
                <br />
                Node: {reviewed?.request.active_attempt?.node || "Not reported"}
                <br />
                Report SHA256:{" "}
                {reviewed?.request.active_attempt?.report_sha256 ||
                  "Not reported"}
              </div>
            </Collapse>
          </>
        )}
        {message && <ErrorState title={message} />}
        {action === "retry" && (reviewRequired || !reviewedCurrent) && (
          <Button
            type="button"
            disabled={
              !scope.ready || review.isPending || save.isPending || q.isFetching
            }
            onClick={() => review.mutate()}
          >
            Refresh and review execution
          </Button>
        )}
        {review.isError && (
          <ErrorState title="The current execution could not be reviewed. Saving remains paused." />
        )}
        <div className="flex gap-3">
          <Button
            variant="primary"
            type="submit"
            disabled={
              !ready ||
              !valid ||
              reviewRequired ||
              submitted ||
              conflict ||
              save.isPending ||
              review.isPending
            }
          >
            {save.isPending ? "Saving…" : "Save"}
          </Button>
          <Button
            type="button"
            disabled={save.isPending}
            onClick={() => void navigate({ href: returnPath })}
          >
            Cancel
          </Button>
        </div>
      </form>
    </Card>
  );
}
