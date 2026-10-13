import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useRouteSearchParams } from "@/lib/route-search";
import { ArrowLeft } from "lucide-react";

import { networkRules, type NetworkRuleInventoryRow } from "@/api/client";
import { exportQueryReady, useExportGuard } from "@/hooks/useExportGuard";
import {
  useNetworkRuleScope,
  networkRuleInventoryMatches,
  networkRuleFingerprint,
  networkRuleReturnHref,
} from "./network-rule-inventory";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Select } from "@/components/ui/form";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { GroupPicker } from "@/components/GroupPicker";

export function NetworkRuleFormPage() {
  const scope = useNetworkRuleScope();
  const clusterId = scope.clusterId ?? "";
  const { ruleId } = useParams({ strict: false });
  const [params] = useRouteSearchParams();
  const from = params.get("from")?.trim() ?? "",
    to = params.get("to")?.trim() ?? "";
  const editing = !!ruleId || params.has("from") || params.has("to");
  const exact =
    !editing ||
    (!!from &&
      !!to &&
      params.getAll("from").length === 1 &&
      params.getAll("to").length === 1);
  const listPath = networkRuleReturnHref(clusterId, params.get("return_to"));
  const request = {
    from,
    to,
    limit: 1,
    offset: 0,
    sort: "evaluation",
    order: "asc" as const,
  };
  const key = ["network-rule-editor", scope.owner, clusterId, ruleId, request];
  const context = JSON.stringify([scope.owner, clusterId, ruleId, from, to]);
  const q = useQuery({
    queryKey: key,
    queryFn: async () => {
      const data = await networkRules.inventory(clusterId, request);
      if (
        !networkRuleInventoryMatches(data, clusterId, request) ||
        data.total !== 1 ||
        (ruleId && String(data.rules[0]?.id) !== ruleId)
      )
        throw new Error("Rule identity unavailable");
      return data;
    },
    enabled: scope.ready && editing && exact,
    gcTime: 0,
  });
  const ready =
    scope.ready &&
    exact &&
    (!editing ||
      (q.isSuccess &&
        !q.isFetching &&
        exportQueryReady(scope.client, key) &&
        networkRuleInventoryMatches(q.data, clusterId, request) &&
        q.data.total === 1 &&
        (!ruleId || String(q.data.rules[0]?.id) === ruleId)));
  const [loadedContext, setLoadedContext] = useState<string | null>(null);
  if (ready && loadedContext !== context) setLoadedContext(context);
  const [snapshot, setSnapshot] = useState<{
    context: string;
    row: NetworkRuleInventoryRow;
  } | null>(null);
  if (editing && ready && snapshot?.context !== context)
    setSnapshot({ context, row: q.data!.rules[0] });
  const initial = snapshot?.context === context ? snapshot.row : undefined;
  const recheck = () =>
    scope.recheck() &&
    ready &&
    (!editing || exportQueryReady(scope.client, key, q.data));
  const refresh = async () => {
    if (!scope.recheck()) {
      scope.retry();
      return undefined;
    }
    const result = await q.refetch();
    return scope.recheck() &&
      result.isSuccess &&
      networkRuleInventoryMatches(result.data, clusterId, request) &&
      result.data.total === 1 &&
      (!ruleId || String(result.data.rules[0].id) === ruleId)
      ? result.data.rules[0]
      : undefined;
  };
  return (
    <div className="space-y-6">
      <PageHeader
        title={editing ? "Edit network rule" : "Add network rule"}
        description="Control traffic between two workloads with an allow or deny rule."
        backLink={
          <a
            href={listPath}
            className="inline-flex items-center gap-1 hover:text-foreground"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> Network Rules
          </a>
        }
      />
      {!exact ? (
        <ErrorState
          title="Select the exact source and destination to edit this rule."
          action={<a href={listPath}>Choose a rule</a>}
        />
      ) : !scope.ready && loadedContext !== context ? (
        <ErrorState
          title="Resolve the selected cluster and operator to author network rules."
          action={<Button onClick={scope.retry}>Retry cluster</Button>}
        />
      ) : editing && !initial ? (
        q.isPending || q.isFetching ? (
          <LoadingState label="Loading network rule…" />
        ) : (
          <ErrorState
            title="This network rule could not be loaded for the selected cluster."
            action={<Button onClick={() => void q.refetch()}>Retry</Button>}
          />
        )
      ) : (
        <NetworkRuleEditor
          key={context}
          clusterId={clusterId}
          initial={initial}
          latest={ready ? q.data?.rules[0] : undefined}
          listPath={listPath}
          context={context}
          owner={scope.owner}
          unavailable={!ready}
          recheck={recheck}
          refresh={refresh}
          retryScope={scope.retry}
        />
      )}
    </div>
  );
}

function NetworkRuleEditor({
  clusterId,
  initial,
  latest,
  listPath,
  context,
  owner,
  unavailable,
  recheck,
  refresh,
  retryScope,
}: {
  clusterId: string;
  initial?: NetworkRuleInventoryRow;
  latest?: NetworkRuleInventoryRow;
  listPath: string;
  context: string;
  owner: string;
  unavailable: boolean;
  recheck: () => boolean;
  refresh: () => Promise<NetworkRuleInventoryRow | undefined>;
  retryScope: () => void;
}) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const editing = !!initial;
  const [from, setFrom] = useState(initial?.from ?? "");
  const [to, setTo] = useState(initial?.to ?? "");
  const [ports, setPorts] = useState(initial?.ports ?? "any");
  const [apps, setApps] = useState(initial?.applications.join(", ") ?? "");
  const [action, setAction] = useState<"allow" | "deny">(
    initial?.action ?? "allow",
  );
  const [comment, setComment] = useState(initial?.comment ?? "");
  const [disable, setDisable] = useState(initial?.disable ?? false);
  const [priority, setPriority] = useState(String(initial?.priority ?? 1000));
  const valid =
    !!from.trim() &&
    !!to.trim() &&
    /^-?\d+$/.test(priority) &&
    Number(priority) >= -2147483648 &&
    Number(priority) <= 2147483647;

  const [reviewed, setReviewed] = useState(initial);
  const [uncertain, setUncertain] = useState(false);
  const changed =
    editing &&
    (!latest ||
      !reviewed ||
      networkRuleFingerprint(latest) !== networkRuleFingerprint(reviewed));
  const blocked = unavailable || changed || uncertain;
  const captureCurrent = useExportGuard(
    JSON.stringify([context, reviewed && networkRuleFingerprint(reviewed)]),
    blocked,
    recheck,
  );
  const captureContext = useExportGuard(context, false);
  const review = useMutation({
    mutationFn: async () => {
      const current = captureContext(),
        row = await refresh();
      if (!current() || !row) throw new Error("Rule review unavailable");
      return row;
    },
    onSuccess: (row) => setReviewed(row),
  });
  const save = useMutation({
    mutationFn: async () => {
      if (blocked || !recheck()) throw new Error("Refresh rule scope first");
      const current = captureCurrent();
      const saved = await networkRules.upsert(clusterId, {
        from: from.trim(),
        to: to.trim(),
        ports: ports.trim() || "any",
        applications: apps
          .split(",")
          .map((app) => app.trim())
          .filter(Boolean),
        action,
        comment: comment.trim(),
        disable,
        priority: Number(priority),
      });
      if (
        !current() ||
        saved?.ok !== true ||
        !Number.isSafeInteger(saved.id) ||
        (editing && saved.id !== initial!.id) ||
        !["user_created", "learned_override"].includes(saved.cfg_type)
      ) {
        setUncertain(true);
        throw new Error("Save could not be confirmed");
      }
      void qc.invalidateQueries({
        queryKey: ["network-rules-inventory", owner, clusterId],
      });
      navigate({ href: listPath });
    },
  });

  return (
    <div className="space-y-4">
      {unavailable && (
        <ErrorState
          title="Current rule evidence is unavailable or refreshing. Your draft is preserved; saving is paused."
          action={
            <Button
              disabled={review.isPending || save.isPending}
              onClick={() => (editing ? review.mutate() : retryScope())}
            >
              {editing ? "Refresh rule" : "Retry cluster"}
            </Button>
          }
        />
      )}
      {changed && !unavailable && (
        <ErrorState
          title="The saved rule changed. Review it before applying your retained draft."
          action={
            <Button
              disabled={review.isPending || save.isPending}
              onClick={() => review.mutate()}
            >
              Review saved rule
            </Button>
          }
        />
      )}
      {review.isError && (
        <ErrorState title="The saved rule could not be reviewed. Your draft is preserved." />
      )}
      {uncertain && (
        <ErrorState title="The save could not be confirmed in this workspace. Reload before another write." />
      )}
      <Card
        title="Rule"
        description="Traffic from the source workload to the destination, restricted to these applications and ports."
      >
        <form
          className="space-y-5"
          onSubmit={(e) => {
            e.preventDefault();
            if (valid && !save.isPending && !blocked) save.mutate();
          }}
        >
          <fieldset disabled={save.isPending} className="space-y-5">
            <div className="grid gap-5 sm:grid-cols-2">
              <Field label="From (source)" htmlFor="network-rule-from" required>
                <GroupPicker
                  clusterId={clusterId}
                  value={from}
                  onChange={setFrom}
                  autoFocus
                  required
                  disabled={editing}
                  placeholder="prod/frontend or external"
                  inputId="network-rule-from"
                  testId="network-rule-from-group"
                />
              </Field>
              <Field
                label="To (destination)"
                htmlFor="network-rule-to"
                required
              >
                <GroupPicker
                  clusterId={clusterId}
                  value={to}
                  onChange={setTo}
                  required
                  disabled={editing}
                  placeholder="prod/api or external"
                  inputId="network-rule-to"
                  testId="network-rule-to-group"
                />
              </Field>
              <Field
                label="Applications"
                htmlFor="network-rule-applications"
                hint="Comma-separated (e.g. HTTP, gRPC). Blank = any."
              >
                <TextInput
                  id="network-rule-applications"
                  disabled={initial?.learned}
                  placeholder="HTTP, gRPC"
                  value={apps}
                  onChange={(e) => setApps(e.target.value)}
                />
              </Field>
              <Field
                label="Ports"
                htmlFor="network-rule-ports"
                hint="Comma-separated, or 'any'."
              >
                <TextInput
                  id="network-rule-ports"
                  disabled={initial?.learned}
                  placeholder="443, 8080"
                  value={ports}
                  onChange={(e) => setPorts(e.target.value)}
                />
              </Field>
              <Field label="Action" htmlFor="network-rule-action" required>
                <Select
                  id="network-rule-action"
                  value={action}
                  onChange={(e) =>
                    setAction(e.target.value as "allow" | "deny")
                  }
                >
                  <option value="allow">Allow</option>
                  <option value="deny">Deny</option>
                </Select>
              </Field>
              <Field label="Comment" htmlFor="network-rule-comment">
                <TextInput
                  id="network-rule-comment"
                  placeholder="why this rule exists"
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                />
              </Field>
            </div>
            {initial?.learned && (
              <p className="text-sm text-muted-foreground">
                Applications and ports come from observed traffic for learned
                rules. You can override their action, status, comment, and
                priority.
              </p>
            )}
            <Collapse label="Advanced">
              {reviewed && (
                <div className="mb-3 space-y-2 text-xs">
                  <p>
                    Reviewed saved rule: {reviewed.action} ·{" "}
                    {reviewed.disable ? "Disabled" : "Enabled"} · priority{" "}
                    {reviewed.priority}. Saving applies your retained draft.
                  </p>
                  <p>Saved comment: {reviewed.comment || "None"}</p>
                </div>
              )}
              <div className="grid gap-5 sm:grid-cols-2">
                <Field label="Status" htmlFor="network-rule-status">
                  <Select
                    id="network-rule-status"
                    value={disable ? "disabled" : "enabled"}
                    onChange={(e) => setDisable(e.target.value === "disabled")}
                  >
                    <option value="enabled">Enabled</option>
                    <option value="disabled">Disabled</option>
                  </Select>
                </Field>
                <Field
                  label="Priority"
                  htmlFor="network-rule-priority"
                  hint="Lower numbers are evaluated first among configured rules."
                >
                  <TextInput
                    id="network-rule-priority"
                    type="number"
                    step="1"
                    min="-2147483648"
                    max="2147483647"
                    required
                    value={priority}
                    onChange={(e) => setPriority(e.target.value)}
                  />
                </Field>
              </div>
            </Collapse>
            {save.isError && (
              <p role="alert" className="text-sm text-status-error">
                Could not save this network rule. Your draft is preserved. Try
                again.
              </p>
            )}
            <div className="flex items-center gap-3">
              <Button
                type="submit"
                variant="primary"
                size="lg"
                disabled={!valid || save.isPending || blocked}
              >
                {save.isPending
                  ? "Saving…"
                  : editing
                    ? "Save changes"
                    : "Add rule"}
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="lg"
                onClick={() => navigate({ href: listPath })}
              >
                Cancel
              </Button>
            </div>
          </fieldset>
        </form>
      </Card>
    </div>
  );
}
