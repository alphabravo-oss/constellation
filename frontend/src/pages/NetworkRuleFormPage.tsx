import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useRouteSearchParams } from "@/lib/route-search";
import { ArrowLeft } from "lucide-react";

import { networkRules, type NetworkRule } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Select } from "@/components/ui/form";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { GroupPicker } from "@/components/GroupPicker";

export function NetworkRuleFormPage() {
  const { clusterId } = useCluster();
  const { ruleId } = useParams({ strict: false });
  const [params] = useRouteSearchParams();
  // Old edit links identify a pair; all editable values come from the server.
  const from = params.get("from");
  const to = params.get("to");
  const editing = !!ruleId || from !== null;
  const listPath = clusterId ? `/clusters/${clusterId}/network-rules` : "/network-rules";
  const q = useQuery({
    queryKey: ["network-rule-editor", clusterId, ruleId, from, to],
    queryFn: () => networkRules.list(clusterId!),
    enabled: !!clusterId && editing,
    gcTime: 0,
  });
  const matches = q.data && q.data.cluster_id === clusterId ? q.data.rules.filter((rule) =>
    (!ruleId || String(rule.id) === ruleId) &&
    (from === null || rule.from === from) && (to === null || rule.to === to)) : [];
  const initial = matches.length === 1 ? matches[0] : undefined;
  return <div className="space-y-6">
    <PageHeader title={editing ? "Edit network rule" : "Add network rule"}
      description="Control traffic between two workloads with an allow or deny rule."
      backLink={<Link to="." href={listPath} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Network Rules</Link>} />
    {!clusterId ? <ErrorState title="Select a cluster to author network rules." />
      : editing && q.isPending ? <LoadingState label="Loading network rule…" />
      : editing && !initial ? <ErrorState title="This network rule could not be loaded for the selected cluster."
          action={<Button onClick={() => void q.refetch()}>Retry</Button>} />
      : <>
        {q.isError && <p role="alert" className="text-sm text-status-error">Could not refresh the saved rule. Your draft is preserved.</p>}
        <NetworkRuleEditor key={`${clusterId}:${ruleId ?? ""}:${from ?? ""}:${to ?? ""}`}
          clusterId={clusterId} initial={initial} listPath={listPath} />
      </>}
  </div>;
}

function NetworkRuleEditor({ clusterId, initial, listPath }: { clusterId: string; initial?: NetworkRule; listPath: string }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const editing = !!initial;
  const [from, setFrom] = useState(initial?.from ?? "");
  const [to, setTo] = useState(initial?.to ?? "");
  const [ports, setPorts] = useState(initial?.ports ?? "any");
  const [apps, setApps] = useState(initial?.applications.join(", ") ?? "");
  const [action, setAction] = useState<"allow" | "deny">(initial?.action ?? "allow");
  const [comment, setComment] = useState(initial?.comment ?? "");
  const [disable, setDisable] = useState(initial?.disable ?? false);
  const [priority, setPriority] = useState(String(initial?.priority ?? 1000));
  const valid = !!from.trim() && !!to.trim() && /^-?\d+$/.test(priority) && Number(priority) >= -2147483648 && Number(priority) <= 2147483647;

  const save = useMutation({
    mutationFn: () =>
      networkRules.upsert(clusterId, {
        from: from.trim(),
        to: to.trim(),
        ports: ports.trim() || "any",
        applications: apps.split(",").map((a) => a.trim()).filter(Boolean),
        action,
        comment: comment.trim(),
        disable,
        priority: Number(priority),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["network-rules", clusterId] });
      navigate({ href: listPath });
    },
  });

  return (
      <Card title="Rule" description="Traffic from the source workload to the destination, restricted to these applications and ports.">
        <form
          className="space-y-5"
          onSubmit={(e) => { e.preventDefault(); if (valid && !save.isPending) save.mutate(); }}
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
            <Field label="To (destination)" htmlFor="network-rule-to" required>
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
            <Field label="Applications" htmlFor="network-rule-applications" hint="Comma-separated (e.g. HTTP, gRPC). Blank = any.">
              <TextInput id="network-rule-applications" disabled={initial?.learned} placeholder="HTTP, gRPC" value={apps} onChange={(e) => setApps(e.target.value)} />
            </Field>
            <Field label="Ports" htmlFor="network-rule-ports" hint="Comma-separated, or 'any'.">
              <TextInput id="network-rule-ports" disabled={initial?.learned} placeholder="443, 8080" value={ports} onChange={(e) => setPorts(e.target.value)} />
            </Field>
            <Field label="Action" htmlFor="network-rule-action" required>
              <Select id="network-rule-action" value={action} onChange={(e) => setAction(e.target.value as "allow" | "deny")}>
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
              </Select>
            </Field>
            <Field label="Comment" htmlFor="network-rule-comment">
              <TextInput id="network-rule-comment" placeholder="why this rule exists" value={comment} onChange={(e) => setComment(e.target.value)} />
            </Field>
          </div>
          {initial?.learned && <p className="text-sm text-muted-foreground">Applications and ports come from observed traffic for learned rules. You can override their action, status, comment, and priority.</p>}
          <Collapse label="Advanced">
            <div className="grid gap-5 sm:grid-cols-2">
              <Field label="Status" htmlFor="network-rule-status">
                <Select id="network-rule-status" value={disable ? "disabled" : "enabled"} onChange={(e) => setDisable(e.target.value === "disabled")}>
                  <option value="enabled">Enabled</option><option value="disabled">Disabled</option>
                </Select>
              </Field>
              <Field label="Priority" htmlFor="network-rule-priority" hint="Lower numbers are evaluated first among configured rules.">
                <TextInput id="network-rule-priority" type="number" step="1" min="-2147483648" max="2147483647" required value={priority} onChange={(e) => setPriority(e.target.value)} />
              </Field>
            </div>
          </Collapse>
          {save.isError && <p role="alert" className="text-sm text-status-error">Could not save this network rule. Your draft is preserved. Try again.</p>}
          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" size="lg" disabled={!valid || save.isPending}>
              {save.isPending ? "Saving…" : editing ? "Save changes" : "Add rule"}
            </Button>
            <Button type="button" variant="ghost" size="lg" onClick={() => navigate({ href: listPath })}>Cancel</Button>
          </div>
          </fieldset>
        </form>
      </Card>
  );
}
