// NetworkRuleFormPage — /clusters/:id/network-rules/new (and ?from=&to= to edit a manual
// rule). Dedicated add/edit page (Astronomer pattern) for a NeuVector-style network rule:
// From -> To with applications, ports, and an allow/deny action. Learned rules are edited
// inline on the list; this page authors manual (user_created) rules or edits their fields.
import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";

import { networkRules } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Select } from "@/components/ui/form";

export function NetworkRuleFormPage() {
  const { clusterId } = useCluster();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [params] = useSearchParams();
  const editing = !!params.get("from");
  const listPath = clusterId ? `/clusters/${clusterId}/network-rules` : "/network-rules";

  const [from, setFrom] = useState(params.get("from") ?? "");
  const [to, setTo] = useState(params.get("to") ?? "");
  const [ports, setPorts] = useState(params.get("ports") ?? "any");
  const [apps, setApps] = useState(params.get("applications") ?? "");
  const [action, setAction] = useState<"allow" | "deny">((params.get("action") as "allow" | "deny") ?? "allow");
  const [comment, setComment] = useState(params.get("comment") ?? "");

  const save = useMutation({
    mutationFn: () =>
      networkRules.upsert(clusterId!, {
        from: from.trim(),
        to: to.trim(),
        ports: ports.trim() || "any",
        applications: apps.split(",").map((a) => a.trim()).filter(Boolean),
        action,
        comment: comment.trim(),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["network-rules", clusterId] });
      navigate(listPath);
    },
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={editing ? "Edit network rule" : "Add network rule"}
        description="Author an ordered allow/deny rule between two workloads. Use namespace/name (e.g. prod/api) or 'external' for outside traffic."
        backLink={<Link to={listPath} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Network Rules</Link>}
      />
      <Card title="Rule" description="Traffic from the source workload to the destination, restricted to these applications and ports.">
        <form
          className="space-y-5"
          onSubmit={(e) => { e.preventDefault(); save.mutate(); }}
        >
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="From (source)" required>
              <TextInput autoFocus placeholder="prod/frontend or external" value={from} onChange={(e) => setFrom(e.target.value)} required disabled={editing} />
            </Field>
            <Field label="To (destination)" required>
              <TextInput placeholder="prod/api or external" value={to} onChange={(e) => setTo(e.target.value)} required disabled={editing} />
            </Field>
            <Field label="Applications" hint="Comma-separated (e.g. HTTP, gRPC). Blank = any.">
              <TextInput placeholder="HTTP, gRPC" value={apps} onChange={(e) => setApps(e.target.value)} />
            </Field>
            <Field label="Ports" hint="Comma-separated, or 'any'.">
              <TextInput placeholder="443, 8080" value={ports} onChange={(e) => setPorts(e.target.value)} />
            </Field>
            <Field label="Action" required>
              <Select value={action} onChange={(e) => setAction(e.target.value as "allow" | "deny")}>
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
              </Select>
            </Field>
            <Field label="Comment">
              <TextInput placeholder="why this rule exists" value={comment} onChange={(e) => setComment(e.target.value)} />
            </Field>
          </div>
          {save.isError && <p className="text-sm text-status-error">{(save.error as Error).message}</p>}
          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" size="lg" disabled={!from.trim() || !to.trim() || save.isPending}>
              {save.isPending ? "Saving…" : editing ? "Save changes" : "Add rule"}
            </Button>
            <Button type="button" variant="ghost" size="lg" onClick={() => navigate(listPath)}>Cancel</Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
