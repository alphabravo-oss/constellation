import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { runtimeSignatures, type DLPRule } from "@/api/client";
import { useRouteSearchParams } from "@/lib/route-search";
import { patternLines, patternsFromText } from "@/lib/dlp-patterns";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Field, TextInput, Textarea, Select } from "@/components/ui/form";
import { Collapse } from "@/components/ui/collapse";
import { LoadingState, ErrorState } from "@/components/ui/states";

export function RuntimeSignatureFormPage() {
  const [search] = useRouteSearchParams();
  const { id: pathClusterID, sigId } = useParams({ strict: false });
  const clusterID = pathClusterID ?? search.get("cluster_id") ?? "";
  const ruleID = sigId ?? null;
  const backTo = clusterID ? `/clusters/${encodeURIComponent(clusterID)}/runtime-signatures${search.size ? `?${search}` : ""}` : "/clusters";
  const existing = useQuery({
    queryKey: ["runtime-signature", clusterID, ruleID],
    queryFn: () => runtimeSignatures.get(ruleID!),
    enabled: !!clusterID && !!ruleID,
    gcTime: 0,
  });
  const initial = existing.data?.cluster_id === clusterID && existing.data.id === ruleID && ["signature", "waf"].includes(existing.data.category)
    ? existing.data : undefined;

  return <div className="space-y-6">
    <PageHeader title={ruleID ? "Edit signature" : "New signature"}
      description="Define patterns to inspect in network traffic. Saving configures the rule; application to workloads depends on group scope and detector deployment."
      backLink={<Link to="." href={backTo} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> DPI Signatures</Link>} />
    {!clusterID ? <ErrorState title="Select a cluster to author signatures." />
      : ruleID && existing.isPending ? <LoadingState label="Loading signature…" />
      : ruleID && !initial ? <ErrorState title="This signature could not be loaded for the selected cluster."
          action={<Button onClick={() => void existing.refetch()}>Retry</Button>} />
      : <>
        {existing.isError && <p role="alert" className="text-sm text-status-error">Could not refresh the saved signature. Your draft is preserved.</p>}
        <RuleEditor key={`${clusterID}:${ruleID ?? "new"}`} clusterID={clusterID} initial={initial} backTo={backTo} />
      </>}
  </div>;
}

function RuleEditor({ clusterID, initial, backTo }: { clusterID: string; initial?: DLPRule; backTo: string }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [name, setName] = useState(initial?.name ?? "");
  const [severity, setSeverity] = useState(initial?.severity ?? 5);
  const [applyDir, setApplyDir] = useState(initial?.apply_dir ?? 3);
  const [description, setDescription] = useState(initial?.description ?? "");
  const [patternsText, setPatternsText] = useState(() => patternLines(initial?.patterns));
  // Keep structured pattern metadata from the version that initialized this draft.
  const [originalPatterns] = useState(initial?.patterns);
  const valid = !!name.trim() && !!patternsText.trim() && Number.isInteger(severity) && severity >= 1 && severity <= 9 && (!!initial || [1, 2, 3].includes(applyDir));
  const save = useMutation({
    mutationFn: () => {
      const patterns = patternsFromText(patternsText, originalPatterns);
      if (!valid || !patterns.length) throw new Error("Invalid rule");
      return initial
        ? runtimeSignatures.update(initial.id, { patterns, severity, description })
        : runtimeSignatures.create({ cluster_id: clusterID, name: name.trim(), severity, patterns, description, mode: "monitor", apply_dir: applyDir });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["runtime-signatures", clusterID] });
      void queryClient.invalidateQueries({ queryKey: ["runtime-signature", clusterID] });
      navigate({ href: backTo });
    },
  });

  return <Card title="Signature" description="New rules are configured in monitor mode. Change enforcement separately from the list.">
    <form className="space-y-5" data-testid="runtime-signatures-editor" onSubmit={(e) => { e.preventDefault(); if (valid && !save.isPending) save.mutate(); }}>
      <fieldset disabled={save.isPending} className="space-y-5">
        <Field label="Name" htmlFor="runtime-signatures-name" required hint={initial ? "The name is fixed after creation." : undefined}>
          <TextInput id="runtime-signatures-name" value={name} onChange={(e) => setName(e.target.value)} disabled={!!initial} placeholder="log4shell-jndi" required />
        </Field>
        <Field label="Description" htmlFor="runtime-signatures-description">
          <TextInput id="runtime-signatures-description" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What should this rule detect?" />
        </Field>
        <Field label="Patterns (one PCRE expression per line)" htmlFor="runtime-signatures-patterns" required hint="Empty lines are ignored. Existing pattern operators and contexts are retained for unchanged patterns.">
          <Textarea id="runtime-signatures-patterns" className="min-h-[220px] font-mono" value={patternsText} onChange={(e) => setPatternsText(e.target.value)} spellCheck={false} required data-testid="runtime-signatures-editor-patterns" />
        </Field>
        <Collapse label="Advanced">
          <div className="space-y-5">
          <Field label="Severity" htmlFor="runtime-signatures-severity" hint="1 is lowest; 9 is highest.">
            <div className="flex items-center gap-3"><input id="runtime-signatures-severity" type="range" min={1} max={9} value={severity} onChange={(e) => setSeverity(Number(e.target.value))} className="flex-1" data-testid="runtime-signatures-editor-severity" /><span className="text-sm tabular-nums">{severity}</span></div>
          </Field>
          <Field label="Direction" htmlFor="signature-direction" hint={initial ? "Direction is fixed after creation." : "Both directions is the default for attack signatures."}>
            <Select id="signature-direction" value={applyDir} onChange={(e) => setApplyDir(Number(e.target.value))} disabled={!!initial} data-testid="runtime-signatures-editor-direction">
              <option value={3}>Both directions</option><option value={1}>Egress only</option><option value={2}>Ingress only</option>
            </Select>
          </Field>
          <p className="text-xs text-muted-foreground">The workload detector compiles PCRE expressions before applying them. A saved configuration does not confirm successful compilation or deployment.</p>
          </div>
        </Collapse>
        {save.isError && <p role="alert" className="text-sm text-status-error" data-testid="runtime-signatures-editor-error">Could not save this signature. Your draft is preserved. Check the patterns and your permissions, then try again.</p>}
        <div className="flex items-center gap-3">
          <Button type="submit" size="lg" disabled={!valid || save.isPending} data-testid="runtime-signatures-editor-save">{save.isPending ? "Saving…" : initial ? "Save changes" : "Create in monitor mode"}</Button>
          <Button type="button" variant="ghost" size="lg" onClick={() => navigate({ href: backTo })}>Cancel</Button>
        </div>
      </fieldset>
    </form>
  </Card>;
}
