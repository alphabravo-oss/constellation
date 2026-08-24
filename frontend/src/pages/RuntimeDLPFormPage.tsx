// DLP rule add/edit as a DEDICATED PAGE (the Astronomer pattern —
// see frontend/CLAUDE.md "Forms & actions — DEDICATED PAGES, NOT DRAWERS").
// Replaces the old slide-in Drawer editor. Handles both create
// (/runtime-dlp/new) and edit (/runtime-dlp/:ruleId). The cluster comes from
// the parent :id route param (query-string fallback for standalone routing).
// All data logic + testids are preserved verbatim from the former DLPEditor.
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";

import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/cn";

import {
  runtimeDLP,
  type DLPRule,
} from "@/api/client";
import { patternLines, patternsFromText } from "@/lib/dlp-patterns";

export function RuntimeDLPFormPage() {
  const navigate = useNavigate();
  const [search] = useSearchParams();
  const { id: pathClusterID, ruleId } = useParams();
  const clusterID = pathClusterID ?? search.get("cluster_id") ?? "";
  const ruleID = ruleId ?? null;

  const queryClient = useQueryClient();
  const existing = useQuery({
    queryKey: ["runtime-dlp-rule", ruleID],
    queryFn: () => runtimeDLP.get(ruleID as string),
    enabled: !!ruleID,
  });

  const [name, setName] = useState("");
  const [severity, setSeverity] = useState(5);
  const [description, setDescription] = useState("");
  // One pattern per line for easy authoring. Empty lines are dropped on save.
  const [patternsText, setPatternsText] = useState("");
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (existing.data) {
      setName(existing.data.name);
      setSeverity(existing.data.severity);
      setDescription(existing.data.description ?? "");
      setPatternsText(patternLines(existing.data.patterns));
    } else if (!ruleID) {
      setName("");
      setSeverity(5);
      setDescription("");
      setPatternsText("");
    }
  }, [existing.data, ruleID]);

  const backTo = { pathname: "..", search: search.toString() };
  const goBack = () => navigate(backTo);

  const parsedPatterns = () => patternsFromText(patternsText, existing.data?.patterns);

  const save = useMutation({
    mutationFn: async (): Promise<DLPRule> => {
      setErr(null);
      const patterns = parsedPatterns();
      if (patterns.length === 0) throw new Error("at least one pattern is required");
      if (ruleID) {
        return runtimeDLP.update(ruleID, { patterns, severity, description });
      }
      if (!name) throw new Error("name is required");
      return runtimeDLP.create({
        cluster_id: clusterID, name, severity, patterns, description,
        mode: "monitor",
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["runtime-dlp-rules", clusterID] });
      goBack();
    },
    onError: (e) => setErr((e as Error).message),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={ruleID ? "Edit DLP rule" : "New DLP rule"}
        description="PCRE patterns dp's hyperscan engine compiles and scans payloads against. New rules start in monitor mode; promote separately to enforce."
        backLink={<Link to={backTo} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> DLP Rules</Link>}
      />

      <Card title="Rule" description="Name, severity, and the PCRE patterns to scan for.">
        <div className="flex flex-col gap-3" data-testid="runtime-dlp-editor">
          <DLPField label="Name" value={name} onChange={setName} disabled={!!ruleID} placeholder="aws-keys" />
          <div className="flex items-center gap-2">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Severity</div>
            <input
              type="range"
              min={1}
              max={9}
              value={severity}
              onChange={(e) => setSeverity(Number(e.target.value))}
              className="flex-1"
              data-testid="runtime-dlp-editor-severity"
            />
            <span className="text-mono text-xs tabular-nums">{severity}</span>
          </div>
          <DLPField label="Description" value={description} onChange={setDescription} placeholder="What does this catch?" />
          <div className="flex flex-col">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Patterns (one PCRE per line)</div>
            <textarea
              className="mt-0.5 min-h-[220px] w-full rounded border border-input bg-background p-2 font-mono text-[11px] outline-none focus:border-[color:var(--color-primary)]"
              value={patternsText}
              onChange={(e) => setPatternsText(e.target.value)}
              spellCheck={false}
              placeholder={"AKIA[0-9A-Z]{16}\nAIza[0-9A-Za-z\\-_]{35}"}
              data-testid="runtime-dlp-editor-patterns"
            />
          </div>
          {err && (
            <div
              className="rounded border border-[color:var(--color-status-error)] bg-card p-2 text-[11px] text-[color:var(--color-status-error)]"
              data-testid="runtime-dlp-editor-error"
            >
              {err}
            </div>
          )}
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <Button onClick={() => save.mutate()} disabled={save.isPending} data-testid="runtime-dlp-editor-save">
                {ruleID ? "Save changes" : "Create (in monitor mode)"}
              </Button>
              <Button variant="ghost" onClick={goBack}>Cancel</Button>
            </div>
            <span className="text-[10px] text-muted-foreground">
              dp's hyperscan validates each pattern on compile; bad regex = the rule fails to apply and an audit event records the error.
            </span>
          </div>
        </div>
      </Card>
    </div>
  );
}

function DLPField({
  label,
  value,
  onChange,
  placeholder,
  disabled,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  disabled?: boolean;
}) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        className={cn(
          "mt-0.5 w-full rounded border border-input bg-background px-2 py-1 text-xs outline-none focus:border-[color:var(--color-primary)]",
          disabled && "opacity-60",
        )}
      />
    </div>
  );
}
