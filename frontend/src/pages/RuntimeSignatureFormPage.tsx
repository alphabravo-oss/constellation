// Routes: /clusters/:id/runtime-signatures/new (create) and
// /clusters/:id/runtime-signatures/:sigId (edit).
//
// Dedicated form page (the Astronomer add/edit-as-a-page pattern, replacing the
// old right-side Drawer) for authoring / editing custom DPI signatures. New
// signatures start in monitor mode; promote one to enforce (on the list page) to
// start blocking. The same dp hyperscan engine runs the NeuVector built-ins.
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ArrowLeft, ShieldAlert } from "lucide-react";

import { runtimeSignatures, type DLPRule } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";

export function RuntimeSignatureFormPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [search] = useSearchParams();
  const { id: pathClusterID, sigId } = useParams();
  const clusterID = pathClusterID ?? search.get("cluster_id") ?? "";
  const ruleID = sigId ?? null;
  const isEdit = Boolean(ruleID);

  const backTo = pathClusterID
    ? `/clusters/${pathClusterID}/runtime-signatures`
    : `/runtime-signatures?cluster_id=${clusterID}`;

  const existing = useQuery({
    queryKey: ["runtime-signature", ruleID],
    queryFn: () => runtimeSignatures.get(ruleID as string),
    enabled: !!ruleID,
  });

  const [name, setName] = useState("");
  const [severity, setSeverity] = useState(5);
  const [applyDir, setApplyDir] = useState(3); // both
  const [description, setDescription] = useState("");
  const [patternsText, setPatternsText] = useState("");
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (existing.data) {
      setName(existing.data.name);
      setSeverity(existing.data.severity);
      setApplyDir(existing.data.apply_dir || 3);
      setDescription(existing.data.description ?? "");
      setPatternsText((existing.data.patterns ?? []).join("\n"));
    } else if (!ruleID) {
      setName("");
      setSeverity(5);
      setApplyDir(3);
      setDescription("");
      setPatternsText("");
    }
  }, [existing.data, ruleID]);

  const save = useMutation({
    mutationFn: async (): Promise<DLPRule> => {
      setErr(null);
      const patterns = patternsText.split("\n").map((s) => s.trim()).filter(Boolean);
      if (patterns.length === 0) throw new Error("at least one pattern is required");
      if (ruleID) {
        return runtimeSignatures.update(ruleID, { patterns, severity, description });
      }
      if (!name) throw new Error("name is required");
      return runtimeSignatures.create({
        cluster_id: clusterID, name, severity, patterns,
        description, mode: "monitor", apply_dir: applyDir,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["runtime-signatures", clusterID] });
      navigate(backTo);
    },
    onError: (e) => setErr((e as Error).message),
  });

  if (!clusterID) {
    return (
      <div className="flex h-[calc(100vh-72px)] items-center justify-center text-sm text-muted-foreground" data-testid="runtime-signatures-empty">
        Select a cluster (the URL needs <code>?cluster_id=&lt;uuid&gt;</code>).
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        backLink={
          <Link to={backTo} className="inline-flex items-center gap-1 hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> DPI Signatures
          </Link>
        }
        title={
          <span className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5" aria-hidden />
            {isEdit ? "Edit signature" : "New signature"}
          </span>
        }
        description="Attack-pattern PCRE patterns dp's hyperscan engine compiles and matches payloads against."
      />

      <Card title="Signature" description="Attack-pattern PCRE rules dp matches against packet payloads (bidirectional by default).">
        <form
          className="flex flex-col gap-3"
          data-testid="runtime-signatures-editor"
          onSubmit={(e) => { e.preventDefault(); save.mutate(); }}
        >
          <SigField label="Name" value={name} onChange={setName} disabled={!!ruleID} placeholder="log4shell-jndi" />
          <div className="flex items-center gap-2">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Severity</div>
            <input
              type="range"
              min={1}
              max={9}
              value={severity}
              onChange={(e) => setSeverity(Number(e.target.value))}
              className="flex-1"
              data-testid="runtime-signatures-editor-severity"
            />
            <span className="text-mono text-xs tabular-nums">{severity}</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Direction</div>
            <select
              value={applyDir}
              onChange={(e) => setApplyDir(Number(e.target.value))}
              disabled={!!ruleID /* dp doesn't re-key existing rules on direction change */}
              className="rounded border border-input bg-background px-2 py-1 text-xs outline-none focus:border-[color:var(--color-primary)]"
              data-testid="runtime-signatures-editor-direction"
            >
              <option value={3}>Both (default — catch attacks either way)</option>
              <option value={1}>Egress only</option>
              <option value={2}>Ingress only</option>
            </select>
          </div>
          <SigField label="Description" value={description} onChange={setDescription} placeholder="What does this catch?" />
          <div className="flex flex-col">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Patterns (one PCRE per line)</div>
            <textarea
              className="mt-0.5 min-h-[220px] w-full rounded border border-input bg-background p-2 font-mono text-[11px] outline-none focus:border-[color:var(--color-primary)]"
              value={patternsText}
              onChange={(e) => setPatternsText(e.target.value)}
              spellCheck={false}
              placeholder={"\\$\\{jndi:(ldap|rmi|dns)://[^}]+\\}\n\\.\\.\\/\\.\\.\\/(etc|root)"}
              data-testid="runtime-signatures-editor-patterns"
            />
          </div>
          {err && (
            <div
              className="rounded border border-[color:var(--color-status-error)] bg-card p-2 text-[11px] text-[color:var(--color-status-error)]"
              data-testid="runtime-signatures-editor-error"
            >
              {err}
            </div>
          )}
          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" size="lg" disabled={save.isPending} data-testid="runtime-signatures-editor-save">
              {ruleID ? "Save changes" : "Create (in monitor mode)"}
            </Button>
            <Button type="button" variant="ghost" size="lg" onClick={() => navigate(backTo)}>Cancel</Button>
          </div>
          <span className="text-[10px] text-muted-foreground">
            Same dp hyperscan engine that runs the NeuVector built-ins (SQL injection, log4shell, etc.).
          </span>
        </form>
      </Card>
    </div>
  );
}

function SigField({
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
