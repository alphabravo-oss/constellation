// AdmissionRuleFormPage — /clusters/:id/admission/new. Dedicated dropdown-driven builder
// for a NeuVector-style admission rule: pick criteria from the live options catalog, enter
// values, and the server translates them into the engine's YAML spec (validated before
// save). Replaces hand-writing admission YAML on the Policies page.
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { ArrowLeft, Plus, X } from "lucide-react";

import { policies as policiesApi, type AdmissionCriterionOption } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Select } from "@/components/ui/form";

interface Row { key: string; value: string }

export function AdmissionRuleFormPage() {
  const { clusterId } = useCluster();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const listPath = clusterId ? `/clusters/${clusterId}/admission` : "/admission";

  const optionsQ = useQuery({ queryKey: ["admission-options"], queryFn: () => policiesApi.admissionOptions() });
  const options = optionsQ.data;
  const catalog = options?.criteria ?? [];
  const byKey = (k: string): AdmissionCriterionOption | undefined => catalog.find((c) => c.key === k);

  const [name, setName] = useState("");
  const [mode, setMode] = useState("monitor");
  const [rows, setRows] = useState<Row[]>([{ key: "", value: "" }]);

  const setRow = (i: number, patch: Partial<Row>) => setRows((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const addRow = () => setRows((rs) => [...rs, { key: "", value: "" }]);
  const removeRow = (i: number) => setRows((rs) => rs.filter((_, j) => j !== i));

  const save = useMutation({
    mutationFn: () =>
      policiesApi.createAdmissionRule(
        { name: name.trim(), mode, criteria: rows.filter((r) => r.key).map((r) => ({ key: r.key, value: r.value.trim() })) },
        { cluster_id: clusterId },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["admission-rules", clusterId] });
      navigate(listPath);
    },
  });

  const validRows = rows.filter((r) => r.key);
  const canSave = name.trim().length > 0 && validRows.length > 0 && !save.isPending;

  // Render the value input appropriate to the selected criterion's value_type.
  function valueInput(row: Row, i: number) {
    const opt = byKey(row.key);
    if (!opt || opt.value_type === "none") return <span className="text-xs text-muted-foreground">no value needed</span>;
    if (opt.value_type === "severity") {
      return (
        <Select value={row.value} onChange={(e) => setRow(i, { value: e.target.value })}>
          <option value="">choose…</option>
          {(options?.severities ?? []).map((s) => <option key={s} value={s}>{s}</option>)}
        </Select>
      );
    }
    if (opt.value_type === "pss") {
      return (
        <Select value={row.value} onChange={(e) => setRow(i, { value: e.target.value })}>
          <option value="">choose…</option>
          {(options?.pss_levels ?? []).map((s) => <option key={s} value={s}>{s}</option>)}
        </Select>
      );
    }
    return <TextInput placeholder={opt.placeholder ?? ""} value={row.value} onChange={(e) => setRow(i, { value: e.target.value })} inputMode={opt.value_type === "int" || opt.value_type === "float" ? "decimal" : "text"} />;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Add admission rule"
        description="Build a deny rule from criteria — the server compiles it to the engine's policy spec and validates it before saving."
        backLink={<Link to={listPath} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Admission Control</Link>}
      />
      <Card title="Rule" description="A workload is denied when it matches all of the criteria below.">
        <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); if (canSave) save.mutate(); }}>
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Rule name" required>
              <TextInput autoFocus placeholder="block-privileged-prod" value={name} onChange={(e) => setName(e.target.value)} required />
            </Field>
            <Field label="Mode" hint="Enforce denies; Monitor logs the would-be deny only.">
              <Select value={mode} onChange={(e) => setMode(e.target.value)}>
                {(options?.rule_modes ?? ["monitor", "enforce"]).map((m) => <option key={m} value={m}>{m}</option>)}
              </Select>
            </Field>
          </div>

          <div className="space-y-2">
            <div className="text-xs font-medium text-foreground">Criteria</div>
            {rows.map((row, i) => {
              const opt = byKey(row.key);
              return (
                <div key={i} className="space-y-1">
                  <div className="flex items-start gap-2">
                    <Select className="w-1/2" value={row.key} onChange={(e) => setRow(i, { key: e.target.value, value: "" })}>
                      <option value="">Select a criterion…</option>
                      {catalog.map((c) => <option key={c.key} value={c.key}>{c.label}</option>)}
                    </Select>
                    <div className="flex-1">{valueInput(row, i)}</div>
                    <button type="button" onClick={() => removeRow(i)} className="mt-2 rounded p-1 text-muted-foreground hover:bg-accent" title="Remove"><X className="h-3.5 w-3.5" /></button>
                  </div>
                  {opt && <p className="pl-1 text-[11px] text-muted-foreground">{opt.help}</p>}
                </div>
              );
            })}
            <button type="button" onClick={addRow} className="inline-flex items-center gap-1 text-xs text-[color:var(--color-primary)] hover:underline"><Plus className="h-3.5 w-3.5" /> Add criterion</button>
          </div>

          {save.isError && <p className="text-sm text-status-error">{(save.error as { response?: { data?: { error?: string } } })?.response?.data?.error ?? (save.error as Error).message}</p>}
          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" size="lg" disabled={!canSave}>{save.isPending ? "Saving…" : "Create rule"}</Button>
            <Button type="button" variant="ghost" size="lg" onClick={() => navigate(listPath)}>Cancel</Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
