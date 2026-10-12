// AdmissionRuleFormPage — /clusters/:id/admission/new. Dedicated dropdown-driven builder
// for a NeuVector-style admission rule: pick criteria from the live options catalog, enter
// values, and the server translates them into the engine's YAML spec (validated before
// save). Replaces hand-writing admission YAML on the Policies page.
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { ArrowLeft, Plus, ShieldAlert, X } from "lucide-react";

import { policies as policiesApi, type AdmissionCriterionOption } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Select } from "@/components/ui/form";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { GroupPicker } from "@/components/GroupPicker";
import {
  ADMISSION_RISK_SHORTCUTS,
  admissionShortcutAvailable,
  admissionShortcutPayload,
} from "@/lib/admission-rule-shortcuts";

interface Row { key: string; value: string }

export function AdmissionRuleFormPage() {
  const { clusterId } = useCluster();
  return <AdmissionRuleEditor key={clusterId ?? "none"} clusterId={clusterId} />;
}

function AdmissionRuleEditor({ clusterId }: { clusterId?: string }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const listPath = clusterId ? `/clusters/${clusterId}/admission` : "/admission";

  const optionsQ = useQuery({ queryKey: ["admission-options"], queryFn: () => policiesApi.admissionOptions() });
  const options = optionsQ.data;
  const catalog = options?.criteria ?? [];
  const byKey = (k: string): AdmissionCriterionOption | undefined => catalog.find((c) => c.key === k);

  const [name, setName] = useState("");
  const [mode, setMode] = useState("monitor");
  const [group, setGroup] = useState("");
  const [rows, setRows] = useState<Row[]>([{ key: "", value: "" }]);

  const setRow = (i: number, patch: Partial<Row>) => setRows((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const addRow = () => setRows((rs) => [...rs, { key: "", value: "" }]);
  const removeRow = (i: number) => setRows((rs) => rs.filter((_, j) => j !== i));
  const applyShortcut = (id: string) => {
    const shortcut = ADMISSION_RISK_SHORTCUTS.find((item) => item.id === id);
    if (!shortcut) return;
    const payload = admissionShortcutPayload(shortcut, catalog);
    if (payload.rows.length === 0) return;
    setName(payload.name);
    setMode(payload.mode);
    setRows(payload.rows);
  };

  const save = useMutation({
    mutationFn: () =>
      policiesApi.createAdmissionRule(
        {
          name: name.trim(),
          mode,
          group: group.trim() || undefined,
          criteria: rows.filter((r) => r.key).map((r) => ({ key: r.key, value: r.value.trim() })),
        },
        { cluster_id: clusterId },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["admission-rules", clusterId] });
      navigate({ href: listPath });
    },
  });

  const validRows = rows.filter((r) => r.key);
  const validValue = (row: Row) => {
    const option = byKey(row.key);
    if (!option) return false;
    if (option.value_type === "none") return true;
    if (!row.value.trim()) return false;
    if (option.value_type === "int") return /^-?\d+$/.test(row.value.trim()) && Number.isSafeInteger(Number(row.value));
    if (option.value_type === "float") return Number.isFinite(Number(row.value));
    return true;
  };
  const canSave = !!clusterId && !!options && !optionsQ.isError && name.trim().length > 0 && validRows.length > 0 && rows.every(validValue) && !save.isPending;

  // Render the value input appropriate to the selected criterion's value_type.
  function valueInput(row: Row, i: number) {
    const opt = byKey(row.key);
    if (!opt || opt.value_type === "none") return <span className="text-xs text-muted-foreground">no value needed</span>;
    if (opt.value_type === "severity") {
      return (
        <Select aria-label={`Criterion ${i + 1} value`} required value={row.value} onChange={(e) => setRow(i, { value: e.target.value })}>
          <option value="">choose…</option>
          {(options?.severities ?? []).map((s) => <option key={s} value={s}>{s}</option>)}
        </Select>
      );
    }
    if (opt.value_type === "pss") {
      return (
        <Select aria-label={`Criterion ${i + 1} value`} required value={row.value} onChange={(e) => setRow(i, { value: e.target.value })}>
          <option value="">choose…</option>
          {(options?.pss_levels ?? []).map((s) => <option key={s} value={s}>{s}</option>)}
        </Select>
      );
    }
    return <TextInput aria-label={`Criterion ${i + 1} value`} required placeholder={opt.placeholder ?? ""} value={row.value} onChange={(e) => setRow(i, { value: e.target.value })} inputMode={opt.value_type === "int" || opt.value_type === "float" ? "decimal" : "text"} />;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Add admission rule"
        description="Choose the conditions that flag or block a workload when it is deployed."
        backLink={<Link to="." href={listPath} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Admission Control</Link>}
      />
      {optionsQ.isPending ? <LoadingState label="Loading admission criteria…" /> : optionsQ.isError ? <ErrorState title="Could not load admission criteria." action={<Button onClick={() => void optionsQ.refetch()}>Retry</Button>} /> : null}
      <Card title="Rule" description="All criteria must match. Monitor records the decision; Enforce can block a matching deployment when cluster admission is protecting.">
        <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); if (canSave) save.mutate(); }}>
          <fieldset disabled={save.isPending || optionsQ.isPending || optionsQ.isError || !clusterId} className="space-y-5">
          <Collapse label="Risk shortcuts">
          <section className="space-y-2" data-testid="admission-risk-shortcuts">
            <div className="flex items-center gap-1.5 text-xs font-medium text-foreground">
              <ShieldAlert className="h-3.5 w-3.5 text-[color:var(--color-severity-high)]" />
              Risk shortcuts
            </div>
            <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
              {ADMISSION_RISK_SHORTCUTS.map((shortcut) => {
                const available = admissionShortcutAvailable(shortcut, catalog);
                return (
                  <button
                    key={shortcut.id}
                    type="button"
                    disabled={!available}
                    onClick={() => applyShortcut(shortcut.id)}
                    className="rounded-md border border-border bg-background px-3 py-2 text-left transition-colors hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                    data-testid={`admission-risk-shortcut-${shortcut.id}`}
                  >
                    <span className="block text-xs font-medium text-foreground">{shortcut.name}</span>
                    <span className="mt-0.5 block text-[11px] leading-relaxed text-muted-foreground">{shortcut.description}</span>
                  </button>
                );
              })}
            </div>
          </section>
          </Collapse>

          <div className="grid gap-5 md:grid-cols-3">
            <Field label="Rule name" htmlFor="admission-rule-name" required>
              <TextInput id="admission-rule-name" autoFocus placeholder="block-privileged-prod" value={name} onChange={(e) => setName(e.target.value)} required />
            </Field>
            <Field label="Mode" htmlFor="admission-rule-mode" hint="Enforce denies; Monitor logs the would-be deny only.">
              <Select id="admission-rule-mode" value={mode} onChange={(e) => setMode(e.target.value)}>
                {(options?.rule_modes ?? ["monitor", "enforce"]).map((m) => <option key={m} value={m}>{m}</option>)}
              </Select>
            </Field>
            <Field label="Group" htmlFor="admission-rule-group" hint="Optional workload group scope.">
              <GroupPicker
                inputId="admission-rule-group"
                clusterId={clusterId}
                value={group}
                onChange={setGroup}
                allowExternal={false}
                placeholder="Any group"
                testId="admission-rule-group-picker"
              />
            </Field>
          </div>

          <div className="space-y-2">
            <div className="text-xs font-medium text-foreground">Criteria</div>
            {rows.map((row, i) => {
              const opt = byKey(row.key);
              return (
                <div key={i} className="space-y-1">
                  <div className="flex items-start gap-2">
                    <Select aria-label={`Criterion ${i + 1} type`} required className="w-1/2" value={row.key} onChange={(e) => setRow(i, { key: e.target.value, value: "" })}>
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

          {save.isError && <p role="alert" className="text-sm text-status-error">Could not create this admission rule. Your draft is preserved. Check the criteria and try again.</p>}
          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" size="lg" disabled={!canSave}>{save.isPending ? "Saving…" : "Create rule"}</Button>

          </div>
          </fieldset>
          <Button type="button" variant="ghost" size="lg" disabled={save.isPending} onClick={() => navigate({ href: listPath })}>Cancel</Button>
        </form>
      </Card>
    </div>
  );
}
