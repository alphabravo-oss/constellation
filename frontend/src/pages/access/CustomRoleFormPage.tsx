import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft } from "lucide-react";

import { customRoles } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput } from "@/components/ui/form";

const BACK_TO = "/settings/access?tab=roles";

// Grantable verbs are "action-noun" (e.g. read-findings, manage-quarantine). Group by the
// action so the picker reads like NeuVector's permission matrix (all Manage-* together, …).
function domainOf(verb: string): string {
  const i = verb.indexOf("-");
  return i > 0 ? verb.slice(0, i) : "other";
}

/**
 * CustomRoleFormPage — /settings/access/roles/new. Defines an org custom role by picking
 * grantable permission verbs from the live catalog (the editable half of the role
 * permission matrix). Built-in roles stay fixed; this authors new named permission sets.
 */
export function CustomRoleFormPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const catalog = useQuery({ queryKey: ["custom-roles"], queryFn: () => customRoles.list() });
  const verbs = catalog.data?.grantable_verbs ?? [];

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const grouped = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const v of verbs) {
      const d = domainOf(v);
      if (!m.has(d)) m.set(d, []);
      m.get(d)!.push(v);
    }
    return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [verbs]);

  const toggle = (v: string) => setSelected((s) => { const n = new Set(s); n.has(v) ? n.delete(v) : n.add(v); return n; });
  const toggleDomain = (domainVerbs: string[]) => setSelected((s) => {
    const n = new Set(s);
    const allOn = domainVerbs.every((v) => n.has(v));
    domainVerbs.forEach((v) => (allOn ? n.delete(v) : n.add(v)));
    return n;
  });

  const save = useMutation({
    mutationFn: () => customRoles.create({ name: name.trim(), description: description.trim(), verbs: [...selected] }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["access-control"] });
      void qc.invalidateQueries({ queryKey: ["custom-roles"] });
      toast.success("Custom role created");
      navigate(BACK_TO);
    },
    onError: (e: unknown) => toast.error((e as { response?: { data?: { error?: string } } })?.response?.data?.error || "Failed to create role"),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="New custom role"
        description="Define a named permission set by selecting the actions it grants. Built-in roles can't be edited; custom roles are yours to shape."
        backLink={<Link to={BACK_TO} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Access Control</Link>}
      />
      <Card title="Role details">
        <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Name" required>
              <TextInput autoFocus value={name} onChange={(e) => setName(e.target.value)} required placeholder="incident-responder" />
            </Field>
            <Field label="Description">
              <TextInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Can triage findings and quarantine workloads" />
            </Field>
          </div>

          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-medium text-foreground">Permissions <span className="text-muted-foreground">({selected.size} selected)</span></span>
            </div>
            {catalog.isPending ? (
              <p className="text-sm text-muted-foreground">Loading permission catalog…</p>
            ) : (
              <div className="space-y-3">
                {grouped.map(([domain, domainVerbs]) => {
                  const allOn = domainVerbs.every((v) => selected.has(v));
                  return (
                    <div key={domain} className="rounded-md border border-border">
                      <div className="flex items-center justify-between border-b border-border bg-muted/40 px-3 py-1.5">
                        <span className="text-xs font-semibold capitalize">{domain}</span>
                        <button type="button" onClick={() => toggleDomain(domainVerbs)} className="text-[11px] text-[color:var(--color-primary)] hover:underline">
                          {allOn ? "Clear all" : "Select all"}
                        </button>
                      </div>
                      <div className="flex flex-wrap gap-x-4 gap-y-1.5 p-3">
                        {domainVerbs.map((v) => (
                          <label key={v} className="inline-flex items-center gap-1.5 text-xs">
                            <input type="checkbox" checked={selected.has(v)} onChange={() => toggle(v)} className="h-3.5 w-3.5 rounded border-border" />
                            <span className="font-mono text-[11px]">{v}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" size="lg" disabled={!name.trim() || selected.size === 0 || save.isPending}>
              {save.isPending ? "Creating…" : "Create role"}
            </Button>
            <Button type="button" variant="ghost" size="lg" onClick={() => navigate(BACK_TO)}>Cancel</Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
