import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft } from "lucide-react";

import { accessControl, accessControlAdmin } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Select } from "@/components/ui/form";

const BACK_TO = "/settings/access?tab=roles";

/**
 * RoleBindingFormPage — /settings/access/bindings/new. A dedicated form page (the
 * Astronomer add/edit-as-a-page pattern, replacing the old drawer). Grants a role to a
 * subject, optionally scoped to specific resources.
 */
export function RoleBindingFormPage() {
  const navigate = useNavigate();
  const q = useQuery({ queryKey: ["access-control"], queryFn: () => accessControl.overview() });
  const roles = useMemo(() => q.data?.roles ?? [], [q.data?.roles]);

  const [subjectId, setSubjectId] = useState("");
  const [subjectType, setSubjectType] = useState("user");
  const [roleId, setRoleId] = useState("");
  const [scopeKind, setScopeKind] = useState("");
  const [scopeValues, setScopeValues] = useState("");
  const save = useMutation({
    mutationFn: () =>
      accessControlAdmin.createRoleBinding({
        subject_id: subjectId.trim(),
        subject_type: subjectType,
        role_id: roleId,
        scopes: scopeKind.trim()
          ? [{ kind: scopeKind.trim(), values: scopeValues.split(",").map((v) => v.trim()).filter(Boolean), inherited: false }]
          : [],
      }),
    onSuccess: () => { toast.success("Role binding created"); navigate(BACK_TO); },
    onError: () => toast.error("Failed to create binding"),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Add role binding"
        description="Grant a role to a subject, optionally scoped to specific resources."
        backLink={<Link to={BACK_TO} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Access Control</Link>}
      />

      <Card title="Binding details" description="Choose the subject, the role, and an optional scope.">
        <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <Field label="Subject ID">
            <TextInput value={subjectId} onChange={(e) => setSubjectId(e.target.value)} required placeholder="user@org or id" />
          </Field>
          <Field label="Subject type">
            <Select value={subjectType} onChange={(e) => setSubjectType(e.target.value)}>
              <option value="user">user</option>
              <option value="group">group</option>
              <option value="service_account">service account</option>
            </Select>
          </Field>
          <Field label="Role">
            <Select value={roleId} onChange={(e) => setRoleId(e.target.value)} required>
              <option value="" disabled>Select a role…</option>
              {roles.map((r) => <option key={r.name} value={r.name}>{r.name}</option>)}
            </Select>
          </Field>
          <Field label="Scope kind (optional)">
            <TextInput value={scopeKind} onChange={(e) => setScopeKind(e.target.value)} placeholder="cluster / namespace" />
          </Field>
          <Field label="Scope values (comma-separated)">
            <TextInput value={scopeValues} onChange={(e) => setScopeValues(e.target.value)} placeholder="prod-1, prod-2" />
          </Field>
          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" size="lg" disabled={save.isPending}>
              {save.isPending ? "Creating…" : "Create binding"}
            </Button>
            <Button type="button" variant="ghost" size="lg" onClick={() => navigate(BACK_TO)}>Cancel</Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
