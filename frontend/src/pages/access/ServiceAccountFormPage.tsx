import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft } from "lucide-react";

import { accessControlAdmin } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput } from "@/components/ui/form";

const BACK_TO = "/settings/access?tab=service-accounts";

/**
 * ServiceAccountFormPage — /settings/access/service-accounts/new. A dedicated form page
 * (the Astronomer add/edit-as-a-page pattern, replacing the old drawer). Creates a
 * non-human identity for automation, with scoped permissions.
 */
export function ServiceAccountFormPage() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [scopes, setScopes] = useState("");
  const save = useMutation({
    mutationFn: () =>
      accessControlAdmin.createServiceAccount({
        name: name.trim(),
        description: description.trim() || undefined,
        scopes: scopes.split(",").map((s) => s.trim()).filter(Boolean),
      }),
    onSuccess: () => { toast.success("Service account created"); navigate(BACK_TO); },
    onError: () => toast.error("Failed to create service account"),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="New service account"
        description="A non-human identity for automation, with scoped permissions."
        backLink={<Link to={BACK_TO} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Access Control</Link>}
      />

      <Card title="Service account details" description="Name the account and grant it scoped permissions.">
        <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <Field label="Name">
            <TextInput value={name} onChange={(e) => setName(e.target.value)} required placeholder="ci-scanner" />
          </Field>
          <Field label="Description">
            <TextInput value={description} onChange={(e) => setDescription(e.target.value)} />
          </Field>
          <Field label="Scopes (comma-separated)">
            <TextInput value={scopes} onChange={(e) => setScopes(e.target.value)} placeholder="findings:read, scan:write" />
          </Field>
          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" size="lg" disabled={save.isPending}>
              {save.isPending ? "Creating…" : "Create service account"}
            </Button>
            <Button type="button" variant="ghost" size="lg" onClick={() => navigate(BACK_TO)}>Cancel</Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
