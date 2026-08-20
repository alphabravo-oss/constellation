import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft } from "lucide-react";

import { accessControl, RBAC_ROLES } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Select } from "@/components/ui/form";

const BACK_TO = "/settings/access?tab=users";

/**
 * LocalUserFormPage — /settings/access/users/new. Creates a password-authenticated local
 * user with an org-scoped role (the "create user outside SSO JIT" capability NeuVector
 * ships). A dedicated form page per the add/edit-as-a-page pattern.
 */
export function LocalUserFormPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<string>("Analyst");

  const save = useMutation({
    mutationFn: () =>
      accessControl.createLocalUser({ email: email.trim(), display_name: displayName.trim(), password, role }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["access-control"] });
      toast.success("User created");
      navigate(BACK_TO);
    },
    onError: (e: unknown) => {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
      toast.error(msg || "Failed to create user");
    },
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="New local user"
        description="A password-authenticated user with a single org-scoped role. Use this for accounts that don't sign in through your SSO provider."
        backLink={<Link to={BACK_TO} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Access Control</Link>}
      />

      <Card title="User details" description="The user signs in with this email + password and is granted the selected role across the org.">
        <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Email" required>
              <TextInput type="email" autoComplete="off" value={email} onChange={(e) => setEmail(e.target.value)} required placeholder="jane@example.com" />
            </Field>
            <Field label="Display name" hint="Defaults to the email if left blank.">
              <TextInput value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Jane Doe" />
            </Field>
            <Field label="Password" required hint="Must satisfy the org password policy.">
              <TextInput type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            </Field>
            <Field label="Role" required>
              <Select value={role} onChange={(e) => setRole(e.target.value)}>
                {RBAC_ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
              </Select>
            </Field>
          </div>
          {save.isError && <p className="text-sm text-status-error">{(save.error as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Failed to create user"}</p>}
          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" size="lg" disabled={!email.trim() || !password || save.isPending}>
              {save.isPending ? "Creating…" : "Create user"}
            </Button>
            <Button type="button" variant="ghost" size="lg" onClick={() => navigate(BACK_TO)}>Cancel</Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
