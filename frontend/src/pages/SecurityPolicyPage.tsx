import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { securityPolicyApi, type SecurityPolicy } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput } from "@/components/ui/form";

/**
 * Security Policy — the org's password strength rules and session/idle timeouts.
 * Supersedes the built-in defaults for every user in the organization.
 */
export function SecurityPolicyPage() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["security-policy"], queryFn: () => securityPolicyApi.get() });
  const [form, setForm] = useState<SecurityPolicy | null>(null);
  useEffect(() => { if (q.data) setForm(q.data); }, [q.data]);

  const save = useMutation({
    mutationFn: (body: SecurityPolicy) => securityPolicyApi.put(body),
    onSuccess: (data) => {
      qc.setQueryData(["security-policy"], data);
      setForm(data);
      toast.success("Security policy saved");
    },
    onError: (error: unknown) => {
      const status = (error as { response?: { status?: number } })?.response?.status;
      if (status === 409) {
        void qc.invalidateQueries({ queryKey: ["security-policy"] });
        toast.error("Policy changed elsewhere; reloaded latest — please retry.");
        return;
      }
      toast.error("Failed to save security policy");
    },
  });

  const set = (k: keyof SecurityPolicy, v: number) => setForm((f) => (f ? { ...f, [k]: v } : f));
  const num = (v: string) => {
    const n = Number.parseInt(v, 10);
    return Number.isNaN(n) ? 0 : n;
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Policy"
        description="Password strength requirements and session lifetimes applied to every user in your organization."
      />

      <VerdictBanner
        status="info"
        title="Org-wide identity policy"
        detail="These rules override the built-in defaults at sign-in and password change. They do not apply to SSO-federated identities, whose provider owns password policy."
      />

      {form && (
        <form
          className="space-y-6"
          onSubmit={(e) => { e.preventDefault(); save.mutate(form); }}
        >
          <Card
            title="Password requirements"
            description="Enforced when a user sets or rotates a local password."
          >
            <div className="grid gap-5 sm:grid-cols-2">
              <Field label="Minimum length" hint="Total characters required (e.g. 12).">
                <TextInput type="number" min={1} value={form.min_length}
                  onChange={(e) => set("min_length", num(e.target.value))} className="w-32" />
              </Field>
              <Field label="Minimum character classes" hint="Distinct classes required: lower, upper, digit, symbol (1–4).">
                <TextInput type="number" min={1} max={4} value={form.min_classes}
                  onChange={(e) => set("min_classes", num(e.target.value))} className="w-32" />
              </Field>
              <Field label="Min uppercase" hint="Minimum uppercase letters. 0 = no specific minimum.">
                <TextInput type="number" min={0} value={form.min_uppercase}
                  onChange={(e) => set("min_uppercase", num(e.target.value))} className="w-32" />
              </Field>
              <Field label="Min lowercase" hint="Minimum lowercase letters. 0 = no specific minimum.">
                <TextInput type="number" min={0} value={form.min_lowercase}
                  onChange={(e) => set("min_lowercase", num(e.target.value))} className="w-32" />
              </Field>
              <Field label="Min digits" hint="Minimum digits. 0 = no specific minimum.">
                <TextInput type="number" min={0} value={form.min_digit}
                  onChange={(e) => set("min_digit", num(e.target.value))} className="w-32" />
              </Field>
              <Field label="Min special" hint="Minimum special characters. 0 = no specific minimum.">
                <TextInput type="number" min={0} value={form.min_special}
                  onChange={(e) => set("min_special", num(e.target.value))} className="w-32" />
              </Field>
              <Field label="Maximum age (days)" hint="Force a change after this many days. 0 disables expiry.">
                <TextInput type="number" min={0} value={form.max_age_days}
                  onChange={(e) => set("max_age_days", num(e.target.value))} className="w-32" />
              </Field>
              <Field label="History depth" hint="Block reuse of this many previous passwords. 0 disables.">
                <TextInput type="number" min={0} value={form.history_depth}
                  onChange={(e) => set("history_depth", num(e.target.value))} className="w-32" />
              </Field>
            </div>
          </Card>

          <Card
            title="Sessions"
            description="How long a signed-in session stays valid."
          >
            <div className="grid gap-5 sm:grid-cols-2">
              <Field label="Session timeout (minutes)" hint="Absolute session lifetime before re-auth is required. 0 uses the deploy default.">
                <TextInput type="number" min={0} value={form.session_timeout_minutes}
                  onChange={(e) => set("session_timeout_minutes", num(e.target.value))} className="w-32" />
              </Field>
              <Field label="Idle timeout (minutes)" hint="Sign out after this much inactivity. 0 uses the deploy default.">
                <TextInput type="number" min={0} value={form.idle_timeout_minutes}
                  onChange={(e) => set("idle_timeout_minutes", num(e.target.value))} className="w-32" />
              </Field>
            </div>
          </Card>

          <Card
            title="Account lockout"
            description="Brute-force protection: lock an account after too many consecutive failed logins."
          >
            <div className="grid gap-5 sm:grid-cols-2">
              <Field label="Failed-login threshold" hint="Lock the account after this many consecutive failures. 0 uses the deploy default (5).">
                <TextInput type="number" min={0} max={100} value={form.lockout_threshold}
                  onChange={(e) => set("lockout_threshold", num(e.target.value))} className="w-32" />
              </Field>
              <Field label="Lockout window (minutes)" hint="How long the account stays locked after tripping the threshold. 0 uses the deploy default (15).">
                <TextInput type="number" min={0} max={1440} value={form.lockout_window_minutes}
                  onChange={(e) => set("lockout_window_minutes", num(e.target.value))} className="w-32" />
              </Field>
            </div>
          </Card>

          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" size="lg" disabled={save.isPending}>
              {save.isPending ? "Saving…" : "Save policy"}
            </Button>
            {q.data && <Button type="button" variant="ghost" size="lg" onClick={() => setForm(q.data)}>Reset</Button>}
          </div>
        </form>
      )}
    </div>
  );
}
