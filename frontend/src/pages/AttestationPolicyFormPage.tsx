// Routes: /settings/attestation-trust/new (create) and /settings/attestation-trust/:id (edit).
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft, Save, ShieldCheck } from "lucide-react";

import {
  repositoryScanAttestationTrustPolicies,
  type RepositoryAttestationTrustPolicy,
  type RepositoryAttestationTrustPolicyInput,
} from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Collapse } from "@/components/ui/collapse";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Textarea, Select, Switch } from "@/components/ui/form";

type PolicyFormState = {
  name: string;
  description: string;
  enabled: boolean;
  auto_verify: boolean;
  subject_kind: "image";
  source_types: string[];
  repository_ref_patterns: string;
  source_ref_patterns: string;
  predicate_types: string;
  allowed_identities: string;
  allowed_issuers: string;
  require_rekor: boolean;
  verifier_mode: "keyless" | "public-key";
  public_key_pem: string;
};

const SOURCE_TYPES = [
  "repository",
  "registry",
  "runtime-agent",
  "manual",
  "discoverer",
  "platform",
  "host",
  "serverless",
];

const DEFAULT_FORM: PolicyFormState = {
  name: "",
  description: "",
  enabled: true,
  auto_verify: true,
  subject_kind: "image",
  source_types: ["repository"],
  repository_ref_patterns: "",
  source_ref_patterns: "",
  predicate_types: "https://slsa.dev/provenance/v1",
  allowed_identities: "",
  allowed_issuers: "https://token.actions.githubusercontent.com",
  require_rekor: false,
  verifier_mode: "keyless",
  public_key_pem: "",
};

const BACK_LINK = "/settings/attestation-trust";

/**
 * AttestationPolicyFormPage — /settings/attestation-trust/new and /:id. A dedicated
 * form page (the Astronomer add/edit-as-a-page pattern, replacing the old drawer) for
 * creating and editing attestation trust policies. Verify an image's
 * signature/attestation (Sigstore/cosign, SLSA provenance) before it's allowed to run.
 */
export function AttestationPolicyFormPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { id } = useParams<{ id: string }>();
  const isEdit = Boolean(id);

  const [form, setForm] = useState<PolicyFormState>(DEFAULT_FORM);
  const [editing, setEditing] = useState<RepositoryAttestationTrustPolicy | null>(null);

  // No single-policy endpoint — load the list and find the one being edited.
  const policiesQ = useQuery({
    queryKey: ["attestation-trust-policies"],
    queryFn: () => repositoryScanAttestationTrustPolicies.list(),
    enabled: isEdit,
  });
  const loaded = policiesQ.data?.policies?.find((p) => p.id === id) ?? null;

  useEffect(() => {
    if (isEdit && loaded) {
      setEditing(loaded);
      setForm(policyToForm(loaded));
    }
  }, [isEdit, loaded]);

  const savePolicy = useMutation({
    mutationFn: () => {
      const input = formToPolicyInput(form);
      if (editing) {
        return repositoryScanAttestationTrustPolicies.update(editing.id, input);
      }
      return repositoryScanAttestationTrustPolicies.create(input);
    },
    onSuccess: () => {
      toast.success(editing ? "Trust policy updated" : "Trust policy created");
      void qc.invalidateQueries({ queryKey: ["attestation-trust-policies"] });
      void qc.invalidateQueries({ queryKey: ["repository-scans"] });
      navigate(BACK_LINK);
    },
    onError: (err: unknown) => toast.error(`Save failed: ${errorMessage(err)}`),
  });

  const set = <K extends keyof PolicyFormState>(key: K, value: PolicyFormState[K]) =>
    setForm((prev) => ({ ...prev, [key]: value }));

  const notFound = isEdit && !policiesQ.isLoading && !policiesQ.error && !loaded;

  return (
    <div className="space-y-6">
      <PageHeader
        backLink={
          <Link to={BACK_LINK} className="inline-flex items-center gap-1 hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Attestation trust
          </Link>
        }
        title={
          <span className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" aria-hidden />
            {isEdit ? "Edit trust policy" : "New trust policy"}
          </span>
        }
        description="Verify an image's signature/attestation before it's allowed to run."
      />

      {isEdit && policiesQ.isLoading ? (
        <Card title="Policy">
          <div className="p-2 text-sm text-muted-foreground">Loading policy…</div>
        </Card>
      ) : notFound ? (
        <Card title="Policy">
          <div className="p-2 text-sm text-destructive">Trust policy not found.</div>
          <Button variant="outline" size="lg" className="mt-3" onClick={() => navigate(BACK_LINK)}>
            Back to policies
          </Button>
        </Card>
      ) : (
        <Card title="Policy" description="Which signatures and attestations are required, and where this policy applies.">
          <form
            data-testid="attestation-trust-editor"
            onSubmit={(event) => {
              event.preventDefault();
              savePolicy.mutate();
            }}
          >
            {editing ? (
              <div className="mb-3 break-all font-mono text-[10px] text-muted-foreground">{editing.id}</div>
            ) : null}

            <div className="space-y-5">
              <Field label="Name">
                <TextInput
                  value={form.name}
                  onChange={(event) => set("name", event.target.value)}
                  required
                  data-testid="attestation-trust-name"
                />
              </Field>

              <Field label="Description">
                <Textarea
                  value={form.description}
                  onChange={(event) => set("description", event.target.value)}
                  rows={2}
                />
              </Field>

              <div className="space-y-3 rounded-lg border border-border bg-muted/30 px-4 py-3">
                <Switch
                  checked={form.enabled}
                  onCheckedChange={(checked) => set("enabled", checked)}
                  label="Enabled"
                  description="Enforce this policy during admission."
                />
                <Switch
                  checked={form.auto_verify}
                  onCheckedChange={(checked) => set("auto_verify", checked)}
                  label="Auto verify"
                  description="Verify new attestations as they arrive."
                />
              </div>

              <Field label="Verifier" hint="How signatures are trusted.">
                <Select
                  value={form.verifier_mode}
                  onChange={(event) => set("verifier_mode", event.target.value as PolicyFormState["verifier_mode"])}
                >
                  <option value="keyless">keyless (Sigstore OIDC identity)</option>
                  <option value="public-key">public key (cosign)</option>
                </Select>
              </Field>

              <Field label="Sources" hint="Which image sources this policy applies to.">
                <div className="grid grid-cols-2 gap-1.5">
                  {SOURCE_TYPES.map((sourceType) => {
                    const active = form.source_types.includes(sourceType);
                    return (
                      <label
                        key={sourceType}
                        className={`flex cursor-pointer items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs transition-colors ${
                          active ? "border-[color:var(--color-brand)] bg-[color:var(--color-brand)]/5 text-foreground" : "border-border text-muted-foreground hover:bg-accent"
                        }`}
                      >
                        <input
                          type="checkbox"
                          className="accent-[color:var(--color-brand)]"
                          checked={active}
                          onChange={(event) => {
                            const next = event.target.checked
                              ? [...form.source_types, sourceType]
                              : form.source_types.filter((item) => item !== sourceType);
                            set("source_types", next);
                          }}
                        />
                        {sourceType}
                      </label>
                    );
                  })}
                </div>
              </Field>

              {form.verifier_mode === "public-key" ? (
                <TextList label="Cosign public key" value={form.public_key_pem} onChange={(value) => set("public_key_pem", value)} required />
              ) : (
                <>
                  <TextList label="Allowed identities" value={form.allowed_identities} onChange={(value) => set("allowed_identities", value)} required />
                  <TextList label="Allowed issuers" value={form.allowed_issuers} onChange={(value) => set("allowed_issuers", value)} required />
                </>
              )}

              <Collapse label="Advanced">
                <div className="space-y-5">
                  <div className="rounded-lg border border-border bg-muted/30 px-4 py-3">
                    <Switch
                      checked={form.require_rekor}
                      onCheckedChange={(checked) => set("require_rekor", checked)}
                      label="Require Rekor transparency log"
                      description="Reject signatures without a Rekor entry."
                    />
                  </div>
                  <TextList label="Repository patterns" value={form.repository_ref_patterns} onChange={(value) => set("repository_ref_patterns", value)} />
                  <TextList label="Source ref patterns" value={form.source_ref_patterns} onChange={(value) => set("source_ref_patterns", value)} />
                  <TextList label="Predicate types" value={form.predicate_types} onChange={(value) => set("predicate_types", value)} required />
                </div>
              </Collapse>

              <div className="flex items-center gap-3">
                <Button
                  type="submit"
                  variant="primary"
                  size="lg"
                  disabled={savePolicy.isPending}
                  data-testid="attestation-trust-save"
                >
                  <Save className="h-4 w-4" aria-hidden />
                  {savePolicy.isPending ? "Saving…" : "Save policy"}
                </Button>
                <Button type="button" variant="ghost" size="lg" onClick={() => navigate(BACK_LINK)}>
                  Cancel
                </Button>
              </div>
            </div>
          </form>
        </Card>
      )}
    </div>
  );
}

function TextList({
  label,
  value,
  onChange,
  required,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  required?: boolean;
}) {
  return (
    <Field label={label}>
      <Textarea
        value={value}
        onChange={(event) => onChange(event.target.value)}
        rows={3}
        required={required}
        spellCheck={false}
        className="font-mono text-xs"
      />
    </Field>
  );
}

function policyToForm(policy: RepositoryAttestationTrustPolicy): PolicyFormState {
  return {
    name: policy.name,
    description: policy.description,
    enabled: policy.enabled,
    auto_verify: policy.auto_verify,
    subject_kind: "image",
    source_types: policy.source_types,
    repository_ref_patterns: listToText(policy.repository_ref_patterns),
    source_ref_patterns: listToText(policy.source_ref_patterns),
    predicate_types: listToText(policy.predicate_types),
    allowed_identities: listToText(policy.allowed_identities),
    allowed_issuers: listToText(policy.allowed_issuers),
    require_rekor: policy.require_rekor,
    verifier_mode: policy.verifier_mode || "keyless",
    public_key_pem: policy.public_key_pem || "",
  };
}

function formToPolicyInput(form: PolicyFormState): RepositoryAttestationTrustPolicyInput {
  return {
    name: form.name.trim(),
    description: form.description.trim(),
    enabled: form.enabled,
    auto_verify: form.auto_verify,
    subject_kind: form.subject_kind,
    source_types: uniqueList(form.source_types),
    repository_ref_patterns: textToList(form.repository_ref_patterns),
    source_ref_patterns: textToList(form.source_ref_patterns),
    predicate_types: textToList(form.predicate_types),
    allowed_identities: form.verifier_mode === "public-key" ? [] : textToList(form.allowed_identities),
    allowed_issuers: form.verifier_mode === "public-key" ? [] : textToList(form.allowed_issuers),
    require_rekor: form.require_rekor,
    verifier_mode: form.verifier_mode,
    public_key_pem: form.verifier_mode === "public-key" ? form.public_key_pem.trim() : "",
  };
}

function listToText(values: string[]): string {
  return values.join("\n");
}

function textToList(value: string): string[] {
  return uniqueList(value.split(/[\n,]/g));
}

function uniqueList(values: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of values) {
    const value = raw.trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

function errorMessage(err: unknown): string {
  const typed = err as { response?: { data?: unknown }; message?: string };
  return String(typed.response?.data ?? typed.message ?? err);
}
