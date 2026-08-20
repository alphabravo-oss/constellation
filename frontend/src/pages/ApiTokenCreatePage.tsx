// ApiTokenCreatePage — /settings/api-tokens/new.
//
// The dedicated create-token page (the Astronomer add-as-a-page pattern, replacing the
// old slide-in drawer wizard). Walks through name → scopes → expiry → attach, mints the
// token via the same /api/v1/api-tokens create call, then reveals the raw token exactly
// once as an on-page result section (modeled on RegisterClusterPage's post-mint view).

import { useMemo, useState } from "react";
import { useMutation, useQueryClient, useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft, Check, ClipboardCopy, KeyRound, ShieldAlert } from "lucide-react";

import {
  apiTokens,
  type ApiTokenCreateResponse,
  type VerbInfo,
} from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput } from "@/components/ui/form";

const EXPIRY_PRESETS: Array<{ id: string; label: string; durationHours: number | null; warn?: boolean }> = [
  { id: "24h", label: "24 hours", durationHours: 24 },
  { id: "7d", label: "7 days", durationHours: 24 * 7 },
  { id: "30d", label: "30 days", durationHours: 24 * 30 },
  { id: "90d", label: "90 days", durationHours: 24 * 90 },
  { id: "1y", label: "1 year", durationHours: 24 * 365 },
  { id: "never", label: "Never (warning)", durationHours: null, warn: true },
];

type Step = 1 | 2 | 3 | 4;

export function ApiTokenCreatePage() {
  const navigate = useNavigate();
  const qc = useQueryClient();

  const verbsQ = useQuery({
    queryKey: ["rbac-verbs"],
    queryFn: () => apiTokens.verbCatalog(),
  });

  const [step, setStep] = useState<Step>(1);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [scopes, setScopes] = useState<Set<string>>(new Set());
  const [expiry, setExpiry] = useState<string>("30d");
  const [attachedTo, setAttachedTo] = useState<string>("user");
  const [revealed, setRevealed] = useState<ApiTokenCreateResponse | null>(null);

  const verbs = verbsQ.data ?? [];
  const grantable = useMemo(() => verbs.filter((v) => v.user_grantable), [verbs]);
  const groups = useMemo(() => {
    const out = new Map<string, VerbInfo[]>();
    for (const v of grantable) {
      const arr = out.get(v.category) ?? [];
      arr.push(v);
      out.set(v.category, arr);
    }
    return Array.from(out.entries());
  }, [grantable]);

  const createMutation = useMutation({
    mutationFn: () => {
      const expiresAt = expiryToISO(expiry);
      return apiTokens.create({
        name: description ? `${name} — ${description}` : name,
        scopes: Array.from(scopes),
        expires_at: expiresAt ?? undefined,
        attached_to: attachedTo,
      });
    },
    onSuccess: (resp) => {
      toast.success("Token created");
      setRevealed(resp);
      qc.invalidateQueries({ queryKey: ["api-tokens"] });
    },
    onError: (e: Error) => toast.error(`Create failed: ${e.message}`),
  });

  const canAdvance =
    (step === 1 && name.trim().length > 0) ||
    (step === 2 && scopes.size > 0) ||
    (step === 3 && expiry !== "") ||
    step === 4;

  return (
    <div className="space-y-6">
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <KeyRound className="h-5 w-5" aria-hidden />
            Create API token
          </span>
        }
        description="Scoped, long-lived bearer token for CI, scripts, or integrations. Tokens inherit the privileges of the minting user (or attached service account)."
        backLink={
          <Link to="/settings/api-tokens" className="inline-flex items-center gap-1 hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> API tokens
          </Link>
        }
      />

      {!revealed ? (
        <Card title="Token details" description="Name it, scope it, set an expiry, and choose what it attaches to.">
          <div className="space-y-4">
            <StepBar step={step} />

            {step === 1 && (
              <div className="space-y-5">
                <Field label="Name" required>
                  <TextInput
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="jenkins-prod"
                    data-testid="wizard-name"
                    autoFocus
                  />
                </Field>
                <Field label="Description (optional)">
                  <TextInput
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    placeholder="CI scanner for the main-prod cluster"
                  />
                </Field>
              </div>
            )}

            {step === 2 && (
              <div className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Select the verbs this token can perform. The token's effective verbs are the
                  intersection of these scopes and the underlying user's role grants.
                </p>
                {groups.map(([category, items]) => (
                  <fieldset key={category} className="rounded-md border border-border p-3">
                    <legend className="px-1 text-xs font-medium uppercase text-muted-foreground">{category}</legend>
                    <div className="space-y-2">
                      {items.map((v) => (
                        <label key={v.name} className="flex items-start gap-2 text-sm">
                          <input
                            type="checkbox"
                            checked={scopes.has(v.name)}
                            onChange={(e) => {
                              const next = new Set(scopes);
                              if (e.target.checked) next.add(v.name);
                              else next.delete(v.name);
                              setScopes(next);
                            }}
                            className="mt-1"
                            data-testid={`wizard-scope-${v.name}`}
                          />
                          <span>
                            <span className="font-mono text-xs">{v.name}</span>
                            <span className="ml-2 text-xs text-muted-foreground">{v.description}</span>
                          </span>
                        </label>
                      ))}
                    </div>
                  </fieldset>
                ))}
              </div>
            )}

            {step === 3 && (
              <div className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Choose how long this token is valid. Short-lived tokens are recommended.
                </p>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                  {EXPIRY_PRESETS.map((p) => (
                    <Button
                      key={p.id}
                      type="button"
                      variant={expiry === p.id ? "primary" : "outline"}
                      size="md"
                      className="w-full"
                      onClick={() => setExpiry(p.id)}
                      data-testid={`wizard-expiry-${p.id}`}
                    >
                      {p.label}
                    </Button>
                  ))}
                </div>
                {expiry === "never" && (
                  <div className="flex items-start gap-2 rounded-md border border-status-warning/40 bg-status-warning/10 p-2 text-xs text-status-warning">
                    <ShieldAlert className="mt-0.5 h-4 w-4" aria-hidden />
                    Tokens without an expiry persist until manually revoked. Use only when an automated rotation cannot be configured.
                  </div>
                )}
              </div>
            )}

            {step === 4 && (
              <div className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Attach this token to the current user (default), or to a service account so it
                  can outlive any individual.
                </p>
                <label className="flex items-start gap-2 text-sm">
                  <input
                    type="radio"
                    name="attached"
                    value="user"
                    checked={attachedTo === "user"}
                    onChange={() => setAttachedTo("user")}
                    className="mt-1"
                  />
                  <span>
                    <span>Current user</span>
                    <span className="ml-2 block text-xs text-muted-foreground">Token is revoked if the user is deleted.</span>
                  </span>
                </label>
                <Field label="Or a service account id">
                  <TextInput
                    value={attachedTo.startsWith("service-account-") ? attachedTo.replace("service-account-", "") : ""}
                    onChange={(e) => {
                      const v = e.target.value.trim();
                      setAttachedTo(v ? `service-account-${v}` : "user");
                    }}
                    placeholder="00000000-0000-0000-0000-000000000000"
                    className="font-mono text-xs"
                  />
                </Field>

                <div className="rounded-md border border-border bg-muted p-3 text-xs">
                  <div className="font-medium">Summary</div>
                  <dl className="mt-2 grid grid-cols-[120px,1fr] gap-y-1">
                    <dt className="text-muted-foreground">Name</dt><dd className="font-mono">{name}</dd>
                    <dt className="text-muted-foreground">Scopes</dt><dd className="font-mono">{Array.from(scopes).join(", ")}</dd>
                    <dt className="text-muted-foreground">Expiry</dt><dd>{expiry}</dd>
                    <dt className="text-muted-foreground">Attached</dt><dd>{attachedTo}</dd>
                  </dl>
                </div>
              </div>
            )}

            <div className="flex items-center justify-between pt-2">
              <Button type="button" variant="ghost" size="lg" onClick={() => navigate("/settings/api-tokens")}>
                Cancel
              </Button>
              <div className="inline-flex gap-2">
                {step > 1 && (
                  <Button
                    type="button"
                    variant="outline"
                    size="lg"
                    onClick={() => setStep((s) => (s - 1) as Step)}
                  >
                    Back
                  </Button>
                )}
                {step < 4 ? (
                  <Button
                    type="button"
                    variant="primary"
                    size="lg"
                    disabled={!canAdvance}
                    onClick={() => setStep((s) => (s + 1) as Step)}
                    data-testid="wizard-next"
                  >
                    Next
                  </Button>
                ) : (
                  <Button
                    type="button"
                    variant="primary"
                    size="lg"
                    disabled={createMutation.isPending || scopes.size === 0 || name.trim() === ""}
                    onClick={() => createMutation.mutate()}
                    data-testid="wizard-submit"
                  >
                    {createMutation.isPending ? "Creating…" : "Create token"}
                  </Button>
                )}
              </div>
            </div>
          </div>
        </Card>
      ) : (
        <RevealSection
          response={revealed}
          onDone={() => navigate("/settings/api-tokens")}
        />
      )}
    </div>
  );
}

function StepBar({ step }: { step: Step }) {
  const labels = ["Name", "Scopes", "Expiry", "Attach"];
  return (
    <ol className="flex items-center gap-2 text-xs">
      {labels.map((l, i) => {
        const active = i + 1 === step;
        const done = i + 1 < step;
        return (
          <li key={l} className="flex items-center gap-1">
            <span
              className={`inline-flex h-5 w-5 items-center justify-center rounded-full text-[10px] ${
                active ? "bg-primary text-primary-foreground" : done ? "bg-status-success/30 text-status-success" : "bg-muted text-muted-foreground"
              }`}
            >
              {done ? <Check className="h-3 w-3" aria-hidden /> : i + 1}
            </span>
            <span className={active ? "font-medium" : "text-muted-foreground"}>{l}</span>
            {i < labels.length - 1 && <span className="text-muted-foreground">→</span>}
          </li>
        );
      })}
    </ol>
  );
}

// --- "copy this once" reveal, as an on-page result section ---

function RevealSection({
  response,
  onDone,
}: {
  response: ApiTokenCreateResponse;
  onDone: () => void;
}) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [copied, setCopied] = useState(false);

  const copyToken = async () => {
    try {
      await navigator.clipboard.writeText(response.raw_token);
      setCopied(true);
      toast.success("Copied to clipboard");
    } catch {
      toast.error("Clipboard not available");
    }
  };

  return (
    <Card title="Copy your token now">
      <div className="space-y-4" data-testid="reveal-dialog">
        <div className="rounded-md border border-status-warning/40 bg-status-warning/10 p-3 text-xs text-status-warning dark:text-status-warning">
          <div className="flex items-center gap-2 font-medium">
            <ShieldAlert className="h-4 w-4" aria-hidden />
            This is the only time the token will be shown.
          </div>
          <p className="mt-2">
            Constellation stores only a hash. If you lose this value you'll need to rotate or
            re-issue the token.
          </p>
        </div>

        <div className="rounded-md border border-border bg-muted p-3">
          <div className="flex items-center justify-between">
            <code className="break-all font-mono text-xs" data-testid="reveal-raw-token">{response.raw_token}</code>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={copyToken}
              className="ml-3 shrink-0"
              data-testid="reveal-copy-button"
            >
              <ClipboardCopy className="h-3.5 w-3.5" aria-hidden /> {copied ? "Copied" : "Copy"}
            </Button>
          </div>
        </div>

        {response.hint && <p className="text-xs text-muted-foreground">{response.hint}</p>}

        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
            data-testid="reveal-ack"
          />
          I've stored the token in a secret manager (or copied it somewhere safe).
        </label>

        <div className="flex justify-end">
          <Button
            type="button"
            variant="primary"
            size="lg"
            onClick={onDone}
            disabled={!acknowledged}
            data-testid="reveal-close"
          >
            Done
          </Button>
        </div>
      </div>
    </Card>
  );
}

// --- expiry helper ---

function expiryToISO(preset: string): string | null {
  if (preset === "never" || preset === "") return null;
  const found = EXPIRY_PRESETS.find((p) => p.id === preset);
  if (!found || found.durationHours == null) return null;
  const d = new Date(Date.now() + found.durationHours * 3600 * 1000);
  return d.toISOString();
}
