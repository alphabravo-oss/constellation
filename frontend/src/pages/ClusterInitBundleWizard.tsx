// ClusterInitBundleWizard — Radix Dialog wizard for minting a cluster init-bundle.
//
// Wave N1: mirrors StackRox's "Generate init bundle" flow. The bundle YAML is shown
// exactly once at mint time; we surface three concrete CLI commands beneath it so an
// operator can copy-paste the install sequence without leaving the page.
//
// State machine: 'form' -> 'minting' -> 'result'. Closing the dialog on 'result' is
// guarded behind a confirmation hint (the YAML is unrecoverable; rotation is required
// if the operator dismisses without saving).
import { useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, ClipboardCheck, Copy, Download, Loader2, X } from "lucide-react";

import {
  clusterInitBundles,
  type ClusterInitBundleMint,
  type CreateClusterInitBundleRequest,
} from "@/api/client";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";

const DISTROS = ["k8s", "k3s", "eks", "gke", "aks", "openshift"] as const;
const EXPIRIES: Array<{ label: string; value: string }> = [
  { label: "24 hours", value: "24h" },
  { label: "7 days", value: "168h" },
  { label: "30 days", value: "720h" },
  { label: "90 days", value: "2160h" },
];

type Step = "form" | "result";

export function ClusterInitBundleWizard({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [step, setStep] = useState<Step>("form");
  const [form, setForm] = useState<CreateClusterInitBundleRequest>({
    name: "",
    distro: "k8s",
    region: "",
    ttl: "720h",
  });
  const [mint, setMint] = useState<ClusterInitBundleMint | null>(null);

  const qc = useQueryClient();
  const create = useMutation({
    mutationFn: (req: CreateClusterInitBundleRequest) => clusterInitBundles.create(req),
    onSuccess: (data) => {
      setMint(data);
      setStep("result");
      qc.invalidateQueries({ queryKey: ["cluster-init-bundles"] });
    },
  });

  const reset = () => {
    setStep("form");
    setMint(null);
    create.reset();
    setForm({ name: "", distro: "k8s", region: "", ttl: "720h" });
  };

  return (
    <Dialog.Root
      open={open}
      onOpenChange={(o) => {
        onOpenChange(o);
        if (!o) reset();
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-background/50 backdrop-blur-[2px]" />
        <Dialog.Content
          className={cn(
            "fixed left-1/2 top-1/2 z-50 w-[min(720px,calc(100%-2rem))] -translate-x-1/2 -translate-y-1/2",
            "bg-card border border-border rounded-md shadow-[var(--elev-3)] flex flex-col max-h-[90vh]",
          )}
          data-testid="cluster-init-bundle-wizard"
        >
          <header className="flex items-start justify-between gap-2 border-b border-border px-5 py-4">
            <div>
              <Dialog.Title className="text-display text-base font-semibold tracking-tight">
                Register cluster
              </Dialog.Title>
              <Dialog.Description className="mt-0.5 text-xs text-muted-foreground">
                Mint a sealed init-bundle for a remote cluster. Includes scoped tokens,
                admission TLS material, and an audit HMAC secret.
              </Dialog.Description>
            </div>
            <Dialog.Close
              aria-label="Close"
              className="rounded p-1 text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
            >
              <X className="h-4 w-4" />
            </Dialog.Close>
          </header>

          <div className="flex-1 overflow-y-auto px-5 py-4">
            {step === "form" && (
              <FormStep
                form={form}
                setForm={setForm}
                submitting={create.isPending}
                error={create.error instanceof Error ? create.error.message : null}
                onSubmit={() => create.mutate(form)}
              />
            )}
            {step === "result" && mint && <ResultStep mint={mint} />}
          </div>

          <footer className="flex items-center justify-between gap-2 border-t border-border px-5 py-3">
            <div className="text-[11px] text-muted-foreground">
              {step === "result" ? (
                <span className="inline-flex items-center gap-1">
                  <AlertTriangle className="h-3 w-3 text-[var(--color-status-warning)]" />
                  This is the only time the secrets are shown. Lose it = rotate.
                </span>
              ) : (
                "Mint is audit-logged. RBAC: manage-org."
              )}
            </div>
            {step === "form" ? (
              <Button
                variant="primary"
                onClick={() => create.mutate(form)}
                disabled={create.isPending || !form.name.trim()}
                data-testid="mint-bundle-submit"
              >
                {create.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                Generate bundle
              </Button>
            ) : (
              <Button variant="primary" onClick={() => onOpenChange(false)}>
                Done
              </Button>
            )}
          </footer>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function FormStep({
  form,
  setForm,
  submitting,
  error,
  onSubmit,
}: {
  form: CreateClusterInitBundleRequest;
  setForm: (f: CreateClusterInitBundleRequest) => void;
  submitting: boolean;
  error: string | null;
  onSubmit: () => void;
}) {
  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit();
      }}
    >
      <Field label="Cluster name" required>
        <input
          autoFocus
          required
          className={fieldClass}
          placeholder="prod-us-east-1"
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          data-testid="bundle-name-input"
        />
        <p className="mt-1 text-[11px] text-muted-foreground">
          Used as the clusters row name + bundle DNS SAN for admission TLS.
        </p>
      </Field>

      <div className="grid gap-3 md:grid-cols-2">
        <Field label="Distribution">
          <select
            className={fieldClass}
            value={form.distro}
            onChange={(e) => setForm({ ...form, distro: e.target.value })}
          >
            {DISTROS.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
        </Field>

        <Field label="Region">
          <input
            className={fieldClass}
            placeholder="us-east-1"
            value={form.region ?? ""}
            onChange={(e) => setForm({ ...form, region: e.target.value })}
          />
        </Field>
      </div>

      <Field label="Expires after">
        <select
          className={fieldClass}
          value={form.ttl}
          onChange={(e) => setForm({ ...form, ttl: e.target.value })}
        >
          {EXPIRIES.map((e) => (
            <option key={e.value} value={e.value}>
              {e.label}
            </option>
          ))}
        </select>
        <p className="mt-1 text-[11px] text-muted-foreground">
          Bundle + underlying tokens are auto-revoked at this time. Rotate before then to
          extend the cluster's lease.
        </p>
      </Field>

      {error && (
        <div className="rounded border border-[color-mix(in_oklab,var(--color-destructive)_60%,var(--color-border))] bg-[color-mix(in_oklab,var(--color-destructive)_8%,transparent)] px-3 py-2 text-xs text-[var(--color-destructive)]">
          {error}
        </div>
      )}
      {/* submit happens via the footer button */}
      {submitting && (
        <p className="text-xs text-muted-foreground">
          Generating TLS material and minting tokens…
        </p>
      )}
    </form>
  );
}

function ResultStep({ mint }: { mint: ClusterInitBundleMint }) {
  const filename = `${mint.name}-init-bundle.yaml`;
  const helmCommand = `helm install constellation deploy/charts/constellation \\
  -n constellation-system \\
  --set initBundle.secretName=constellation-init-bundle`;
  const kubectlCommand = `kubectl create ns constellation-system
kubectl -n constellation-system create secret generic constellation-init-bundle \\
  --from-file=bundle.yaml=${filename}`;
  const verifyCommand = `kubectl -n constellation-system get secret constellation-admission-tls -o yaml
kubectl -n constellation-system rollout status deploy/constellation-admission`;

  return (
    <div className="space-y-4">
      <Banner mint={mint} />

      <section>
        <SectionHeader>1. Bundle YAML</SectionHeader>
        <pre
          data-testid="bundle-yaml"
          className="mt-2 max-h-72 overflow-auto rounded border border-border bg-muted/30 p-3 text-[11px] text-mono"
        >
          {mint.yaml}
        </pre>
        <div className="mt-2 flex gap-2">
          <CopyButton value={mint.yaml} label="Copy YAML" />
          <DownloadButton filename={filename} content={mint.yaml} />
        </div>
      </section>

      <section>
        <SectionHeader>2. Create the secret on the target cluster</SectionHeader>
        <Snippet label="kubectl create secret" value={kubectlCommand} />
      </section>

      <section>
        <SectionHeader>3. Install the chart in consumer mode</SectionHeader>
        <Snippet label="helm install" value={helmCommand} />
      </section>

      <section>
        <SectionHeader>4. Verify</SectionHeader>
        <Snippet label="kubectl verify" value={verifyCommand} />
      </section>
    </div>
  );
}

function Banner({ mint }: { mint: ClusterInitBundleMint }) {
  return (
    <div className="rounded border border-[color-mix(in_oklab,var(--color-status-warning)_40%,var(--color-border))] bg-[color-mix(in_oklab,var(--color-status-warning)_8%,transparent)] px-3 py-2 text-xs">
      <div className="flex items-start gap-2">
        <AlertTriangle className="h-4 w-4 mt-0.5 text-[var(--color-status-warning)]" />
        <div>
          <div className="font-medium">Bundle minted</div>
          <div className="mt-0.5 text-muted-foreground">
            cluster_id <span className="text-mono">{mint.cluster_id}</span> · expires{" "}
            <span className="text-mono">{new Date(mint.expires_at).toLocaleString()}</span>
          </div>
          <div className="mt-1 text-[11px]">
            This is the ONLY time we&apos;ll show the raw tokens + TLS key. Save the YAML
            now; lose it and you&apos;ll have to rotate.
          </div>
        </div>
      </div>
    </div>
  );
}

function SectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
      {children}
    </h3>
  );
}

function Snippet({ label, value }: { label: string; value: string }) {
  return (
    <div className="mt-2 rounded border border-border bg-muted/30">
      <div className="flex items-center justify-between border-b border-border px-3 py-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
        {label}
        <CopyButton value={value} />
      </div>
      <pre className="overflow-auto px-3 py-2 text-[11px] text-mono">{value}</pre>
    </div>
  );
}

function CopyButton({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        await navigator.clipboard.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}
      className="inline-flex items-center gap-1 rounded border border-input bg-card px-2 py-0.5 text-[11px] hover:bg-accent"
    >
      {copied ? <ClipboardCheck className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
      {label ?? (copied ? "Copied" : "Copy")}
    </button>
  );
}

function DownloadButton({ filename, content }: { filename: string; content: string }) {
  return (
    <button
      type="button"
      onClick={() => {
        const blob = new Blob([content], { type: "application/x-yaml" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }}
      className="inline-flex items-center gap-1 rounded border border-input bg-card px-2 py-1 text-xs hover:bg-accent"
      data-testid="download-bundle"
    >
      <Download className="h-3 w-3" />
      Download {filename}
    </button>
  );
}

function Field({
  label,
  required,
  children,
}: {
  label: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
        {label}
        {required && <span className="ml-1 text-[var(--color-destructive)]">*</span>}
      </span>
      <div className="mt-1">{children}</div>
    </label>
  );
}

const fieldClass =
  "block w-full rounded border border-input bg-background px-2.5 py-1.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring";
