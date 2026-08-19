import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import {
  UsersRound,
  HeartPulse,
  ScanSearch,
  Plug,
  BadgeCheck,
  Save,
  Plus,
  Server,
  Copy,
  Check,
  Download,
  Globe2,
} from "lucide-react";

import { clusterInitBundles, type ClusterInitBundleMint } from "@/api/client";
import { useAuth } from "@/contexts/AuthContext";
import { PageHeader } from "@/components/ui/page";
import { Drawer } from "@/components/ui/drawer";
import { Collapse } from "@/components/ui/collapse";

const QUICK_LINKS = [
  { to: "/settings/access", label: "Access Control", desc: "Users, roles & SSO", icon: UsersRound },
  { to: "/settings/health", label: "System Health", desc: "Fleet & component status", icon: HeartPulse },
  { to: "/settings/scanner", label: "Scanner & CVE Sources", desc: "Vulnerability data health", icon: ScanSearch },
  { to: "/settings/integrations", label: "Integrations", desc: "Alerting & routing", icon: Plug },
  { to: "/settings/attestation-trust", label: "Attestation Trust", desc: "Image signing policies", icon: BadgeCheck },
  { to: "/settings/backup", label: "Backup", desc: "Export & restore config", icon: Save },
];

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          toast.error("Copy failed");
        }
      }}
      className="inline-flex shrink-0 items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-xs hover:bg-accent"
    >
      {copied ? <Check className="h-3.5 w-3.5 text-status-success" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? "Copied" : label}
    </button>
  );
}

/**
 * SettingsLanding — the /settings index inside SettingsShell. Identity + a real
 * cluster-registration flow (mints a cluster-init-bundle: creates the cluster
 * record + tokens, and the bundle carries this control-plane's FQDN so the agent
 * connects back and enrolls) + quick links.
 */
export function SettingsLanding() {
  const { me } = useAuth();
  const [open, setOpen] = useState(false);

  return (
    <div className="space-y-6">
      <PageHeader title="Settings" description="Organization, platform, and integration configuration. Pick an area on the left, or start below." />

      {/* Register a cluster — mints a real init-bundle (cluster record + tokens + this
          host's FQDN); the agent connects back to that FQDN with its token to enroll. */}
      <section className="rounded-lg border border-border bg-card p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="flex items-center gap-2 text-sm font-medium">
              <Server className="h-4 w-4" aria-hidden /> Add a cluster
            </h2>
            <p className="mt-1 text-xs text-muted-foreground">
              Name a cluster to mint a registration bundle. Install it on the target cluster; the agent
              connects back to this control plane and the cluster appears under{" "}
              <Link to="/clusters" className="text-primary hover:underline">Clusters</Link>.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setOpen(true)}
            className="inline-flex shrink-0 items-center gap-2 rounded-md border border-border bg-primary px-3 py-2 text-sm font-medium text-primary-foreground shadow-sm hover:bg-primary/90"
            data-testid="register-cluster-button"
          >
            <Plus className="h-4 w-4" /> Register a cluster
          </button>
        </div>
      </section>

      <RegisterClusterDrawer open={open} onOpenChange={setOpen} />

      {/* Quick links */}
      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {QUICK_LINKS.map((l) => (
          <Link key={l.to} to={l.to} className="group flex items-start gap-3 rounded-lg border border-border bg-card p-4 transition-colors hover:border-[color-mix(in_oklab,var(--color-primary)_30%,var(--color-border))]">
            <l.icon className="mt-0.5 h-5 w-5 text-muted-foreground group-hover:text-foreground" />
            <div className="min-w-0">
              <div className="text-sm font-medium">{l.label}</div>
              <div className="text-xs text-muted-foreground">{l.desc}</div>
            </div>
          </Link>
        ))}
      </section>

      {/* Identity */}
      <section data-testid="identity-card" className="rounded-lg border border-border bg-card p-4">
        <h2 className="mb-2 text-sm font-medium">Your identity</h2>
        <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-xs">
          <dt className="text-muted-foreground">User</dt>
          <dd data-testid="identity-email">{me?.email}</dd>
          <dt className="text-muted-foreground">Org</dt>
          <dd className="font-mono">{me?.org_id}</dd>
          <dt className="text-muted-foreground">Roles</dt>
          <dd data-testid="identity-roles">{me?.roles.join(", ")}</dd>
        </dl>
      </section>
    </div>
  );
}

function RegisterClusterDrawer({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [name, setName] = useState("");
  const [mint, setMint] = useState<ClusterInitBundleMint | null>(null);
  const create = useMutation({
    mutationFn: (n: string) => clusterInitBundles.create({ name: n }),
    onSuccess: (m) => {
      setMint(m);
      toast.success(`Cluster "${m.name}" registered — install the bundle to connect it`);
    },
    onError: () => toast.error("Failed to mint registration bundle"),
  });

  const reset = () => { setName(""); setMint(null); };
  const filename = mint ? `${mint.name}-init-bundle.yaml` : "init-bundle.yaml";
  const secretCmd = `kubectl create ns constellation-system
kubectl -n constellation-system create secret generic constellation-init-bundle \\
  --from-file=bundle.yaml=${filename}`;
  const helmCmd = `helm install constellation deploy/charts/constellation \\
  -n constellation-system \\
  --set initBundle.secretName=constellation-init-bundle`;

  return (
    <Drawer
      open={open}
      onOpenChange={(o) => { onOpenChange(o); if (!o) reset(); }}
      title="Register a Kubernetes cluster"
      description="Name the cluster to mint its registration bundle, then install it on the target cluster."
    >
      {!mint ? (
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); if (name.trim()) create.mutate(name.trim()); }}>
          <label className="block text-xs font-medium">
            Cluster name <span className="text-destructive">*</span>
            <input
              autoFocus
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. prod-us-east-1"
              className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
              data-testid="cluster-name-input"
            />
          </label>
          <p className="text-xs text-muted-foreground">
            This creates the cluster record and mints its agent + scanner tokens. The bundle embeds this
            control plane's URL so the installed agent knows where to connect.
          </p>
          <button
            type="submit"
            disabled={create.isPending || !name.trim()}
            className="w-full rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            data-testid="mint-bundle-submit"
          >
            {create.isPending ? "Minting…" : "Mint registration bundle"}
          </button>
        </form>
      ) : (
        <div className="space-y-4">
          <div className="rounded-md border border-border bg-muted/30 p-3 text-xs">
            <div className="flex items-center gap-2 font-medium"><Globe2 className="h-4 w-4" /> Cluster registered</div>
            <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
              <dt className="text-muted-foreground">Name</dt><dd>{mint.name}</dd>
              <dt className="text-muted-foreground">Control plane</dt><dd className="font-mono break-all">{mint.server_url}</dd>
              <dt className="text-muted-foreground">Cluster ID</dt><dd className="font-mono break-all">{mint.cluster_id}</dd>
              <dt className="text-muted-foreground">Bundle expires</dt><dd className="font-mono">{new Date(mint.expires_at).toLocaleString()}</dd>
            </dl>
            <p className="mt-2 text-[11px] text-muted-foreground">
              This is the only time the raw tokens are shown. Save the bundle now — lose it and you'll rotate.
            </p>
          </div>

          {/* Primary: one-command join (Rancher-style). */}
          <section>
            <div className="mb-1 flex items-center justify-between">
              <div className="text-xs font-semibold">Run this on the target cluster</div>
              <CopyButton text={`kubectl apply -f ${mint.import_url}`} />
            </div>
            <pre className="overflow-auto rounded border border-border bg-muted/30 p-3 text-[11px] text-mono" data-testid="import-command">kubectl apply -f {mint.import_url}</pre>
            <p className="mt-1 text-[11px] text-muted-foreground">
              One command — installs the agent (token + control-plane URL baked in), which connects back to{" "}
              <span className="font-mono">{mint.server_url}</span> and registers the cluster. It goes active once it checks in.
            </p>
          </section>

          {/* Advanced: full install via helm (adds scanner, admission, etc.). */}
          <Collapse label="Advanced: full platform install (scanner, admission, …) via helm">
            <div className="space-y-3">
              <section>
                <div className="mb-1 flex items-center justify-between">
                  <div className="text-xs font-semibold">1. Registration bundle</div>
                  <div className="flex gap-2">
                    <CopyButton text={mint.yaml} label="Copy" />
                    <button
                      type="button"
                      onClick={() => {
                        const blob = new Blob([mint.yaml], { type: "text/yaml" });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = url; a.download = filename; a.click();
                        URL.revokeObjectURL(url);
                      }}
                      className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-xs hover:bg-accent"
                    >
                      <Download className="h-3.5 w-3.5" /> Download
                    </button>
                  </div>
                </div>
                <pre className="max-h-56 overflow-auto rounded border border-border bg-muted/30 p-3 text-[11px] text-mono" data-testid="bundle-yaml">{mint.yaml}</pre>
              </section>
              <section>
                <div className="mb-1 flex items-center justify-between">
                  <div className="text-xs font-semibold">2. Create the secret on the target cluster</div>
                  <CopyButton text={secretCmd} />
                </div>
                <pre className="overflow-auto rounded border border-border bg-muted/30 p-3 text-[11px] text-mono">{secretCmd}</pre>
              </section>
              <section>
                <div className="mb-1 flex items-center justify-between">
                  <div className="text-xs font-semibold">3. Install the full platform (consumer mode)</div>
                  <CopyButton text={helmCmd} />
                </div>
                <pre className="overflow-auto rounded border border-border bg-muted/30 p-3 text-[11px] text-mono">{helmCmd}</pre>
              </section>
            </div>
          </Collapse>

          <button type="button" onClick={reset} className="w-full rounded-md border border-border px-3 py-2 text-sm hover:bg-accent">
            Register another cluster
          </button>
        </div>
      )}
    </Drawer>
  );
}
