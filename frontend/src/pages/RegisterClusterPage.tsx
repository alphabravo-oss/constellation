import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useBlocker, useNavigate, useParams } from "@tanstack/react-router";
import { toast } from "sonner";
import { Copy, Check, Download, Earth } from "lucide-react";

import { clusterInitBundles, type ClusterInitBundleMint } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Collapse } from "@/components/ui/collapse";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput } from "@/components/ui/form";

/**
 * RegisterClusterPage — /settings/clusters/new. A dedicated form page (the
 * Astronomer add/edit-as-a-page pattern, replacing the old drawer). Mints a real
 * cluster-init-bundle (cluster record + tokens + this control-plane FQDN) so the
 * installed agent connects back and enrolls.
 */
export function RegisterClusterPage() {
  const { bundleId } = useParams({ strict: false });
  return <RegisterClusterForm key={bundleId ?? "new"} bundleId={bundleId} />;
}

function RegisterClusterForm({ bundleId }: { bundleId?: string }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const bundles = useQuery({ queryKey: ["cluster-init-bundles"], queryFn: () => clusterInitBundles.list(), enabled: !!bundleId });
  const rotating = bundles.data?.find((bundle) => bundle.id === bundleId);
  const back = bundleId ? "/clusters?tab=bundles" : "/clusters";
  const [distro, setDistro] = useState("k8s");
  const [region, setRegion] = useState("");
  const [ttl, setTtl] = useState("720h");
  const [saved, setSaved] = useState(false);
  const [name, setName] = useState("");
  const [mint, setMint] = useState<ClusterInitBundleMint | null>(null);
  const create = useMutation({
    mutationFn: (n: string) => bundleId ? clusterInitBundles.rotate(bundleId) : clusterInitBundles.create({ name: n, distro, region: region.trim(), ttl }),
    gcTime: 0,
    onSuccess: (m) => {
      setMint(m);
      void qc.invalidateQueries({ queryKey: ["clusters"] });
      void qc.invalidateQueries({ queryKey: ["cluster-init-bundles"] });
      toast.success(`Cluster "${m.name}" registered — install the bundle to connect it`);
    },
    onError: () => toast.error("Failed to mint registration bundle"),
  });

  useBlocker({ shouldBlockFn: () => create.isPending || (!!mint && !saved && !window.confirm("Leave without saving the registration bundle? Its secrets cannot be shown again.")), enableBeforeUnload: create.isPending || (!!mint && !saved) });

  if (bundleId && !mint && bundles.isPending) return <p>Loading registration bundle...</p>;
  if (bundleId && !mint && (bundles.isError || !rotating)) return <div className="space-y-4"><p role="alert">Registration bundle could not be loaded.</p><Link to="." href={back}>Back to registration bundles</Link></div>;

  const filename = mint ? `${mint.name}-init-bundle.yaml` : "init-bundle.yaml";
  const secretCmd = `kubectl create ns constellation-system
kubectl -n constellation-system create secret generic constellation-init-bundle \\
  --from-file=bundle.yaml=${filename}`;
  const helmCmd = `helm install constellation deploy/charts/constellation \\
  -n constellation-system \\
  --set initBundle.secretName=constellation-init-bundle`;

  return (
    <div className="space-y-6">
      <PageHeader
        title={bundleId ? `Rotate registration — ${mint?.name ?? rotating?.name}` : "Connect a cluster"}
        backLink={<Link to="." href={back}>Back to clusters</Link>}
        description={bundleId ? "Replace this cluster’s registration credentials, then save and install the new bundle." : "Register a Kubernetes cluster and get the installation command that connects it to this control plane."}
      />

      {!mint ? (
        <Card title={bundleId ? "Replace registration credentials" : "Cluster details"} description={bundleId ? "The replacement bundle is shown once after rotation." : "Name the cluster to generate its registration bundle."}>
          <form
            className="space-y-5"
            onSubmit={(e) => { e.preventDefault(); if (!create.isPending && (bundleId || name.trim())) create.mutate(name.trim()); }}
          >
            {!bundleId && <Field
              label="Cluster name"
              htmlFor="cluster-name"
              required
              hint="This creates the cluster record and mints its agent + scanner tokens. The bundle embeds this control plane's URL so the installed agent knows where to connect."
            >
              <TextInput
                id="cluster-name"
                required
                autoFocus
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. prod-us-east-1"
                data-testid="cluster-name-input"
                className="max-w-md"
              />
            </Field>}
            {!bundleId && <Collapse label="Advanced registration settings">
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Distribution" htmlFor="cluster-distro"><select id="cluster-distro" className="w-full rounded border border-input bg-background p-2" value={distro} onChange={(e) => setDistro(e.target.value)}>{["k8s", "k3s", "eks", "gke", "aks", "openshift"].map((value) => <option key={value}>{value}</option>)}</select></Field>
                <Field label="Region" htmlFor="cluster-region"><TextInput id="cluster-region" value={region} onChange={(e) => setRegion(e.target.value)} placeholder="us-east-1" /></Field>
                <Field label="Expires after" htmlFor="cluster-ttl"><select id="cluster-ttl" className="w-full rounded border border-input bg-background p-2" value={ttl} onChange={(e) => setTtl(e.target.value)}>{[["24h", "24 hours"], ["168h", "7 days"], ["720h", "30 days"], ["2160h", "90 days"]].map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></Field>
              </div>
            </Collapse>}
            {bundleId && <p>Rotating replaces the existing credentials. Save the returned bundle and update the target cluster.</p>}
            {create.isError && <p role="alert">Registration failed. Your settings are preserved; try again.</p>}
            <div className="flex items-center gap-3">
              <Button type="submit" variant="primary" size="lg" disabled={create.isPending || (!bundleId && !name.trim()) || rotating?.status === "revoked"} data-testid="mint-bundle-submit">
                {create.isPending ? "Generating…" : bundleId ? "Rotate and generate bundle" : "Generate registration bundle"}
              </Button>
              <Button type="button" variant="ghost" size="lg" disabled={create.isPending} onClick={() => navigate({ href: back })}>Cancel</Button>
            </div>
          </form>
        </Card>
      ) : (
        <div className="space-y-6">
          <Card title={<span className="flex items-center gap-2"><Earth className="h-4 w-4" /> Cluster registered</span>}>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
              <dt className="text-muted-foreground">Name</dt><dd>{mint.name}</dd>
              <dt className="text-muted-foreground">Control plane</dt><dd className="font-mono break-all">{mint.server_url}</dd>
              <dt className="text-muted-foreground">Cluster ID</dt><dd className="font-mono break-all">{mint.cluster_id}</dd>
              <dt className="text-muted-foreground">Bundle expires</dt><dd className="font-mono">{new Date(mint.expires_at).toLocaleString()}</dd>
            </dl>
            <p className="mt-3 text-[11px] text-muted-foreground">
              This is the only time the raw tokens are shown. Save the bundle now — lose it and you'll rotate.
            </p>
          </Card>

          <Card title="Run this on the target cluster" description="One command — installs the agent (token + control-plane URL baked in), which connects back and registers the cluster.">
            <div className="space-y-2">
              <div className="flex items-center justify-end">
                <CopyButton text={`kubectl apply -f ${mint.import_url}`} />
              </div>
              <pre className="overflow-auto rounded border border-border bg-muted/30 p-3 text-[11px] text-mono" data-testid="import-command">kubectl apply -f {mint.import_url}</pre>
              <p className="text-[11px] text-muted-foreground">
                Connects back to <span className="font-mono">{mint.server_url}</span> and goes active once it checks in.
              </p>
            </div>
          </Card>

          <Card title="Advanced" description="Full platform install (scanner, admission, …) via helm." padded>
            <Collapse label="Show helm install steps">
              <div className="space-y-3 pt-1">
                <section>
                  <div className="mb-1 flex items-center justify-between">
                    <div className="text-xs font-semibold">1. Registration bundle</div>
                    <div className="flex gap-2">
                      <CopyButton text={mint.yaml} label="Copy" />
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          const blob = new Blob([mint.yaml], { type: "text/yaml" });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a");
                          a.href = url; a.download = filename; a.click();
                          URL.revokeObjectURL(url);
                        }}
                      >
                        <Download className="h-3.5 w-3.5" /> Download
                      </Button>
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
          </Card>

          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />I saved the registration bundle or installation command.</label>
            <Button variant="ghost" size="lg" onClick={() => navigate({ href: back })}>Done</Button>
          </div>
        </div>
      )}
    </div>
  );
}

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          toast.error("Copy failed");
        }
      }}
    >
      {copied ? <Check className="h-3.5 w-3.5 text-status-success" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? "Copied" : label}
    </Button>
  );
}
