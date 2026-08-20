import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { Copy, Check, Download, Globe2 } from "lucide-react";

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
  const navigate = useNavigate();
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
        title="Connect a cluster"
        description="Register a Kubernetes cluster to get a one-command install that enrolls it into this control plane."
      />

      {!mint ? (
        <Card title="Cluster details" description="Name the cluster to mint its registration bundle.">
          <form
            className="space-y-5"
            onSubmit={(e) => { e.preventDefault(); if (name.trim()) create.mutate(name.trim()); }}
          >
            <Field
              label="Cluster name"
              required
              hint="This creates the cluster record and mints its agent + scanner tokens. The bundle embeds this control plane's URL so the installed agent knows where to connect."
            >
              <TextInput
                autoFocus
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. prod-us-east-1"
                data-testid="cluster-name-input"
                className="max-w-md"
              />
            </Field>
            <div className="flex items-center gap-3">
              <Button type="submit" variant="primary" size="lg" disabled={create.isPending || !name.trim()} data-testid="mint-bundle-submit">
                {create.isPending ? "Minting…" : "Mint registration bundle"}
              </Button>
              <Button type="button" variant="ghost" size="lg" onClick={() => navigate("/settings")}>Cancel</Button>
            </div>
          </form>
        </Card>
      ) : (
        <div className="space-y-6">
          <Card title={<span className="flex items-center gap-2"><Globe2 className="h-4 w-4" /> Cluster registered</span>}>
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
            <Button variant="outline" size="lg" onClick={() => { setMint(null); setName(""); }}>Register another cluster</Button>
            <Button variant="ghost" size="lg" onClick={() => navigate("/settings")}>Done</Button>
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
