import { useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft, ShieldCheck } from "lucide-react";

import { backupsApi, type BackupManifestDTO } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, Select, Switch } from "@/components/ui/form";

/**
 * BackupRestorePage — /settings/backup/restore. A dedicated form page (the
 * Astronomer add/edit-as-a-page pattern, replacing the old drawer). Import a
 * signed constellation-backup-*.tar.gz onto this instance; verify its signature
 * and per-table counts before the destructive "Apply restore" is confirmed.
 */
export function BackupRestorePage() {
  const navigate = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [manifest, setManifest] = useState<BackupManifestDTO | null>(null);
  const [policy, setPolicy] = useState<"skip" | "overwrite">("skip");
  const [allowUnverified, setAllowUnverified] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const verifyMutation = useMutation({
    mutationFn: (f: File) => backupsApi.verify(f),
    onSuccess: (m) => {
      setManifest(m);
      toast.success(`Manifest valid: org=${m.org_name}, tables=${m.tables.length}`);
    },
    onError: (e: Error) => toast.error(`Verify failed: ${e.message}`),
  });

  const restoreMutation = useMutation({
    mutationFn: () => {
      if (!file) throw new Error("no file");
      return backupsApi.restore(file, { on_conflict: policy, allow_unverified: allowUnverified });
    },
    onSuccess: () => {
      toast.success("Restore applied. Reload the dashboard to see new rows.");
      setFile(null);
      setManifest(null);
      if (inputRef.current) inputRef.current.value = "";
      navigate("/settings/backup");
    },
    onError: (e: Error) => toast.error(`Restore failed: ${e.message}`),
  });

  return (
    <div className="space-y-6" data-testid="backup-restore">
      <PageHeader
        title="Restore from a backup tarball"
        description="Upload a signed backup; verify its signature and contents before anything is applied. Uploading never overwrites data until you confirm."
        backLink={<Link to="/settings/backup" className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Backup &amp; Restore</Link>}
      />

      <Card title="Restore" description="Import a signed constellation-backup-*.tar.gz onto this instance.">
        <div className="space-y-5">
          <Field label="Backup tarball" hint="A constellation-backup-*.tar.gz produced by this or another instance.">
            <input
              ref={inputRef}
              type="file"
              accept=".tar.gz,.tgz,application/gzip"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) {
                  setFile(f);
                  setManifest(null);
                  verifyMutation.mutate(f);
                }
              }}
              className="block w-full text-sm text-muted-foreground file:mr-3 file:rounded-md file:border file:border-border file:bg-background file:px-3 file:py-1.5 file:text-sm file:font-medium file:text-foreground hover:file:bg-accent"
            />
          </Field>
          {manifest && (
            <div className="rounded-lg border border-border bg-muted/30 p-4 text-sm">
              <p className="mb-2 flex items-center gap-2 font-medium">
                <ShieldCheck className="h-4 w-4 text-status-success" aria-hidden />
                {manifest.signer_identity
                  ? <span>Signed by <code className="font-mono">{manifest.signer_identity}</code></span>
                  : <span className="text-status-warning">Unsigned manifest</span>}
              </p>
              <dl className="grid grid-cols-2 gap-1 text-xs md:grid-cols-3">
                <div><dt className="text-muted-foreground">Org</dt><dd className="font-mono">{manifest.org_name}</dd></div>
                <div><dt className="text-muted-foreground">Format</dt><dd className="font-mono">{manifest.format_version}</dd></div>
                <div><dt className="text-muted-foreground">Generated</dt><dd className="font-mono">{new Date(manifest.generated_at).toLocaleString()}</dd></div>
                <div><dt className="text-muted-foreground">Source</dt><dd className="font-mono">{manifest.source_instance || "—"}</dd></div>
                <div><dt className="text-muted-foreground">Tables</dt><dd className="font-mono">{manifest.tables.length}</dd></div>
                <div><dt className="text-muted-foreground">Root hash</dt><dd className="font-mono truncate">{manifest.root_hash.slice(0, 16)}…</dd></div>
              </dl>
              <details className="mt-2">
                <summary className="cursor-pointer text-xs text-muted-foreground">Per-table breakdown</summary>
                <ul className="mt-1 text-xs font-mono">
                  {manifest.tables.map((t) => (
                    <li key={t.name}>{t.name}: {t.rows} rows ({t.bytes} bytes)</li>
                  ))}
                </ul>
              </details>
            </div>
          )}
          <Field label="On conflict" hint="How to handle rows that already exist on this instance.">
            <Select value={policy} onChange={(e) => setPolicy(e.target.value as "skip" | "overwrite")} className="max-w-md">
              <option value="skip">skip (safe)</option>
              <option value="overwrite">overwrite</option>
            </Select>
          </Field>
          <div className="rounded-lg border border-border bg-muted/30 px-4 py-3">
            <Switch
              checked={allowUnverified}
              onCheckedChange={setAllowUnverified}
              label="Allow unverified"
              description="DEV ONLY — apply a backup whose signature could not be verified."
            />
          </div>
          <div className="flex items-center gap-3">
            <Button
              variant="destructive"
              size="lg"
              disabled={!file || restoreMutation.isPending}
              onClick={() => {
                if (!window.confirm(`Apply backup of org "${manifest?.org_name ?? "?"}" to THIS instance? Existing rows will be ${policy === "overwrite" ? "OVERWRITTEN" : "preserved"}.`)) return;
                restoreMutation.mutate();
              }}
            >
              {restoreMutation.isPending ? "Applying…" : "Apply restore"}
            </Button>
            <Button type="button" variant="ghost" size="lg" onClick={() => navigate("/settings/backup")}>Cancel</Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
