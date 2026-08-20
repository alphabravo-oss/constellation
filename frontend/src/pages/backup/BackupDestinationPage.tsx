import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft } from "lucide-react";

import { backupsApi, type BackupSchedule } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Collapse } from "@/components/ui/collapse";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Select } from "@/components/ui/form";

/**
 * BackupDestinationPage — /settings/backup/destination. A dedicated form page
 * (the Astronomer add/edit-as-a-page pattern, replacing the old drawer). Choose
 * WHERE backups are stored: local disk (not durable) or an Amazon S3 bucket. The
 * S3 target lives on the BackupSchedule (s3_bucket / s3_prefix / s3_endpoint); we
 * merge our edits into the current schedule so cron / sign_mode / enabled are
 * never wiped.
 */
export function BackupDestinationPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const schedQ = useQuery({ queryKey: ["backups-schedule"], queryFn: () => backupsApi.getSchedule() });
  const schedule = schedQ.data;

  const [seeded, setSeeded] = useState(false);
  const [mode, setMode] = useState<"local" | "s3">("local");
  const [bucket, setBucket] = useState("");
  const [prefix, setPrefix] = useState("");
  const [endpoint, setEndpoint] = useState("");

  // Seed the form from the current schedule once it loads.
  useEffect(() => {
    if (schedule && !seeded) {
      const hasS3 = !!(schedule.s3_bucket && schedule.s3_bucket.trim());
      setMode(hasS3 ? "s3" : "local");
      setBucket(schedule.s3_bucket ?? "");
      setPrefix(schedule.s3_prefix ?? "");
      setEndpoint(schedule.s3_endpoint ?? "");
      setSeeded(true);
    }
  }, [schedule, seeded]);

  const save = useMutation({
    mutationFn: () => {
      if (!schedule) throw new Error("schedule not loaded yet");
      const merged: BackupSchedule = {
        ...schedule,
        s3_bucket: mode === "s3" ? bucket.trim() : "",
        s3_prefix: mode === "s3" ? prefix.trim() : "",
        s3_endpoint: mode === "s3" ? endpoint.trim() : "",
      };
      return backupsApi.putSchedule(merged);
    },
    onSuccess: () => {
      toast.success("Backup destination saved");
      qc.invalidateQueries({ queryKey: ["backups-schedule"] });
      navigate("/settings/backup");
    },
    onError: (e: Error) => toast.error(`Save failed: ${e.message}`),
  });

  return (
    <div className="space-y-6" data-testid="backup-destination">
      <PageHeader
        title="Backup destination"
        description="Choose where scheduled and on-demand backups are stored — local disk or a durable Amazon S3 bucket."
        backLink={<Link to="/settings/backup" className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Backup &amp; Restore</Link>}
      />

      <Card title="Where backups are stored" description="Local disk is simple but not durable; Amazon S3 is durable, off-cluster storage.">
        <form
          className="space-y-5"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <Field label="Store backups in" hint="Local disk is simple but not durable; Amazon S3 is durable, off-cluster storage.">
            <Select value={mode} onChange={(e) => setMode(e.target.value as "local" | "s3")} className="max-w-md">
              <option value="local">Local storage</option>
              <option value="s3">Amazon S3</option>
            </Select>
          </Field>

          {mode === "s3" && (
            <div className="space-y-5">
              <Field label="S3 bucket">
                <TextInput
                  value={bucket}
                  onChange={(e) => setBucket(e.target.value)}
                  className="font-mono max-w-md"
                  placeholder="my-backup-bucket"
                  data-testid="backup-destination-bucket"
                />
              </Field>
              <Field label="S3 prefix" hint="Optional key prefix inside the bucket.">
                <TextInput
                  value={prefix}
                  onChange={(e) => setPrefix(e.target.value)}
                  className="font-mono max-w-md"
                  placeholder="constellation/"
                  data-testid="backup-destination-prefix"
                />
              </Field>
              {bucket.trim() && (
                <p className="rounded-lg border border-border bg-muted/30 px-4 py-3 text-xs">
                  Backups will be written to{" "}
                  <span className="font-mono">s3://{bucket.trim()}/{prefix.trim().replace(/^\/+/, "")}</span>
                </p>
              )}
              <Collapse label="Advanced">
                <Field label="S3 endpoint" hint="Optional — for S3-compatible stores like MinIO.">
                  <TextInput
                    value={endpoint}
                    onChange={(e) => setEndpoint(e.target.value)}
                    className="font-mono max-w-md"
                    placeholder="https://s3.us-east-1.amazonaws.com"
                    data-testid="backup-destination-endpoint"
                  />
                </Field>
              </Collapse>
            </div>
          )}

          <div className="flex items-center gap-3">
            <Button
              type="submit"
              variant="primary"
              size="lg"
              disabled={save.isPending || !schedule || (mode === "s3" && !bucket.trim())}
              data-testid="backup-destination-save"
            >
              {save.isPending ? "Saving…" : "Save destination"}
            </Button>
            <Button type="button" variant="ghost" size="lg" onClick={() => navigate("/settings/backup")}>Cancel</Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
