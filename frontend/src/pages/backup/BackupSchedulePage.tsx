import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft } from "lucide-react";

import { backupsApi, type BackupSchedule } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Select, Switch } from "@/components/ui/form";

/**
 * BackupSchedulePage — /settings/backup/schedule. A dedicated form page (the
 * Astronomer add/edit-as-a-page pattern, replacing the old drawer). Automatic
 * signed backups on a cron schedule; the destination is set on the Backup
 * destination page and preserved here.
 */
export function BackupSchedulePage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const schedQ = useQuery({ queryKey: ["backups-schedule"], queryFn: () => backupsApi.getSchedule() });
  const schedule = schedQ.data;

  const [draft, setDraft] = useState<BackupSchedule | null>(null);
  // Initialize draft from schedule when it arrives.
  useEffect(() => {
    if (schedule && !draft) setDraft(schedule);
  }, [schedule, draft]);

  const save = useMutation({
    mutationFn: (s: BackupSchedule) => backupsApi.putSchedule(s),
    onSuccess: () => {
      toast.success("Schedule saved");
      qc.invalidateQueries({ queryKey: ["backups-schedule"] });
      navigate("/settings/backup");
    },
    onError: (e: Error) => toast.error(`Save failed: ${e.message}`),
  });

  return (
    <div className="space-y-6" data-testid="backup-schedule">
      <PageHeader
        title="Configure backup schedule"
        description="Automatic signed backups on a cron schedule, written to the configured destination."
        backLink={<Link to="/settings/backup" className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Backup &amp; Restore</Link>}
      />

      {!draft ? (
        <Card title="Scheduled backups">
          <p className="text-sm text-muted-foreground">Loading schedule…</p>
        </Card>
      ) : (
        <Card title="Schedule" description="Automatic signed backups on a cron schedule.">
          <form
            className="space-y-5"
            onSubmit={(e) => {
              e.preventDefault();
              save.mutate(draft);
            }}
          >
            <Field label="Cron expression (UTC)">
              <TextInput
                value={draft.cron_expr}
                onChange={(e) => setDraft({ ...draft, cron_expr: e.target.value })}
                className="font-mono max-w-md"
                placeholder="0 3 * * *"
              />
            </Field>
            <Field label="Signing mode">
              <Select
                value={draft.sign_mode}
                onChange={(e) => setDraft({ ...draft, sign_mode: e.target.value as BackupSchedule["sign_mode"] })}
                className="max-w-md"
              >
                <option value="static-key">static-key (ed25519)</option>
                <option value="keyless">keyless (Sigstore Fulcio)</option>
                <option value="none">none (dev only)</option>
              </Select>
            </Field>
            <div className="rounded-lg border border-border bg-muted/30 px-4 py-3">
              <Switch
                checked={draft.enabled}
                onCheckedChange={(v) => setDraft({ ...draft, enabled: v })}
                label="Enabled"
                description="Run backups automatically on the schedule above."
              />
            </div>
            <p className="rounded-lg border border-border bg-muted/30 px-4 py-3 text-xs text-muted-foreground">
              Scheduled backups are written to the destination configured on the{" "}
              <span className="font-medium text-foreground">Backup destination</span> page.
            </p>
            <div className="flex items-center gap-3">
              <Button
                type="submit"
                variant="primary"
                size="lg"
                disabled={save.isPending}
              >
                {save.isPending ? "Saving…" : "Save schedule"}
              </Button>
              <Button type="button" variant="ghost" size="lg" onClick={() => navigate("/settings/backup")}>Cancel</Button>
            </div>
          </form>
        </Card>
      )}
    </div>
  );
}
