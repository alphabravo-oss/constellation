import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft, Play } from "lucide-react";

import { scanJobs } from "@/api/client";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput as FormTextInput } from "@/components/ui/form";

/**
 * QueueScanPage — /settings/connectors/scan/new. A dedicated form page (the
 * Astronomer add-as-a-page pattern, replacing the old QueueScanDrawer). Enqueues an
 * on-demand image scan by reference.
 */
export function QueueScanPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ target_ref: "", platform: "linux/amd64" });
  const backTo = "/settings/connectors?tab=scan-jobs";

  const enqueue = useMutation({
    mutationFn: () => scanJobs.enqueue({
      target_type: "image",
      target_ref: form.target_ref.trim(),
      platform: form.platform.trim() || undefined,
    }),
    onSuccess: () => {
      toast.success("Scan job queued");
      void queryClient.invalidateQueries({ queryKey: ["scan-jobs"] });
      navigate(backTo);
    },
    onError: () => toast.error("Unable to queue scan job"),
  });
  const canQueue = Boolean(form.target_ref.trim());

  return (
    <PageContainer>
      <PageHeader
        title="Queue a scan"
        description="Enqueue an on-demand image scan by reference."
        backLink={<Link to={backTo} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Connectors</Link>}
      />

      <Card title="Scan target">
        <form
          className="space-y-5"
          data-testid="queue-scan-target"
          onSubmit={(event) => { event.preventDefault(); if (canQueue && !enqueue.isPending) enqueue.mutate(); }}
        >
          <TextInput label="Target ref" value={form.target_ref} onChange={(target_ref) => setForm((current) => ({ ...current, target_ref }))} testID="queue-scan-target-ref" />
          <TextInput label="Platform" value={form.platform} onChange={(platform) => setForm((current) => ({ ...current, platform }))} />
          <div className="flex items-center gap-3">
            <Button
              type="submit"
              variant="primary"
              size="lg"
              disabled={enqueue.isPending || !canQueue}
              data-testid="queue-scan"
            >
              <Play className="h-4 w-4" aria-hidden />
              Queue scan
            </Button>
            <Button type="button" variant="ghost" size="lg" onClick={() => navigate(backTo)}>Cancel</Button>
          </div>
        </form>
      </Card>
    </PageContainer>
  );
}

function TextInput({
  label,
  value,
  onChange,
  testID,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  testID?: string;
}) {
  return (
    <Field label={label}>
      <FormTextInput
        value={value}
        onChange={(event) => onChange(event.target.value)}
        data-testid={testID}
      />
    </Field>
  );
}
