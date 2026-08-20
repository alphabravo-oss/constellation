import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft } from "lucide-react";

import { systemConfigApi } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Switch } from "@/components/ui/form";

/**
 * NvdConfigPage — /settings/scanner/nvd. A dedicated form page (the Astronomer
 * add/edit-as-a-page pattern, replacing the old drawer). Edits the NVD full-CVE
 * import settings via systemConfigApi.patch and navigates back to the scanner
 * sources list on save/cancel.
 */
export function NvdConfigPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const systemConfig = useQuery({ queryKey: ["system-config"], queryFn: () => systemConfigApi.get() });
  const config = systemConfig.data?.config ?? {};
  const enabled = config.nvd_enabled === true;
  const hasKey = typeof config.nvd_api_key === "string" && config.nvd_api_key !== "";
  const mirror = typeof config.nvd_mirror_url === "string" ? config.nvd_mirror_url : "";

  return (
    <div className="space-y-6">
      <PageHeader
        title="NVD full CVE catalog"
        description="Import CVE descriptions + CVSS from the NVD 2.0 feed. An API key raises the rate limit."
        backLink={<Link to="/settings/scanner" className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Scanner &amp; CVE Sources</Link>}
      />

      {systemConfig.isLoading ? (
        <Card title="Loading…"><div className="text-sm text-muted-foreground">Loading current NVD settings…</div></Card>
      ) : (
        <NvdConfigForm
          enabled={enabled}
          hasKey={hasKey}
          mirror={mirror}
          onSaved={() => {
            void qc.invalidateQueries({ queryKey: ["system-config"] });
            navigate("/settings/scanner");
          }}
          onCancel={() => navigate("/settings/scanner")}
        />
      )}
    </div>
  );
}

function NvdConfigForm({ enabled, hasKey, mirror, onSaved, onCancel }: {
  enabled: boolean; hasKey: boolean; mirror: string; onSaved: () => void; onCancel: () => void;
}) {
  const [en, setEn] = useState(enabled);
  const [apiKey, setApiKey] = useState("");
  const [mir, setMir] = useState(mirror);
  const save = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = { nvd_enabled: en, nvd_mirror_url: mir.trim() };
      if (apiKey.trim()) body.nvd_api_key = apiKey.trim();
      return systemConfigApi.patch(body);
    },
    onSuccess: () => { toast.success("NVD settings saved"); onSaved(); },
    onError: () => toast.error("Failed to save NVD settings"),
  });
  return (
    <Card title="NVD import settings" description="Sync the full CVE catalog on a schedule.">
      <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
        <div className="rounded-lg border border-border bg-muted/30 px-4 py-3">
          <Switch checked={en} onCheckedChange={setEn} label="Enable NVD import" description="Sync the full CVE catalog on a schedule." />
        </div>
        <Field label="NVD API key" hint={hasKey ? "A key is already set — leave blank to keep it." : "Optional. Raises the request rate limit from 5 to 50 per 30s."}>
          <TextInput type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder={hasKey ? "••••••••" : "optional"} />
        </Field>
        <Field label="Mirror URL" hint="Air-gapped only — point at an internal NVD 2.0 mirror.">
          <TextInput value={mir} onChange={(e) => setMir(e.target.value)} placeholder="https://nvd-mirror.internal/rest/json/cves/2.0" />
        </Field>
        <div className="flex items-center gap-3">
          <Button type="submit" variant="primary" size="lg" disabled={save.isPending}>
            {save.isPending ? "Saving…" : "Save changes"}
          </Button>
          <Button type="button" variant="ghost" size="lg" onClick={onCancel}>Cancel</Button>
        </div>
      </form>
    </Card>
  );
}
