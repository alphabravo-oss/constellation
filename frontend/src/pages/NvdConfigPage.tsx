import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useBlocker, useNavigate } from "@tanstack/react-router";
import { z } from "zod";
import { toast } from "sonner";
import { ArrowLeft } from "lucide-react";

import { systemConfigApi, type SystemConfigResponse } from "@/api/client";
import { useAppForm, useStore } from "@/lib/form";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/form";

const hasControlCharacter = (value: string) => ["\r", "\n", "\0"].some((character) => value.includes(character));

const nvdSchema = z.object({
  nvd_enabled: z.boolean(),
  nvd_bootstrap_enabled: z.boolean(),
  apiKey: z.string().max(4096, "The API key is too long.").refine((value) => !hasControlCharacter(value), "Enter a single-line API key."),
  nvd_mirror_url: z.string().max(2048, "The mirror URL is too long.").refine((value) => {
    if (!value.trim()) return true;
    if (hasControlCharacter(value)) return false;
    try {
      const url = new URL(value.trim());
      return ["https:", "http:"].includes(url.protocol) && Boolean(url.hostname) && !url.hash && !url.search;
    } catch { return false; }
  }, "Enter an HTTP(S) NVD API base URL without a query or fragment."),
});

function valuesFrom(data: SystemConfigResponse) {
  return {
    nvd_enabled: data.config.nvd_enabled === true,
    nvd_bootstrap_enabled: data.config.nvd_bootstrap_enabled === true,
    apiKey: "", // Never hydrate the replacement field from a stored/redacted key.
    nvd_mirror_url: typeof data.config.nvd_mirror_url === "string" ? data.config.nvd_mirror_url : "",
  };
}

export function NvdConfigPage() {
  const navigate = useNavigate();
  const query = useQuery({ queryKey: ["system-config"], queryFn: () => systemConfigApi.get() });
  return <div className="space-y-6">
    <PageHeader title="NVD CVE enrichment"
      description="Import descriptions and CVSS for recently modified CVEs from the NVD 2.0 feed. An API key raises the rate limit."
      backLink={<Link to="/settings/scanner" className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Scanner &amp; CVE Sources</Link>} />
    {query.isPending ? <p role="status">Loading current NVD settings…</p> : query.isError && !query.data ?
      <div role="alert">Could not load NVD settings. <Button onClick={() => void query.refetch()}>Retry</Button></div> :
      <NvdConfigForm data={query.data!} onClose={() => void navigate({ href: "/settings/scanner" })} />}
  </div>;
}

function NvdConfigForm({ data, onClose }: { data: SystemConfigResponse; onClose: () => void }) {
  const qc = useQueryClient();
  const savedValues = useMemo(() => valuesFrom(data), [data]);
  const [loadedRevision, setLoadedRevision] = useState(data.revision);
  const [saveError, setSaveError] = useState("");
  const form = useAppForm({
    defaultValues: savedValues,
    validators: { onChange: nvdSchema, onSubmit: nvdSchema },
    onSubmit: async ({ value }) => {
      if (loadedRevision !== data.revision) {
        setSaveError("Settings changed elsewhere. Reload current settings before saving.");
        return;
      }
      setSaveError("");
      const body: Record<string, unknown> = { nvd_enabled: value.nvd_enabled, nvd_bootstrap_enabled: value.nvd_bootstrap_enabled, nvd_mirror_url: value.nvd_mirror_url.trim() };
      if (value.apiKey.trim()) body.nvd_api_key = value.apiKey.trim();
      try {
        const saved = await systemConfigApi.patch(body, loadedRevision);
        form.reset(valuesFrom(saved));
        setLoadedRevision(saved.revision);
        qc.setQueryData(["system-config"], saved);
        toast.success("NVD settings saved");
        onClose();
      } catch (error) {
        const status = (error as { response?: { status?: number } })?.response?.status;
        setSaveError(status === 409 || status === 412 ? "Config changed elsewhere. Your edits are preserved; reload current settings before trying again." :
          "Could not save NVD settings. Your edits are preserved; please retry.");
        if (status === 409 || status === 412) void qc.invalidateQueries({ queryKey: ["system-config"] });
      }
    },
  });
  const dirty = useStore(form.store, (state) => state.isDirty);
  useEffect(() => {
    if (!dirty) {
      form.reset(savedValues);
      setLoadedRevision(data.revision);
    }
  }, [data.revision, savedValues, dirty, form]);
  useBlocker({ shouldBlockFn: () => form.state.isDirty && !window.confirm("Discard unsaved NVD settings?"), enableBeforeUnload: dirty });
  const hasKey = typeof data.config.nvd_api_key === "string" && data.config.nvd_api_key !== "";
  return <Card title="NVD import settings" description="Enrich recently modified CVEs on a schedule.">
    <form className="space-y-5" noValidate onSubmit={(event) => { event.preventDefault(); void form.handleSubmit(); }}>
      {(saveError || (dirty && loadedRevision !== data.revision)) && <div role="alert" className="space-y-2">
        <p>{saveError || "Settings changed elsewhere. Your unsaved edits are preserved."}</p>
        <Button type="button" onClick={() => { form.reset(savedValues); setLoadedRevision(data.revision); setSaveError(""); }}>Reload current settings</Button>
      </div>}
      <div className="rounded-lg border border-border bg-muted/30 px-4 py-3">
        <form.Field name="nvd_enabled">{(field) => <Switch checked={field.state.value} onCheckedChange={field.handleChange}
          label="Enable NVD import" description="Fetch descriptions and CVSS for recently modified CVEs." />}</form.Field>
      </div>
      <form.Field name="nvd_bootstrap_enabled">{(field) => <Switch checked={field.state.value} onCheckedChange={field.handleChange}
        label="Import historical NVD records" description="Requires NVD import enabled. Gradually imports older records, resuming after interruptions. Recent updates run first. This can take several scheduled cycles and uses additional bandwidth and storage." />}</form.Field>
      <form.AppField name="apiKey">{(field) => <field.TextField label="NVD API key" type="password" autoComplete="new-password"
        hint={hasKey ? "A key is already set — leave blank to keep it." : "Optional. Raises the NVD request rate limit."}
        placeholder={hasKey ? "••••••••" : "optional"} />}</form.AppField>
      <form.AppField name="nvd_mirror_url">{(field) => <field.TextField label="Mirror URL" type="url"
        hint="Optional internal NVD 2.0 mirror. Leave blank to use the public feed." placeholder="https://nvd-mirror.internal/rest/json/cves/2.0" />}</form.AppField>
      <div className="flex items-center gap-3">
        <form.AppForm><form.SubmitButton>Save changes</form.SubmitButton></form.AppForm>
        <Button type="button" variant="ghost" size="lg" onClick={onClose}>Cancel</Button>
      </div>
    </form>
  </Card>;
}
