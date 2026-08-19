import { RefreshCw, Pencil } from "lucide-react";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { systemConfigApi } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Drawer } from "@/components/ui/drawer";

/**
 * Scanner & CVE Sources — the single home for "scanner data health" (plan §3.2).
 * Replaces the deleted VulnDB bbolt admin page. Surfaces Trivy/Grype DB freshness
 * controls + air-gap mode. The live CVE-intelligence source status (NVD/KEV/EPSS,
 * plan §3.1) will render here once that importer lands.
 */
export function ScannerSourcesPage() {
  const qc = useQueryClient();
  const systemConfig = useQuery({ queryKey: ["system-config"], queryFn: () => systemConfigApi.get() });
  const config = systemConfig.data?.config ?? {};
  const revision = systemConfig.data?.revision ?? 0;
  const refreshMinutes = typeof config.scanner_db_refresh_minutes === "number" ? config.scanner_db_refresh_minutes : 0;
  const offlineDb = config.scanner_offline_db === true;
  const nvdEnabled = config.nvd_enabled === true;
  const [nvdOpen, setNvdOpen] = useState(false);

  const refreshNow = useMutation({
    mutationFn: () => systemConfigApi.refreshScanner(),
    onSuccess: () => toast.success("Refresh requested — connected scanners will pull the latest DBs shortly"),
    onError: () => toast.error("Failed to request refresh"),
  });
  const updateRefresh = useMutation({
    mutationFn: (minutes: number) => systemConfigApi.patch({ scanner_db_refresh_minutes: minutes }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["system-config"] });
      toast.success("Scanner DB refresh interval updated");
    },
    onError: (error: unknown) => {
      const status = (error as { response?: { status?: number } })?.response?.status;
      if (status === 409) {
        void qc.invalidateQueries({ queryKey: ["system-config"] });
        toast.error("Config changed elsewhere; reloaded latest — please retry.");
        return;
      }
      toast.error("Failed to update scanner DB refresh interval");
    },
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scanner & CVE Sources"
        description="Vulnerability data health — the Trivy/Grype databases that power image and host scanning."
      />

      <VerdictBanner
        status={offlineDb ? "info" : "ok"}
        title={offlineDb ? "Air-gapped mode — databases updated from a local mirror" : "Scanners fed by live Trivy + Grype databases"}
        detail={
          refreshMinutes > 0
            ? `Refreshing every ${refreshMinutes} min`
            : "Refreshing on the deploy default (6h)"
        }
      />

      <section className="rounded-lg border border-border bg-card p-4">
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-sm font-medium">Database refresh</h2>
          <button
            type="button"
            onClick={() => refreshNow.mutate()}
            disabled={refreshNow.isPending || offlineDb}
            title={offlineDb ? "Air-gapped mode — scanners can't pull from upstream" : "Force all scanners to pull the latest DBs now"}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-primary px-2.5 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshNow.isPending ? "animate-spin" : ""}`} />
            Refresh now
          </button>
        </div>
        <div className="mt-3 space-y-3 text-xs text-muted-foreground">
          <label className="flex items-center justify-between gap-2">
            <span className="text-foreground">Refresh interval (minutes)</span>
            <input
              type="number"
              min={0}
              defaultValue={refreshMinutes}
              key={`refresh-${revision}-${refreshMinutes}`}
              disabled={systemConfig.isLoading || updateRefresh.isPending}
              onBlur={(e) => {
                const n = Number.parseInt(e.target.value, 10);
                if (!Number.isNaN(n) && n !== refreshMinutes) updateRefresh.mutate(n);
              }}
              className="w-24 rounded-md border border-border bg-card px-2 py-1 text-xs disabled:opacity-50"
              data-testid="scanner-db-refresh-minutes"
            />
          </label>
          <p>How often connected scanners refresh their Trivy/Grype databases. 0 = use the deploy default (6h).</p>
          <div className="flex items-center justify-between gap-2 rounded-md border border-border p-3">
            <span className="text-foreground">Air-gapped DB mode</span>
            <span
              className={`rounded-md px-2 py-1 text-[10px] ${offlineDb ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground"}`}
              data-testid="scanner-offline-db"
            >
              {offlineDb ? "on" : "off"}
            </span>
          </div>
          <p>Set at deploy time via environment; display-only here.</p>
        </div>
      </section>

      <section className="rounded-lg border border-border bg-card p-4">
        <h2 className="text-sm font-medium">CVE intelligence sources</h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Live feeds that populate the CVE Database with exploitation intelligence.
        </p>
        <div className="mt-3 space-y-2">
          <SourceRow name="CISA KEV" desc="Known-exploited vulnerabilities catalog" status="live" />
          <SourceRow name="FIRST EPSS" desc="Exploit-probability scores (daily)" status="live" />
          <div className="flex items-center justify-between gap-2 rounded-md border border-border p-3">
            <div className="min-w-0">
              <div className="text-sm font-medium">NVD</div>
              <div className="truncate text-xs text-muted-foreground">Full CVE catalog — descriptions + CVSS base scores</div>
            </div>
            <div className="flex items-center gap-2">
              <span className={`shrink-0 rounded-md px-2 py-1 text-[10px] ${nvdEnabled ? "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]" : "bg-muted text-muted-foreground"}`}>
                {nvdEnabled ? "enabled" : "off"}
              </span>
              <button type="button" onClick={() => setNvdOpen(true)} className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs hover:bg-accent">
                <Pencil className="h-3 w-3" /> Configure
              </button>
            </div>
          </div>
        </div>
      </section>

      <NvdConfigDrawer
        open={nvdOpen}
        onOpenChange={setNvdOpen}
        enabled={nvdEnabled}
        hasKey={typeof config.nvd_api_key === "string" && config.nvd_api_key !== ""}
        mirror={typeof config.nvd_mirror_url === "string" ? config.nvd_mirror_url : ""}
        onSaved={() => void qc.invalidateQueries({ queryKey: ["system-config"] })}
      />
    </div>
  );
}

function NvdConfigDrawer({ open, onOpenChange, enabled, hasKey, mirror, onSaved }: {
  open: boolean; onOpenChange: (o: boolean) => void; enabled: boolean; hasKey: boolean; mirror: string; onSaved: () => void;
}) {
  const [en, setEn] = useState(enabled);
  const [apiKey, setApiKey] = useState("");
  const [mir, setMir] = useState(mirror);
  const save = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = { nvd_enabled: en, nvd_mirror_url: mir.trim() };
      if (apiKey.trim()) body.nvd_api_key = apiKey.trim(); // omit to keep existing key
      return systemConfigApi.patch(body);
    },
    onSuccess: () => { toast.success("NVD settings saved"); onOpenChange(false); onSaved(); },
    onError: () => toast.error("Failed to save NVD settings"),
  });
  return (
    <Drawer open={open} onOpenChange={onOpenChange} title="NVD full CVE catalog" description="Import CVE descriptions + CVSS from the NVD 2.0 feed. An API key raises the rate limit.">
      <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
        <label className="flex items-center justify-between gap-2 rounded-md border border-border p-3 text-sm">
          <span>Enable NVD import</span>
          <input type="checkbox" checked={en} onChange={(e) => setEn(e.target.checked)} />
        </label>
        <label className="block text-xs font-medium">NVD API key {hasKey && <span className="text-muted-foreground">(set — leave blank to keep)</span>}
          <input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder={hasKey ? "••••••••" : "optional"} className="mt-1 w-full rounded-md border border-border bg-background p-2 text-sm" />
        </label>
        <label className="block text-xs font-medium">Mirror URL (air-gapped, optional)
          <input value={mir} onChange={(e) => setMir(e.target.value)} placeholder="https://nvd-mirror.internal/rest/json/cves/2.0" className="mt-1 w-full rounded-md border border-border bg-background p-2 text-sm" />
        </label>
        <button type="submit" disabled={save.isPending} className="w-full rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50">{save.isPending ? "Saving…" : "Save"}</button>
      </form>
    </Drawer>
  );
}

function SourceRow({ name, desc, status }: { name: string; desc: string; status: "live" | "planned" }) {
  return (
    <div className="flex items-center justify-between gap-2 rounded-md border border-border p-3">
      <div className="min-w-0">
        <div className="text-sm font-medium">{name}</div>
        <div className="truncate text-xs text-muted-foreground">{desc}</div>
      </div>
      <span
        className={`shrink-0 rounded-md px-2 py-1 text-[10px] ${
          status === "live"
            ? "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]"
            : "bg-muted text-muted-foreground"
        }`}
      >
        {status}
      </span>
    </div>
  );
}
