import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { RefreshCw, Pencil, CheckCircle2, Circle } from "lucide-react";
import { toast } from "sonner";

import { systemConfigApi } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput } from "@/components/ui/form";

/**
 * Scanner & CVE Sources — vulnerability data health. Trivy/Grype DB freshness +
 * the live CVE-intelligence feeds (KEV / EPSS / NVD).
 */
export function ScannerSourcesPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const systemConfig = useQuery({ queryKey: ["system-config"], queryFn: () => systemConfigApi.get() });
  const config = systemConfig.data?.config ?? {};
  const revision = systemConfig.data?.revision ?? 0;
  const refreshMinutes = typeof config.scanner_db_refresh_minutes === "number" ? config.scanner_db_refresh_minutes : 0;
  const offlineDb = config.scanner_offline_db === true;
  const nvdEnabled = config.nvd_enabled === true;

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
        description="Vulnerability data health — the Trivy/Grype databases and CVE feeds that power image and host scanning."
      />

      <VerdictBanner
        status={offlineDb ? "info" : "ok"}
        title={offlineDb ? "Air-gapped — databases loaded from a local mirror" : "Scanners fed by live Trivy + Grype databases"}
        detail={refreshMinutes > 0 ? `Auto-refresh every ${refreshMinutes} minutes` : "Auto-refresh on the deploy default (every 6 hours)"}
      />

      <Card
        title="Database refresh"
        description="How often connected scanners pull the latest Trivy & Grype vulnerability databases."
        action={
          <Button
            variant="primary"
            size="sm"
            onClick={() => refreshNow.mutate()}
            disabled={refreshNow.isPending || offlineDb}
            title={offlineDb ? "Air-gapped — scanners can't pull from upstream" : "Force all scanners to pull the latest DBs now"}
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshNow.isPending ? "animate-spin" : ""}`} />
            Refresh now
          </Button>
        }
      >
        <div className="space-y-5">
          <Field
            label="Auto-refresh interval"
            hint="Minutes between automatic database refreshes. 0 uses the deploy default (6 hours)."
          >
            <div className="flex items-center gap-2">
              <TextInput
                type="number"
                min={0}
                defaultValue={refreshMinutes}
                key={`refresh-${revision}-${refreshMinutes}`}
                disabled={systemConfig.isLoading || updateRefresh.isPending}
                onBlur={(e) => {
                  const n = Number.parseInt(e.target.value, 10);
                  if (!Number.isNaN(n) && n !== refreshMinutes) updateRefresh.mutate(n);
                }}
                className="w-28"
                data-testid="scanner-db-refresh-minutes"
              />
              <span className="text-xs text-muted-foreground">minutes</span>
            </div>
          </Field>

          <div className="flex items-center justify-between gap-4 rounded-lg border border-border bg-muted/30 px-4 py-3">
            <div>
              <div className="text-sm font-medium text-foreground">Air-gapped mode</div>
              <div className="text-xs text-muted-foreground">Databases are pre-loaded; no upstream network pulls. Set at deploy time.</div>
            </div>
            <span
              className={`shrink-0 rounded-full px-2.5 py-1 text-[11px] font-medium ${
                offlineDb ? "bg-[color:var(--color-brand)]/10 text-[color:var(--color-brand)]" : "bg-muted text-muted-foreground"
              }`}
              data-testid="scanner-offline-db"
            >
              {offlineDb ? "On" : "Off"}
            </span>
          </div>
        </div>
      </Card>

      <Card
        title="CVE intelligence sources"
        description="Live feeds that populate the CVE Database with descriptions, severity, and exploitation intelligence."
        padded={false}
      >
        <div className="divide-y divide-border">
          <SourceRow name="CISA KEV" desc="Known-exploited vulnerabilities catalog" live />
          <SourceRow name="FIRST EPSS" desc="Exploit-probability scores, refreshed daily" live />
          <SourceRow
            name="NVD"
            desc="Full CVE catalog — descriptions + CVSS base scores"
            live={nvdEnabled}
            action={
              <Button variant="outline" size="sm" onClick={() => navigate("/settings/scanner/nvd")}>
                <Pencil className="h-3.5 w-3.5" /> Configure
              </Button>
            }
          />
        </div>
      </Card>
    </div>
  );
}

function SourceRow({ name, desc, live, action }: { name: string; desc: string; live: boolean; action?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 px-5 py-3.5">
      <div className="flex min-w-0 items-center gap-3">
        {live ? (
          <CheckCircle2 className="h-4 w-4 shrink-0 text-[color:var(--color-status-success)]" />
        ) : (
          <Circle className="h-4 w-4 shrink-0 text-muted-foreground/40" />
        )}
        <div className="min-w-0">
          <div className="text-sm font-medium text-foreground">{name}</div>
          <div className="truncate text-xs text-muted-foreground">{desc}</div>
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        <span className={`text-[11px] font-medium ${live ? "text-[color:var(--color-status-success)]" : "text-muted-foreground"}`}>
          {live ? "Live" : "Off"}
        </span>
        {action}
      </div>
    </div>
  );
}
