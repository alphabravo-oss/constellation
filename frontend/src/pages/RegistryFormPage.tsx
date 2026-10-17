import { useState, type ChangeEvent } from "react";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft } from "lucide-react";
import { registries as registriesApi, type RegistryDTO, type RegistryKind, type RegistryAuthKind, type RegistryCreateBody, type RegistryScanPolicy } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { useCluster } from "@/hooks/useCluster";
import { KINDS, AUTH_KINDS, CADENCES, PROMOTION_THRESHOLDS, type RegistryScheduleMode, buildScanPolicy, scheduleFromRegistry, buildScanCadence, registryCredentialsForSave } from "@/lib/registry-form";

export function RegistryFormPage() {
  const { regId } = useParams({ strict: false });
  const { clusterId, isLoading } = useCluster();
  const navigate = useNavigate();
  const q = useQuery({ queryKey: ["registry", regId], queryFn: () => registriesApi.get(regId!), enabled: !!regId });
  const back = `/clusters/${clusterId}/registries`;
  if (isLoading || (regId && q.isPending)) return <p>Loading registry...</p>;
  if (regId && (q.isError || !q.data)) return <div className="space-y-4"><p role="alert">Registry could not be loaded.</p><Link to="." href={back}>Back to registries</Link></div>;
  return <div className="space-y-4" data-testid="registry-form-page">
    <PageHeader title={regId ? `Edit registry — ${q.data!.name}` : "Add container registry"}
      description="Save the connection and scan schedule. Test the saved connection from the registry list."
      backLink={<Link to="." href={back} className="inline-flex items-center gap-1"><ChevronLeft className="h-4 w-4" />Registries</Link>} />
    <Card><RegistryForm key={regId ?? "new"} editing={regId ? q.data! : null} onSaved={() => void navigate({ href: back })} onCancel={() => void navigate({ href: back })} /></Card>
  </div>;
}

function RegistryForm({ editing, onSaved, onCancel }: { editing: RegistryDTO | null; onSaved: () => void; onCancel: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState(editing?.name ?? "");
  const [kind, setKind] = useState<RegistryKind>(editing?.kind ?? "docker-hub");
  const [endpoint, setEndpoint] = useState(editing?.endpoint ?? "");
  const [authKind, setAuthKind] = useState<RegistryAuthKind>(editing?.auth_kind ?? "static");
  const initialSchedule = scheduleFromRegistry(editing);
  const [scheduleMode, setScheduleMode] = useState<RegistryScheduleMode>(initialSchedule.mode);
  const [customInterval, setCustomInterval] = useState(initialSchedule.customInterval);
  const [cron, setCron] = useState(initialSchedule.cron);
  const [globs, setGlobs] = useState<string>(editing?.image_globs?.join("\n") ?? "");
  const [excludeGlobs, setExcludeGlobs] = useState<string>(editing?.scan_policy?.exclude_repos?.join("\n") ?? "");
  const [tagSelection, setTagSelection] = useState<RegistryScanPolicy["tag_selection"]>(editing?.scan_policy?.tag_selection ?? "all");
  const [maxAge, setMaxAge] = useState(editing?.scan_policy?.max_age ?? "");
  const [rescanInterval, setRescanInterval] = useState(editing?.scan_policy?.rescan_interval ?? "");
  const [rescanAfterDBUpdate, setRescanAfterDBUpdate] = useState(editing?.scan_policy?.rescan_after_db_update ?? true);
  const [repoLimit, setRepoLimit] = useState(String(editing?.scan_policy?.repo_limit || ""));
  const [tagLimit, setTagLimit] = useState(String(editing?.scan_policy?.tag_limit || ""));
  const [ignoreProxy, setIgnoreProxy] = useState(editing?.scan_policy?.ignore_proxy ?? false);
  const [scanLayers, setScanLayers] = useState(editing?.scan_policy?.scan_layers ?? true);
  const [promotionThreshold, setPromotionThreshold] = useState(editing?.scan_policy?.block_promotion_threshold ?? "critical");
  const [creds, setCreds] = useState<Record<string, string>>({});
  const kindMeta = KINDS.find((k) => k.kind === kind);

  const save = useMutation({
    mutationFn: async () => {
      const parsedGlobs = globs.split(/\n+/).map((s) => s.trim()).filter(Boolean);
      const scanPolicy = buildScanPolicy(
        parsedGlobs,
        excludeGlobs,
        tagSelection,
        maxAge,
        rescanInterval,
        rescanAfterDBUpdate,
        repoLimit,
        tagLimit,
        scheduleMode === "custom" ? customInterval : "",
        scheduleMode === "cron" ? cron : "",
        ignoreProxy,
        scanLayers,
        promotionThreshold,
      );
      const resolvedCadence = buildScanCadence(scheduleMode, customInterval, cron);
      const body: RegistryCreateBody = {
        name,
        kind,
        endpoint,
        auth_kind: authKind,
        credentials: registryCredentialsForSave(authKind, creds, false),
        scan_cadence: resolvedCadence,
        image_globs: parsedGlobs,
        scan_policy: scanPolicy,
      };
      if (editing) {
        await registriesApi.update(editing.id, {
          name,
          endpoint,
          auth_kind: authKind,
          credentials: registryCredentialsForSave(authKind, creds, true),
          scan_cadence: resolvedCadence,
          image_globs: parsedGlobs,
          scan_policy: scanPolicy,
        });
        return editing.id;
      }
      const r = await registriesApi.create(body);
      return r.id;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["registries"] });
      if (editing) qc.invalidateQueries({ queryKey: ["registry", editing.id] });
      onSaved();
    },
  });

  return (
    <form onSubmit={(event) => { event.preventDefault(); save.mutate(); }} data-testid="registry-form">
      <div className="mt-4 grid gap-3">
        <Row label="Name">
          <input
            className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            required
            value={name}
            onChange={(e: ChangeEvent<HTMLInputElement>) => setName(e.target.value)}
            placeholder="prod-ecr-us-east-1"
          />
        </Row>

        {!editing && (
          <Row label="Kind">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
              {KINDS.map((k) => (
                <button
                  key={k.kind}
                  type="button"
                  onClick={() => { setKind(k.kind); setEndpoint(k.endpointHint); setCreds({}); }}
                  className={
                    "rounded-md border px-2 py-2 text-left text-xs transition-colors " +
                    (kind === k.kind
                      ? "border-[color:var(--color-primary)] bg-accent"
                      : "border-border hover:bg-accent")
                  }
                  data-testid={`kind-${k.kind}`}
                >
                  <div className="font-medium">{k.label}</div>
                  <div className="text-xs text-muted-foreground text-mono truncate">{k.kind}</div>
                </button>
              ))}
            </div>
          </Row>
        )}

        <Row label="Endpoint">
          <input
            className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            required
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder={kindMeta?.endpointHint}
          />
        </Row>

        <Row label="Auth">
          <select
            className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            value={authKind}
            onChange={(e) => setAuthKind(e.target.value as RegistryAuthKind)}
          >
            {AUTH_KINDS.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
        </Row>

        {authKind !== "none" && kindMeta && (
          <div className="rounded-md border border-border bg-card p-3 space-y-2">
            <div className="text-sm uppercase tracking-wider text-muted-foreground">
              Credentials for {kindMeta.label}
            </div>
            {editing?.has_secret && <p className="text-xs text-muted-foreground">Leave all fields blank to keep saved credentials. To replace them, enter the complete credential set.</p>}
            {kindMeta.fields.map((f) => (
              <Row key={f.key} label={f.label}>
                <input
                  className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  type={f.secret ? "password" : "text"}
                  value={creds[f.key] ?? ""}
                  onChange={(e) => setCreds({ ...creds, [f.key]: e.target.value })}
                  placeholder={f.placeholder} autoComplete={f.secret ? "new-password" : "off"}
                />
                {f.helper && <div className="text-xs text-muted-foreground mt-0.5">{f.helper}</div>}
              </Row>
            ))}
          </div>
        )}

        <Row label="Scan cadence">
          <select
            className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            value={scheduleMode}
            onChange={(e) => setScheduleMode(e.target.value as RegistryScheduleMode)}
          >
            {CADENCES.map((c) => (
              <option key={c} value={c}>
                {c === "custom" ? "custom interval" : c === "cron" ? "cron schedule" : c}
              </option>
            ))}
          </select>
        </Row>

        {scheduleMode === "custom" && (
          <Row label="Custom interval">
            <input
              className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={customInterval}
              onChange={(e) => setCustomInterval(e.target.value)}
              placeholder="12h"
            />
          </Row>
        )}

        {scheduleMode === "cron" && (
          <Row label="Cron">
            <input
              className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={cron}
              onChange={(e) => setCron(e.target.value)}
              placeholder="0 2 * * *"
            />
          </Row>
        )}

        <Row label="Image globs (one per line)">
          <textarea
            className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm min-h-[64px] font-mono"
            value={globs}
            onChange={(e) => setGlobs(e.target.value)}
            placeholder={"myorg/*\napp:v[0-9]*"}
          />
        </Row>

        <Collapse label="Advanced scan settings">
        <div className="grid gap-3 rounded-md border border-border bg-card p-3 md:grid-cols-2">
          <Row label="Exclude repos">
            <textarea
              className="block min-h-[58px] w-full rounded-md border border-input bg-background px-2 py-1.5 font-mono text-xs"
              value={excludeGlobs}
              onChange={(e) => setExcludeGlobs(e.target.value)}
              placeholder={"*/scratch\n*/experimental-*"}
            />
          </Row>
          <Row label="Tag selection">
            <select
              className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={tagSelection}
              onChange={(e) => setTagSelection(e.target.value as RegistryScanPolicy["tag_selection"])}
            >
              <option value="all">all tags</option>
              <option value="latest">latest tag only</option>
            </select>
          </Row>
          <Row label="Max image age">
            <input
              className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={maxAge}
              onChange={(e) => setMaxAge(e.target.value)}
              placeholder="720h"
            />
          </Row>
          <Row label="Rescan interval">
            <input
              className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={rescanInterval}
              onChange={(e) => setRescanInterval(e.target.value)}
              placeholder="168h"
            />
          </Row>
          <Row label="Repo limit">
            <input
              className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={repoLimit}
              onChange={(e) => setRepoLimit(e.target.value)}
              type="number" min={1} step={1}
              inputMode="numeric"
              placeholder="unlimited"
            />
          </Row>
          <Row label="Tag limit">
            <input
              className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={tagLimit}
              onChange={(e) => setTagLimit(e.target.value)}
              type="number" min={1} step={1}
              inputMode="numeric"
              placeholder="unlimited"
            />
          </Row>
          <Row label="Promotion threshold">
            <select
              className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={promotionThreshold}
              onChange={(e) => setPromotionThreshold(e.target.value)}
            >
              {PROMOTION_THRESHOLDS.map((threshold) => (
                <option key={threshold} value={threshold}>{threshold}</option>
              ))}
            </select>
          </Row>
          <label className="flex min-h-[54px] items-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm">
            <input
              type="checkbox"
              checked={rescanAfterDBUpdate}
              onChange={(e) => setRescanAfterDBUpdate(e.target.checked)}
            />
            <span>Rescan after DB update</span>
          </label>
          <label className="flex min-h-[54px] items-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm">
            <input
              type="checkbox"
              checked={ignoreProxy}
              onChange={(e) => setIgnoreProxy(e.target.checked)}
            />
            <span>Ignore proxy</span>
          </label>
          <label className="flex min-h-[54px] items-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm">
            <input
              type="checkbox"
              checked={scanLayers}
              onChange={(e) => setScanLayers(e.target.checked)}
            />
            <span>Scan layers</span>
          </label>
        </div>

        </Collapse>
        {save.isError && <p role="alert" className="text-sm text-status-error">Could not save registry. Check the connection and scan settings, then try again.</p>}
      </div>

      <div className="mt-5 flex items-center justify-end gap-2">
        <button type="button" onClick={onCancel} disabled={save.isPending} className="rounded-md border border-border px-3 py-2 text-sm">Cancel</button>
        <button
          type="submit"
          disabled={save.isPending}
          className="rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
          data-testid="registry-save"
        >
          {save.isPending ? "Saving…" : editing ? "Save" : "Create"}
        </button>
      </div>
    </form>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="grid gap-1">
      <span className="text-sm text-muted-foreground">{label}</span>
      {children}
    </label>
  );
}
