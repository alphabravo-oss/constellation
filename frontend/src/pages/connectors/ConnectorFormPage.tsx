import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft } from "lucide-react";

import { connectorCoverage } from "@/api/client";
import type { ConnectorCoverageOverview } from "@/api/client";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { Button } from "@/components/ui/button";
import { Field, TextInput as FormTextInput, Select } from "@/components/ui/form";

type RegistryConnector = ConnectorCoverageOverview["registry_connectors"][number];

// The connector-config form state; shared by add + edit.
type ConfigFormState = {
  connector_id: string;
  connector_type: "registry" | "cloud";
  provider: string;
  display_name: string;
  endpoint: string;
  auth_mode: string;
  owner: string;
  scan_cadence: string;
  rotation_due_at: string;
  credential_ref: string;
};

function blankConfig(type: "registry" | "cloud"): ConfigFormState {
  return {
    connector_id: "",
    connector_type: type,
    provider: "",
    display_name: "",
    endpoint: "",
    auth_mode: "",
    owner: "",
    scan_cadence: "daily",
    rotation_due_at: "",
    credential_ref: "",
  };
}

// Pre-fill the config form for an existing registry connector, merging any saved
// metadata (owner / cadence / rotation / credential ref) that already exists.
function configFromRegistry(connector: RegistryConnector, configs: ConnectorCoverageOverview["configs"]): ConfigFormState {
  const saved = configs.find((c) => c.connector_id === connector.id && c.connector_type === "registry");
  return {
    connector_id: connector.id,
    connector_type: "registry",
    provider: connector.provider,
    display_name: connector.name,
    endpoint: connector.endpoint,
    auth_mode: connector.auth_mode,
    owner: saved?.owner ?? "",
    scan_cadence: saved?.scan_cadence ?? "daily",
    rotation_due_at: saved?.rotation_due_at ? saved.rotation_due_at.slice(0, 10) : "",
    credential_ref: saved?.credential_ref ?? "",
  };
}

/**
 * ConnectorFormPage — /settings/connectors/new and /settings/connectors/:id. A
 * dedicated form page (the Astronomer add/edit-as-a-page pattern, replacing the old
 * ConnectorConfigDrawer). Saves connector metadata and an external secret reference;
 * raw credentials are never accepted by this API. Add mode picks a registry or cloud
 * account (?type=); edit mode (:id) pre-fills an existing registry connector.
 */
export function ConnectorFormPage() {
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const q = useQuery({ queryKey: ["connector-coverage"], queryFn: connectorCoverage.overview });

  if (q.isPending) return <p className="text-sm text-muted-foreground">Loading connector coverage...</p>;

  const data = q.data;
  const registryConnectors = data?.registry_connectors ?? [];
  const cloudConnectors = data?.cloud_connectors ?? [];
  const configs = data?.configs ?? [];

  // Editing is registry-only (matching the old drawer's Edit affordance); add can be
  // either registry or cloud via ?type=.
  const editing = Boolean(id);
  const editConnector = editing ? registryConnectors.find((c) => c.id === id) : undefined;
  const connectorType: "registry" | "cloud" = editing
    ? "registry"
    : searchParams.get("type") === "cloud"
      ? "cloud"
      : "registry";
  const initial = editConnector ? configFromRegistry(editConnector, configs) : null;

  const registryOptions = registryConnectors.map((c) => ({ id: c.id, name: c.name, provider: c.provider, endpoint: c.endpoint, auth_mode: c.auth_mode }));
  const cloudOptions = cloudConnectors.map((c) => ({ id: c.id, name: c.name, provider: c.provider, endpoint: c.account, auth_mode: c.auth_mode }));
  const connectors = connectorType === "cloud" ? cloudOptions : registryOptions;

  return (
    <ConnectorFormInner
      connectorType={connectorType}
      connectors={connectors}
      initial={initial}
      editing={editing}
    />
  );
}

function ConnectorFormInner({
  connectorType,
  connectors,
  initial,
  editing,
}: {
  connectorType: "registry" | "cloud";
  connectors: Array<{ id: string; name: string; provider: string; endpoint: string; auth_mode: string }>;
  initial: ConfigFormState | null;
  editing: boolean;
}) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<ConfigFormState>(() => initial ?? blankConfig(connectorType));

  const noun = connectorType === "registry" ? "registry" : "cloud account";
  const backTab = connectorType === "cloud" ? "clouds" : "registries";
  const backTo = `/settings/connectors?tab=${backTab}`;

  const save = useMutation({
    mutationFn: () => {
      const rotation_due_at = form.rotation_due_at
        ? new Date(`${form.rotation_due_at}T00:00:00Z`).toISOString()
        : undefined;
      return connectorCoverage.saveConfig({ ...form, rotation_due_at });
    },
    onSuccess: () => {
      toast.success("Connector metadata saved");
      void queryClient.invalidateQueries({ queryKey: ["connector-coverage"] });
      navigate(backTo);
    },
    onError: () => toast.error("Unable to save connector metadata"),
  });

  const canSave = Boolean(form.connector_id && form.display_name && form.endpoint && form.auth_mode && form.owner);

  return (
    <PageContainer>
      <PageHeader
        title={`${editing ? "Edit" : "Add"} ${noun}`}
        description="Save connector metadata and an external secret reference. Raw credentials are never accepted by this API."
        backLink={<Link to={backTo} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Connectors</Link>}
      />

      <Card title={`${connectorType === "registry" ? "Registry" : "Cloud account"} details`}>
        <form
          className="space-y-5"
          data-testid="connector-config-editor"
          onSubmit={(event) => { event.preventDefault(); if (canSave && !save.isPending) save.mutate(); }}
        >
          <p className="rounded-md border border-border bg-muted px-3 py-2 text-xs text-muted-foreground">
            Raw credentials are never accepted. Store secrets in an external vault and save only the reference here.
          </p>
          <Field label={connectorType === "registry" ? "Registry" : "Cloud account"}>
            <Select
              value={form.connector_id}
              onChange={(event) => {
                const connector = connectors.find((item) => item.id === event.target.value);
                if (!connector) {
                  setForm((current) => ({ ...current, connector_id: "", provider: "", display_name: "", endpoint: "", auth_mode: "" }));
                  return;
                }
                setForm((current) => ({
                  ...current,
                  connector_id: connector.id,
                  connector_type: connectorType,
                  provider: connector.provider,
                  display_name: connector.name,
                  endpoint: connector.endpoint,
                  auth_mode: connector.auth_mode,
                }));
              }}
              data-testid="connector-config-id"
            >
              <option value="">Select {noun}</option>
              {connectors.map((connector) => (
                <option key={connector.id} value={connector.id}>{connector.name}</option>
              ))}
            </Select>
          </Field>
          <TextInput label="Owner" value={form.owner} onChange={(owner) => setForm((current) => ({ ...current, owner }))} testID="connector-config-owner" />
          <TextInput label="Endpoint" value={form.endpoint} onChange={(endpoint) => setForm((current) => ({ ...current, endpoint }))} />
          <TextInput label="Auth mode" value={form.auth_mode} onChange={(auth_mode) => setForm((current) => ({ ...current, auth_mode }))} />
          <TextInput label="Credential ref" value={form.credential_ref} onChange={(credential_ref) => setForm((current) => ({ ...current, credential_ref }))} testID="connector-config-credential-ref" />
          <Collapse label="Advanced">
            <div className="space-y-5">
              <Field label="Scan cadence">
                <Select
                  value={form.scan_cadence}
                  onChange={(event) => setForm((current) => ({ ...current, scan_cadence: event.target.value }))}
                >
                  <option value="hourly">hourly</option>
                  <option value="daily">daily</option>
                  <option value="weekly">weekly</option>
                </Select>
              </Field>
              <Field label="Rotation due">
                <FormTextInput
                  type="date"
                  value={form.rotation_due_at}
                  onChange={(event) => setForm((current) => ({ ...current, rotation_due_at: event.target.value }))}
                />
              </Field>
            </div>
          </Collapse>
          <div className="flex items-center gap-3">
            <Button
              type="submit"
              variant="primary"
              size="lg"
              disabled={save.isPending || !canSave}
              data-testid="connector-config-save"
            >
              {save.isPending ? "Saving…" : "Save metadata"}
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
