import type { RegistryKind, RegistryAuthKind, RegistryScanPolicy, RegistryCadence, RegistryDTO } from "@/api/client";

export const KINDS: Array<{
  kind: RegistryKind;
  label: string;
  endpointHint: string;
  fields: Array<{ key: string; label: string; placeholder?: string; secret?: boolean; helper?: string }>;
}> = [
  { kind: "docker-hub", label: "Docker Hub", endpointHint: "https://registry-1.docker.io",
    fields: [
      { key: "username", label: "Username / namespace", placeholder: "myorg" },
      { key: "password", label: "Password / PAT", secret: true, helper: "Used for listing private repositories" },
    ] },
  { kind: "ghcr", label: "GitHub Container Registry", endpointHint: "https://ghcr.io",
    fields: [
      { key: "username", label: "GitHub owner / org", placeholder: "alphabravocompany" },
      { key: "token", label: "Personal Access Token", secret: true, helper: "scope: read:packages" },
    ] },
  { kind: "ecr", label: "Amazon ECR", endpointHint: "<account>.dkr.ecr.<region>.amazonaws.com",
    fields: [
      { key: "region", label: "AWS region", placeholder: "us-east-1" },
      { key: "role_arn", label: "IAM role ARN (assumed)", placeholder: "arn:aws:iam::123:role/constellation-ecr-reader" },
      { key: "access_key_id", label: "Access key ID", helper: "Static IAM keys (optional — else the ambient/role chain is used)" },
      { key: "secret_access_key", label: "Secret access key", secret: true },
    ] },
  { kind: "gcr", label: "Google Artifact Registry",
    endpointHint: "projects/<id>/locations/<region>/repositories/<repo>",
    fields: [
      { key: "resource_path", label: "GCP repo path", placeholder: "projects/myproj/locations/us-central1/repositories/main" },
      { key: "service_account_json", label: "Service-account JSON key", secret: true, helper: "Service-account key used by this connector" },
      { key: "token", label: "OAuth2 access token", secret: true, helper: "Alternative: a pre-acquired token (expires in ~1h)" },
    ] },
  { kind: "acr", label: "Azure Container Registry", endpointHint: "myregistry.azurecr.io",
    fields: [
      { key: "tenant_id", label: "Tenant ID" },
      { key: "client_id", label: "Client ID" },
      { key: "client_secret", label: "Client secret", secret: true },
      { key: "token", label: "Pre-acquired bearer token", secret: true, helper: "or paste a fresh `az acr login --expose-token` value" },
    ] },
  { kind: "quay", label: "Quay.io", endpointHint: "quay.io",
    fields: [
      { key: "username", label: "Namespace / robot account", placeholder: "myorg+robot" },
      { key: "token", label: "OAuth bearer token", secret: true },
    ] },
  { kind: "harbor", label: "Harbor (self-hosted)", endpointHint: "https://harbor.example.com",
    fields: [
      { key: "username", label: "Username" },
      { key: "password", label: "Password", secret: true },
    ] },
  { kind: "gitlab", label: "GitLab Container Registry", endpointHint: "https://gitlab.com",
    fields: [
      { key: "token", label: "Personal Access Token", secret: true, helper: "scope: read_registry" },
    ] },
  { kind: "jfrog", label: "JFrog Artifactory", endpointHint: "https://your.jfrog.io/artifactory",
    fields: [
      { key: "username", label: "Docker repo name", placeholder: "docker-local" },
      { key: "token", label: "API key", secret: true },
    ] },
  { kind: "generic-v2", label: "Docker Registry v2", endpointHint: "https://registry.example.com", fields: [{ key: "username", label: "Username" }, { key: "password", label: "Password", secret: true }] },
  { kind: "nexus", label: "Sonatype Nexus", endpointHint: "https://nexus.example.com", fields: [{ key: "username", label: "Username" }, { key: "password", label: "Password", secret: true }] },
  { kind: "openshift", label: "OpenShift registry", endpointHint: "https://registry.apps.example.com", fields: [{ key: "username", label: "Username" }, { key: "password", label: "Password", secret: true }, { key: "token", label: "OAuth token", secret: true }] },
  { kind: "ibmcloud", label: "IBM Cloud Container Registry", endpointHint: "https://icr.io", fields: [{ key: "account_id", label: "Account ID" }, { key: "password", label: "API key", secret: true }] },
];

export const AUTH_KINDS: RegistryAuthKind[] = ["static", "aws-iam-role", "gcp-service-account", "azure-managed-id", "none"];
export const CADENCES = ["manual", "auto", "hourly", "6h", "daily", "weekly", "custom", "cron"] as const;
export const PROMOTION_THRESHOLDS = ["critical", "high", "medium", "low", "none"];
export type RegistryScheduleMode = typeof CADENCES[number];

export function buildScanPolicy(
  includeRepos: string[],
  excludeReposRaw: string,
  tagSelection: RegistryScanPolicy["tag_selection"],
  maxAge: string,
  rescanInterval: string,
  rescanAfterDBUpdate: boolean,
  repoLimit: string,
  tagLimit: string,
  customInterval: string,
  cron: string,
  ignoreProxy: boolean,
  scanLayers: boolean,
  blockPromotionThreshold: string,
): RegistryScanPolicy {
  const excludeRepos = excludeReposRaw.split(/\n+/).map((s) => s.trim()).filter(Boolean);
  return {
    include_repos: includeRepos.length > 0 ? includeRepos : ["*"],
    exclude_repos: excludeRepos,
    tag_selection: tagSelection,
    max_age: maxAge.trim(),
    rescan_interval: rescanInterval.trim(),
    rescan_after_db_update: rescanAfterDBUpdate,
    repo_limit: parsePositiveInt(repoLimit),
    tag_limit: parsePositiveInt(tagLimit),
    custom_interval: customInterval.trim(),
    cron: cron.trim(),
    ignore_proxy: ignoreProxy,
    scan_layers: scanLayers,
    block_promotion_threshold: blockPromotionThreshold,
  };
}

function parsePositiveInt(value: string) {
  const n = Number.parseInt(value.trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

export function scheduleFromRegistry(row: RegistryDTO | null): {
  mode: RegistryScheduleMode;
  customInterval: string;
  cron: string;
} {
  const cadence = row?.scan_cadence?.trim() || "manual";
  if (cadence.startsWith("cron:")) {
    return { mode: "cron", customInterval: "", cron: cadence.slice("cron:".length).trim() };
  }
  if ((CADENCES as readonly string[]).includes(cadence) && cadence !== "custom" && cadence !== "cron") {
    return { mode: cadence as RegistryScheduleMode, customInterval: "", cron: "" };
  }
  return { mode: "custom", customInterval: row?.scan_policy?.custom_interval || cadence, cron: "" };
}

export function buildScanCadence(mode: RegistryScheduleMode, customInterval: string, cron: string): RegistryCadence {
  if (mode === "custom") return customInterval.trim() || "custom";
  if (mode === "cron") return `cron:${cron.trim()}`;
  return mode;
}


// Clearing authentication removes the saved secret; an untouched edit preserves it.
export function registryCredentialsForSave(authKind: RegistryAuthKind, credentials: Record<string, string>, editing: boolean) {
  if (authKind === "none") return editing ? {} : undefined;
  const entered = Object.fromEntries(Object.entries(credentials).filter(([, value]) => value !== ""));
  return editing && Object.keys(entered).length === 0 ? undefined : entered;
}
