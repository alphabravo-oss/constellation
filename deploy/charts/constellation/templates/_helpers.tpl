{{/*
Common template helpers for the Constellation chart.
*/}}

{{- define "constellation.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Revision-aware node spreading for replicated application Deployments. The
pod-template-hash matchLabelKey prevents an old ReplicaSet from masking an
imbalanced new rollout.
Args: dict of "ctx" (root) and "component".
*/}}
{{- define "constellation.haTopologySpread" -}}
{{- $ctx := .ctx -}}
{{- if $ctx.Values.highAvailability.enabled }}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: {{ $ctx.Values.highAvailability.topologyKey | quote }}
    whenUnsatisfiable: {{ $ctx.Values.highAvailability.whenUnsatisfiable }}
    matchLabelKeys:
      - pod-template-hash
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: {{ include "constellation.name" $ctx }}
        app.kubernetes.io/component: {{ .component }}
{{- end }}
{{- end -}}

{{- define "constellation.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "constellation.labels" -}}
app.kubernetes.io/name: {{ include "constellation.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: constellation
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "constellation.imageTag" -}}
{{- default (printf "v%s" (trimPrefix "v" .Chart.AppVersion)) .Values.image.tag -}}
{{- end -}}

{{/*
constellation.roleImage returns the fully qualified image for a given role.

Default convention: <image.registry>/<role>:<image.tag-or-v-prefixed-appVersion>
A role can override repository, tag, or digest via .Values.<role>.image.
A digest takes precedence over tags and is specific to one role.

Args: dict of "ctx" (root) and "role" (key under .Values, e.g. "api").
The role name used in the default path is the kebab-case form of the key.
*/}}
{{- define "constellation.roleImage" -}}
{{- $ctx := .ctx -}}
{{- $role := .role -}}
{{- $top := index $ctx.Values $role -}}
{{- /* Kebab-case role name for the default image path. */ -}}
{{- $rolePath := $role -}}
{{- if eq $role "runtimeAgent" -}}{{- $rolePath = "runtime-agent" -}}{{- end -}}
{{- if eq $role "complianceScheduler" -}}{{- $rolePath = "compliance-scheduler" -}}{{- end -}}
{{- if eq $role "auditArchiver" -}}{{- $rolePath = "audit-archiver" -}}{{- end -}}
{{- $registry := $ctx.Values.image.registry | default "ghcr.io/alphabravo-oss/constellation" -}}
{{- if $ctx.Values.fips.enabled -}}{{- $registry = $ctx.Values.fips.registry -}}{{- end -}}
{{- /* Air-gap (guide ch.09): global.imageRegistry is the cluster-local registry every
       role image is pulled from; it overrides image.registry and fips.registry.
       Paths keep the upstream layout so `constellationctl bundle load` targets match. */ -}}
{{- if $ctx.Values.global.imageRegistry -}}{{- $registry = printf "%s/alphabravo-oss/constellation" (trimSuffix "/" $ctx.Values.global.imageRegistry) -}}{{- end -}}
{{- $repo := printf "%s/%s" $registry $rolePath -}}
{{- $tag := include "constellation.imageTag" $ctx -}}
{{- $digest := "" -}}
{{- if and $top (kindIs "map" $top) (hasKey $top "image") -}}
  {{- $img := index $top "image" -}}
  {{- if and (kindIs "map" $img) $img.repository -}}
    {{- $repo = $img.repository -}}
  {{- end -}}
  {{- if and (kindIs "map" $img) $img.tag -}}
    {{- $tag = $img.tag -}}
  {{- end -}}
  {{- if and (kindIs "map" $img) $img.digest -}}
    {{- $digest = $img.digest -}}
  {{- end -}}
{{- end -}}
{{- if $digest -}}
  {{- if not (regexMatch "^sha256:[a-f0-9]{64}$" $digest) -}}
    {{- fail (printf "%s.image.digest must be a lowercase sha256 digest" $role) -}}
  {{- end -}}
  {{- printf "%s@%s" $repo $digest -}}
{{- else -}}
  {{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end -}}

{{/*
constellation.pullSecrets renders an imagePullSecrets list (only if .Values.image.pullSecrets is non-empty).
*/}}
{{- define "constellation.pullSecrets" -}}
{{- with .Values.image.pullSecrets -}}
imagePullSecrets:
{{- range . }}
  - name: {{ .name }}
{{- end }}
{{- end -}}
{{- end -}}

{{/*
constellation.podSecurityContext renders the default pod-level hardening block
for non-privileged workloads.
*/}}
{{- define "constellation.podSecurityContext" -}}
{{- if .Values.security.podSecurityContext.enabled -}}
{{- $ctx := omit .Values.security.podSecurityContext "enabled" -}}
{{- if $ctx }}
securityContext:
{{- toYaml $ctx | nindent 2 }}
{{- end }}
{{- end -}}
{{- end -}}

{{/*
constellation.containerSecurityContext renders the default container-level
hardening block for non-privileged workloads.
*/}}
{{- define "constellation.containerSecurityContext" -}}
{{- if .Values.security.containerSecurityContext.enabled -}}
{{- $ctx := omit .Values.security.containerSecurityContext "enabled" -}}
{{- if $ctx }}
securityContext:
{{- toYaml $ctx | nindent 2 }}
{{- end }}
{{- end -}}
{{- end -}}

{{/*
constellation.helperPodSecurityContext renders hardening that is safe for
third-party helper images with unknown default users.
*/}}
{{- define "constellation.helperPodSecurityContext" -}}
securityContext:
  seccompProfile:
    type: RuntimeDefault
{{- end -}}

{{/*
constellation.helperContainerSecurityContext renders restricted container
settings for helper images used by hook jobs.
*/}}
{{- define "constellation.helperContainerSecurityContext" -}}
securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
  readOnlyRootFilesystem: true
  runAsGroup: 10001
  runAsNonRoot: true
  runAsUser: 10001
{{- end -}}

{{/*
NetworkPolicy egress helpers. Native NetworkPolicy cannot select Kubernetes API
or external managed services by Service name, so those destinations are
operator-supplied CIDR blocks in values.
*/}}
{{- define "constellation.networkPolicyDNSEgress" -}}
{{- if .Values.networkPolicies.dns.enabled }}
- to:
{{- range .Values.networkPolicies.dns.cidrs }}
    - ipBlock:
        cidr: {{ . | quote }}
{{- end }}
  ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
{{- end -}}
{{- end -}}

{{- define "constellation.networkPolicyExternalHTTPEgress" -}}
{{- if .Values.networkPolicies.externalHTTP.enabled }}
- to:
{{- range .Values.networkPolicies.externalHTTP.cidrs }}
    - ipBlock:
        cidr: {{ . | quote }}
{{- end }}
  ports:
{{- range .Values.networkPolicies.externalHTTP.ports }}
    - protocol: TCP
      port: {{ . }}
{{- end }}
{{- end -}}
{{- end -}}

{{- define "constellation.networkPolicyKubeAPIEgress" -}}
- to:
{{- range .Values.networkPolicies.kubeAPI.cidrs }}
    - ipBlock:
        cidr: {{ . | quote }}
{{- end }}
  ports:
{{- range .Values.networkPolicies.kubeAPI.ports }}
    - protocol: TCP
      port: {{ . }}
{{- end }}
{{- end -}}

{{- define "constellation.networkPolicyPostgresEgress" -}}
{{- if ne (include "constellation.postgresMode" .) "external" }}
- to:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: {{ include "constellation.name" . }}
          app.kubernetes.io/component: postgres
  ports:
    - protocol: TCP
      port: 5432
{{- else }}
- to:
{{- range .Values.networkPolicies.externalPostgres.cidrs }}
    - ipBlock:
        cidr: {{ . | quote }}
{{- end }}
  ports:
{{- range .Values.networkPolicies.externalPostgres.ports }}
    - protocol: TCP
      port: {{ . }}
{{- end }}
{{- end -}}
{{- end -}}

{{/*
constellation.dsnSecret returns the secret name + key holding the Postgres DSN.

cnpg mode: postgres-secrets.yaml renders `<fullname>-database-url` pointing at
the CNPG primary Service with the chart-owned credentials.

external mode: either provide `postgres.dsn` (rendered into
`<fullname>-database-url` by the chart) or set `postgres.existingSecret` to
point at a pre-existing Secret.
*/}}
{{- define "constellation.dsnSecret" -}}
{{- if .Values.postgres.existingSecret -}}
{{- .Values.postgres.existingSecret -}}
{{- else -}}
{{- printf "%s-database-url" (include "constellation.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "constellation.dsnSecretKey" -}}
{{- if .Values.postgres.existingSecret -}}
{{- .Values.postgres.existingSecretKey | default "url" -}}
{{- else -}}
url
{{- end -}}
{{- end -}}

{{/*
constellation.postgresMode resolves the single canonical Postgres mode:
  cnpg | external   (default: cnpg)

`postgres.mode` is the canonical toggle. When it is empty the mode is derived
from `postgres.cloudnativepg.enabled` (true -> cnpg, false -> external). An
explicit mode wins. Invalid values fail the render so typos can't silently fall
through to the wrong mode. The former embedded StatefulSet mode was removed
(ADR 0007: Helm + CloudNativePG is the only in-cluster database path).
*/}}
{{- define "constellation.postgresMode" -}}
{{- $m := .Values.postgres.mode | default "" -}}
{{- if $m -}}
  {{- if not (has $m (list "cnpg" "external")) -}}
    {{- fail (printf "postgres.mode must be one of cnpg|external, got %q" $m) -}}
  {{- end -}}
  {{- $m -}}
{{- else if .Values.postgres.cloudnativepg.enabled -}}
cnpg
{{- else -}}
external
{{- end -}}
{{- end -}}

{{/* Per-mode boolean helpers so templates read cleanly. */}}
{{- define "constellation.postgresIsCNPG" -}}
{{- eq (include "constellation.postgresMode" .) "cnpg" -}}
{{- end -}}
{{- define "constellation.postgresIsExternal" -}}
{{- eq (include "constellation.postgresMode" .) "external" -}}
{{- end -}}

{{/*
constellation.cnpgImage resolves the CloudNativePG operand image. Empty
postgres.cloudnativepg.imageName selects the chart's own pgvector-enabled build
<image.registry>/postgres:16.15-v<Chart.appVersion> (deploy/docker/Dockerfile.postgres).
*/}}
{{- define "constellation.cnpgImage" -}}
{{- $cfg := .Values.postgres.cloudnativepg -}}
{{- default (printf "%s/postgres:16.15-v%s" (default "ghcr.io/alphabravo-oss/constellation" .Values.image.registry) (trimPrefix "v" .Chart.AppVersion)) $cfg.imageName -}}
{{- end -}}

{{/*
In-cluster object store (backup.objectStore) naming. The Service/StatefulSet,
the credentials Secret and the Barman Cloud ObjectStore CR all derive from the
release fullname so several releases can coexist in one namespace.
*/}}
{{- define "constellation.objectStoreName" -}}
{{- printf "%s-object-store" (include "constellation.fullname" .) -}}
{{- end -}}

{{- define "constellation.objectStoreCredentialsSecret" -}}
{{- if .Values.backup.objectStore.credentialsSecret -}}
{{- .Values.backup.objectStore.credentialsSecret -}}
{{- else -}}
{{- printf "%s-object-store-credentials" (include "constellation.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "constellation.objectStoreArchiveName" -}}
{{- printf "%s-object-store-archive" (include "constellation.fullname" .) -}}
{{- end -}}

{{/*
constellation.barmanObjectStoreName is the ObjectStore the CNPG Cluster archives
to: postgres.cloudnativepg.barmanCloud.objectStoreName when set, otherwise the
chart-rendered ObjectStore when backup.objectStore.enabled, otherwise "".
*/}}
{{- define "constellation.barmanObjectStoreName" -}}
{{- if .Values.postgres.cloudnativepg.barmanCloud.objectStoreName -}}
{{- .Values.postgres.cloudnativepg.barmanCloud.objectStoreName -}}
{{- else if .Values.backup.objectStore.enabled -}}
{{- include "constellation.objectStoreArchiveName" . -}}
{{- end -}}
{{- end -}}

{{/*
constellation.adminProbes renders the readiness/liveness probes every
Constellation Go role exposes on its admin listener (ADMIN_LISTEN_ADDR, :9090):
/readyz, /healthz and /metrics. Kubelet probes originate from the node, so the
namespace default-deny NetworkPolicy does not block them.
*/}}
{{- define "constellation.adminProbes" -}}
readinessProbe:
  httpGet: { path: /readyz, port: admin }
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
livenessProbe:
  httpGet: { path: /healthz, port: admin }
  initialDelaySeconds: 15
  periodSeconds: 20
  timeoutSeconds: 3
  failureThreshold: 3
{{- end -}}

{{/*
constellation.scannerTokenSecret / runtimeAgentTokenSecret return the secret
holding the bearer token. They default to `<fullname>-{scanner,runtime-agent}-token`
unless overridden by .Values.<role>.tokenSecret.
*/}}
{{- define "constellation.scannerTokenSecret" -}}
{{- if .Values.scanner.tokenSecret -}}
{{- .Values.scanner.tokenSecret -}}
{{- else -}}
{{- printf "%s-scanner-token" (include "constellation.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "constellation.runtimeAgentTokenSecret" -}}
{{- if .Values.runtimeAgent.tokenSecret -}}
{{- .Values.runtimeAgent.tokenSecret -}}
{{- else -}}
{{- printf "%s-runtime-agent-token" (include "constellation.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
constellation.jwtKeysSecretName returns the Secret holding API JWT signing keys.
When api.jwtKeysSecret is empty, the chart creates <fullname>-jwt-keys.
*/}}
{{- define "constellation.jwtKeysSecretName" -}}
{{- if .Values.api.jwtKeysSecret -}}
{{- .Values.api.jwtKeysSecret -}}
{{- else -}}
{{- printf "%s-jwt-keys" (include "constellation.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
constellation.admissionTLSSecret holds CA cert + server cert/key for the
admission webhook.
*/}}
{{- define "constellation.admissionTLSSecret" -}}
{{- printf "%s-admission-tls" (include "constellation.fullname" .) -}}
{{- end -}}

{{/*
constellation.clusterName resolves the ConstellationCluster CR name used for
auto-registration.
*/}}
{{- define "constellation.clusterName" -}}
{{- default .Release.Namespace .Values.clusterRegistration.name -}}
{{- end -}}

{{/*
constellation.apiURL is the API base URL used by in-cluster components.
*/}}
{{- define "constellation.apiURL" -}}
{{- if .Values.controlPlane.apiURL -}}
{{- trimSuffix "/" .Values.controlPlane.apiURL -}}
{{- else -}}
{{- printf "http://%s-api:%v" (include "constellation.fullname" .) .Values.api.service.port -}}
{{- end -}}
{{- end -}}

{{/* Trusted installation configuration only; workload labels never grant protection. */}}
{{- define "constellation.protectedNamespaces" -}}
{{- $shared := dig "systemProtection" "protectedNamespaces" (list) .ctx.Values.AsMap -}}
{{- $names := concat (list .ctx.Release.Namespace "kube-system" "kube-public" "kube-node-lease") $shared (default (list) .extra) | uniq | sortAlpha -}}
{{- toJson $names -}}
{{- end -}}

{{/* Secret holding the age column-encryption key set (key: age-key). */}}
{{- define "constellation.cryptoSecretName" -}}
{{- if .Values.crypto.existingSecret -}}
{{- .Values.crypto.existingSecret -}}
{{- else -}}
{{- printf "%s-age-key" (include "constellation.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* True when a CNPG cluster runs in this namespace: chart-managed (mode cnpg) or an
     operator-managed one named by networkPolicies.cnpg.clusterName (external mode). */}}
{{- define "constellation.cnpgInNamespace" -}}
{{- if or (eq (include "constellation.postgresMode" .) "cnpg") .Values.networkPolicies.cnpg.clusterName -}}true{{- end -}}
{{- end -}}

{{/* Pod labels of the S3 object store the CNPG archive uses. */}}
{{- define "constellation.objectStoreSelector" -}}
{{- if .Values.networkPolicies.cnpg.objectStoreSelector -}}
{{- toYaml .Values.networkPolicies.cnpg.objectStoreSelector -}}
{{- else -}}
app.kubernetes.io/name: {{ include "constellation.name" . }}
app.kubernetes.io/component: object-store
{{- end -}}
{{- end -}}
