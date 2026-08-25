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
{{- default .Chart.AppVersion .Values.image.tag -}}
{{- end -}}

{{/*
constellation.roleImage returns the fully qualified image for a given role.

Default convention: <image.registry>/<role>:<image.tag-or-appVersion>
A role can override either the repository or tag via .Values.<role>.image.

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
{{- if eq $role "auditArchiver" -}}{{- $rolePath = "audit-archiver" -}}{{- end -}}
{{- if eq $role "vulndbImporter" -}}{{- $rolePath = "vulndb-importer" -}}{{- end -}}
{{- $registry := $ctx.Values.image.registry | default "ghcr.io/alphabravo-oss/constellation" -}}
{{- if $ctx.Values.fips.enabled -}}{{- $registry = $ctx.Values.fips.registry -}}{{- end -}}
{{- $repo := printf "%s/%s" $registry $rolePath -}}
{{- $tag  := default $ctx.Chart.AppVersion $ctx.Values.image.tag -}}
{{- if and $top (kindIs "map" $top) (hasKey $top "image") -}}
  {{- $img := index $top "image" -}}
  {{- if and (kindIs "map" $img) $img.repository -}}
    {{- $repo = $img.repository -}}
  {{- end -}}
  {{- if and (kindIs "map" $img) $img.tag -}}
    {{- $tag = $img.tag -}}
  {{- end -}}
{{- end -}}
{{- printf "%s:%s" $repo $tag -}}
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

When postgres.embedded=true the bootstrap Job synthesises
`constellation-database-url` from the embedded StatefulSet credentials.

When postgres.embedded=false the user must either provide `postgres.dsn`
(rendered into `constellation-database-url` by the chart) or set
`postgres.existingSecret` to point at a pre-existing Secret.
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
  statefulset | cnpg | external   (default: statefulset)

`postgres.mode` is the canonical toggle (D5). For backward compatibility, when
`postgres.mode` is unset we derive it from the legacy booleans
(`postgres.cloudnativepg.enabled`, `postgres.embedded`). When `postgres.mode` IS
set it wins outright. Invalid values fail the render so typos can't silently
fall through to the wrong mode.
*/}}
{{- define "constellation.postgresMode" -}}
{{- $m := .Values.postgres.mode | default "" -}}
{{- if $m -}}
  {{- if not (has $m (list "statefulset" "cnpg" "external")) -}}
    {{- fail (printf "postgres.mode must be one of statefulset|cnpg|external, got %q" $m) -}}
  {{- end -}}
  {{- $m -}}
{{- else if .Values.postgres.cloudnativepg.enabled -}}
cnpg
{{- else if .Values.postgres.embedded -}}
statefulset
{{- else -}}
external
{{- end -}}
{{- end -}}

{{/* Per-mode boolean helpers so templates read cleanly. */}}
{{- define "constellation.postgresIsStatefulset" -}}
{{- eq (include "constellation.postgresMode" .) "statefulset" -}}
{{- end -}}
{{- define "constellation.postgresIsCNPG" -}}
{{- eq (include "constellation.postgresMode" .) "cnpg" -}}
{{- end -}}
{{- define "constellation.postgresIsExternal" -}}
{{- eq (include "constellation.postgresMode" .) "external" -}}
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

{{- define "constellation.vulndbPath" -}}
{{- printf "%s/%s" (.Values.vulndb.mountPath | trimSuffix "/") .Values.vulndb.dbFile -}}
{{- end -}}

{{- define "constellation.vulndbPVCName" -}}
{{- if .Values.vulndb.storage.existingClaim -}}
{{- .Values.vulndb.storage.existingClaim -}}
{{- else -}}
{{- printf "%s-vulndb" (include "constellation.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "constellation.vulndbVolume" -}}
- name: vulndb
{{- if or (eq .Values.vulndb.storage.type "pvc") .Values.vulndb.storage.existingClaim }}
  persistentVolumeClaim:
    claimName: {{ include "constellation.vulndbPVCName" . }}
{{- else if eq .Values.vulndb.storage.type "hostPath" }}
  hostPath:
    path: {{ .Values.vulndb.storage.hostPath | quote }}
    type: DirectoryOrCreate
{{- else if eq .Values.vulndb.storage.type "emptyDir" }}
  emptyDir: {}
{{- else }}
  {{- fail "vulndb.storage.type must be pvc, hostPath, or emptyDir" }}
{{- end }}
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
