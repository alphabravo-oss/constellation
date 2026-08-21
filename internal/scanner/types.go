// Package scanner is the multi-engine image scanner aggregator.
//
// Architecture (matches the spec's "ClairCore + Syft + Trivy + Grype, normalized + deduped")
// with a local VulnDB package-matching stage:
//
//	Engine[i].Scan(ref) -> []EngineFinding
//	Syft packages -> PackageMatcher[i].MatchPackages(packages) -> []EngineFinding
//	             ↓
//	Aggregator.Dedupe + merge provenance + asset hydration
//	             ↓
//	         []Finding (the canonical schema is the Go Finding struct in this package)
//
// At v1 the engines are wrapped CLIs (syft + trivy + grype) because their CLIs are stable
// and version-pinned in the agent image. The interface is intentionally shaped like a
// gRPC Plugin so a future cut can move each engine out-of-process (Phase 5: plugin SDK GA).
package scanner

import (
	"context"
	"time"
)

// Engine is one source of findings. Multiple engines run in parallel and their results
// converge in the Aggregator.
type Engine interface {
	// Name returns the canonical engine name ("syft" | "trivy" | "grype" | "claircore").
	Name() string

	// Scan inspects the given image reference and emits raw engine findings.
	// Implementations are responsible for any auth handshake; the registry credentials
	// flow through ScanOptions.
	Scan(ctx context.Context, ref string, opts ScanOptions) (*EngineResult, error)
}

// PackageMatcher resolves the authoritative package list produced by Syft
// against a local vulnerability source.
type PackageMatcher interface {
	// Name returns the canonical matcher name, for example "vulndb".
	Name() string

	// MatchPackages emits vulnerability findings for already-discovered
	// packages. Matchers do not pull images and should be deterministic over the
	// supplied package list plus their local data source.
	MatchPackages(ctx context.Context, ref string, packages []Package, opts ScanOptions) (*EngineResult, error)
}

// ScanOptions caps engine behavior at call time.
type ScanOptions struct {
	// SBOMOnly: skip vulnerability matching, emit SBOM packages only. Useful for the
	// "image-check --sbom" CLI path.
	SBOMOnly bool

	// IncludeIaC: pass the image as a directory ref to Trivy IaC. Used by IaC scans.
	IncludeIaC bool

	// IncludeLicense: extract OSS license findings from Syft package metadata.
	IncludeLicense bool

	// Insecure: tolerate self-signed registries. Translated to --insecure / --insecure-skip-tls.
	Insecure bool

	// Username / Password: optional registry credentials. Threaded into the
	// per-engine environment (registryEnv) as TRIVY_*/GRYPE_*/SYFT_* so the
	// underlying scan tools authenticate against private registries.
	Username string
	Password string

	// RegistryAuthority is the registry host (e.g. "ghcr.io", "docker.io") the
	// Username/Password apply to. Grype and Syft scope credentials per-authority
	// via GRYPE_REGISTRY_AUTH_AUTHORITY / SYFT_REGISTRY_AUTH_AUTHORITY.
	RegistryAuthority string

	// DockerConfigDir, when set, points DOCKER_CONFIG at a directory holding a
	// per-job docker config.json with the registry credentials. This is the
	// credential channel go-containerregistry (Syft/Grype/Trivy image pulls)
	// reads. The caller owns the directory lifecycle (create + cleanup per job).
	DockerConfigDir string

	// Platform pins the OS/arch for multi-arch images (e.g. "linux/amd64").
	Platform string

	// VulnDBPath points at a materialized constellation-vulndb bbolt store. When
	// empty, matchers may use CONSTELLATION_VULNDB_PATH or the chart default.
	VulnDBPath string

	// RequireVulnDB makes the canonical VulnDB matcher authoritative for the scan:
	// when it is set and the vulndb matcher returns an open/query error, the scan
	// fails instead of reporting an evidence-only (Trivy/Grype) success that would
	// overwrite a prior good result. No effect when no vulndb matcher is attached.
	RequireVulnDB bool

	// GoReachability opts into the govulncheck binary-mode reachability pass. When
	// set, the aggregator runs govulncheck (per Go binary, capped at 30s each) over
	// the produced findings to set Finding.Reachable on Go-ecosystem matches and
	// deprioritize the ones proven unreachable. Off by default — it requires the
	// govulncheck binary on PATH and adds per-binary scan latency.
	GoReachability bool

	// Timeout caps each engine invocation. The aggregator wraps this in a context.
	Timeout time.Duration
}

// EngineResult is the unaggregated payload from one engine.
type EngineResult struct {
	Engine         string
	ImageRef       string
	Findings       []EngineFinding
	Packages       []Package
	Secrets        []SecretFinding
	Misconfigs     []MisconfigFinding
	Confidence     float64
	BundleMetadata *BundleMetadata
	Error          string
	Raw            []byte // raw engine output, retained for audit
	Duration       time.Duration
}

// EngineFinding is one vulnerability emitted by a single engine.
type EngineFinding struct {
	Engine          string
	VulnerabilityID string // e.g. CVE-2024-0001
	Aliases         []string
	Severity        string // info/low/medium/high/critical
	CVSSBase        float64
	CVSSVector      string
	KEVListed       bool
	EPSSProbability float64
	Title           string
	Description     string
	References      []string
	Package         Package
	FixedVersion    string
	AffectedRange   *AffectedRange
	Confidence      float64

	// Published is the CVE/advisory publish (disclosure) date as reported by the
	// matcher, in the source's date form (RFC3339 when the source gives us one).
	// Empty when the matcher does not supply a date. Threaded into the finding
	// detail so the admission grace-window can compare against it; a missing value
	// is treated downstream as "count it" (no grace), which is the safe default.
	Published string
}

// SecretFinding is a normalized secret detector hit. Raw secret material is
// never stored; MatchSHA256 fingerprints the raw match and MatchRedacted only
// carries a non-reversible size marker for review workflows.
type SecretFinding struct {
	Engine        string `json:"engine"`
	RuleID        string `json:"rule_id,omitempty"`
	Category      string `json:"category,omitempty"`
	Severity      string `json:"severity,omitempty"`
	Title         string `json:"title,omitempty"`
	Target        string `json:"target,omitempty"`
	Path          string `json:"path,omitempty"`
	StartLine     int    `json:"start_line,omitempty"`
	EndLine       int    `json:"end_line,omitempty"`
	MatchSHA256   string `json:"match_sha256,omitempty"`
	MatchRedacted string `json:"match_redacted,omitempty"`
}

// MisconfigFinding is a normalized Trivy IaC / config misconfiguration hit
// (opt-in via ScanOptions.IncludeIaC -> `trivy --scanners config`). It is
// evidence about an image's embedded config/Dockerfile, kept separate from
// vulnerability Findings so downstream consumers can route it as its own kind.
type MisconfigFinding struct {
	Engine      string `json:"engine"`
	ID          string `json:"id,omitempty"`       // e.g. DS002, AVD-DS-0002
	Severity    string `json:"severity,omitempty"` // info/low/medium/high/critical
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Resolution  string `json:"resolution,omitempty"`
	Target      string `json:"target,omitempty"` // file the misconfig was found in
	Type        string `json:"type,omitempty"`   // dockerfile, kubernetes, etc.
	Message     string `json:"message,omitempty"`
	Reference   string `json:"reference,omitempty"`
}

// SignatureResult is the normalized image-signature verification outcome.
// Status is one of trusted, untrusted, unsigned, unavailable, skipped, or error.
type SignatureResult struct {
	ImageRef     string   `json:"image_ref,omitempty"`
	Status       string   `json:"status,omitempty"`
	Signed       bool     `json:"signed"`
	Trusted      bool     `json:"trusted"`
	Identity     string   `json:"identity,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
	RekorLog     string   `json:"rekor_log,omitempty"`
	Attestations []string `json:"attestations,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// ImageLayerMetadata is registry manifest-derived image layer evidence. It
// records manifest descriptors only; scanner workers do not fetch layer blobs.
type ImageLayerMetadata struct {
	ImageRef         string       `json:"image_ref,omitempty"`
	ManifestDigest   string       `json:"manifest_digest,omitempty"`
	IndexDigest      string       `json:"index_digest,omitempty"`
	MediaType        string       `json:"media_type,omitempty"`
	ConfigDigest     string       `json:"config_digest,omitempty"`
	ConfigMediaType  string       `json:"config_media_type,omitempty"`
	ConfigSizeBytes  int64        `json:"config_size_bytes,omitempty"`
	Layers           []ImageLayer `json:"layers,omitempty"`
	Architectures    []string     `json:"architectures,omitempty"`
	SelectedPlatform string       `json:"selected_platform,omitempty"`
	TotalSizeBytes   int64        `json:"total_size_bytes,omitempty"`
	Status           string       `json:"status,omitempty"`
	Reason           string       `json:"reason,omitempty"`
	Error            string       `json:"error,omitempty"`
}

type ImageLayer struct {
	// Index is the layer's ordinal position in the manifest (0-based, base first).
	Index       int               `json:"index"`
	MediaType   string            `json:"media_type,omitempty"`
	Digest      string            `json:"digest,omitempty"`
	SizeBytes   int64             `json:"size_bytes,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`

	// DiffID is the uncompressed (rootfs diff_id) digest for this layer, taken
	// from the OCI config rootfs.diff_ids. It is the digest Syft records in
	// PackageLocation.LayerDigest, so it is the join key for per-layer package
	// and vulnerability attribution.
	DiffID string `json:"diff_id,omitempty"`

	// CreatedBy is the raw OCI build-history instruction that produced this
	// layer (e.g. "/bin/sh -c #(nop) ADD file:... in /" or a RUN command). It is
	// the Dockerfile reconstruction NeuVector surfaces as the layer's command.
	CreatedBy string `json:"created_by,omitempty"`

	// Command is CreatedBy normalized to its Dockerfile-style instruction
	// (e.g. "ADD file:abc in /", "RUN apk add curl"), with the buildkit
	// "/bin/sh -c #(nop)" and "/bin/sh -c" wrappers stripped for readability.
	Command string `json:"command,omitempty"`

	// Comment / Author / CreatedAt carry the remaining OCI history metadata.
	Comment   string `json:"comment,omitempty"`
	Author    string `json:"author,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`

	// PackageCount is the number of distinct SBOM packages that reside in this
	// layer (joined via DiffID against PackageLocation.LayerDigest).
	PackageCount int `json:"package_count,omitempty"`

	// InBaseImage records whether this layer belongs to the image's base layers
	// (the OS/distro foundation) or to an application layer added on top. It is
	// propagated along layer ancestry: every layer at or below the highest base
	// layer is base; layers above it are application. nil when attribution could
	// not be determined (no base layer found).
	InBaseImage *bool `json:"in_base_image,omitempty"`

	// Vulnerabilities is the per-layer vulnerability rollup: which findings were
	// introduced by packages that reside in this layer.
	Vulnerabilities *LayerVulnRollup `json:"vulnerabilities,omitempty"`
}

// LayerVulnRollup summarizes the vulnerabilities attributable to a single image
// layer. A finding is attributed to the layer that contains the vulnerable
// package (via PackageLocation.LayerDigest == ImageLayer.DiffID).
type LayerVulnRollup struct {
	Total      int `json:"total"`
	Critical   int `json:"critical,omitempty"`
	High       int `json:"high,omitempty"`
	Medium     int `json:"medium,omitempty"`
	Low        int `json:"low,omitempty"`
	Negligible int `json:"negligible,omitempty"`
	Unknown    int `json:"unknown,omitempty"`
	// IDs lists the distinct vulnerability IDs introduced in this layer, sorted.
	IDs []string `json:"ids,omitempty"`
}

// LayerHistoryEntry is a scanner-local projection of one OCI image-config
// history record (config.history[]). It is decoupled from any registry client
// type so layer enrichment is testable with synthetic config JSON and so the
// scanner package owns its own wire shape.
type LayerHistoryEntry struct {
	CreatedBy  string `json:"created_by,omitempty"`
	Comment    string `json:"comment,omitempty"`
	Author     string `json:"author,omitempty"`
	Created    string `json:"created,omitempty"`
	EmptyLayer bool   `json:"empty_layer,omitempty"`
}

// ImageFileRiskReport is layer-applied filesystem risk evidence for an image.
// It records static metadata only; scanner workers never persist file contents.
type ImageFileRiskReport struct {
	ImageRef       string                 `json:"image_ref,omitempty"`
	ManifestDigest string                 `json:"manifest_digest,omitempty"`
	Platform       string                 `json:"platform,omitempty"`
	Status         string                 `json:"status,omitempty"`
	Reason         string                 `json:"reason,omitempty"`
	Error          string                 `json:"error,omitempty"`
	FindingCount   int                    `json:"finding_count"`
	EntryCount     int                    `json:"entry_count"`
	MaxFindings    int                    `json:"max_findings,omitempty"`
	Truncated      bool                   `json:"truncated,omitempty"`
	Findings       []ImageFileRiskFinding `json:"findings,omitempty"`
}

type ImageFileRiskFinding struct {
	Path        string   `json:"path"`
	Type        string   `json:"type,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	UID         int      `json:"uid,omitempty"`
	GID         int      `json:"gid,omitempty"`
	SizeBytes   int64    `json:"size_bytes,omitempty"`
	LayerIndex  int      `json:"layer_index,omitempty"`
	LayerDigest string   `json:"layer_digest,omitempty"`
	LinkName    string   `json:"link_name,omitempty"`
	RiskTypes   []string `json:"risk_types,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

// PackageLocation records where an inventory engine observed a package. Image
// scans use this to join package evidence back to image layers without making
// layer metadata part of vulnerability identity.
type PackageLocation struct {
	Path        string `json:"path,omitempty"`
	AccessPath  string `json:"access_path,omitempty"`
	RealPath    string `json:"real_path,omitempty"`
	LayerID     string `json:"layer_id,omitempty"`
	LayerDigest string `json:"layer_digest,omitempty"`
}

// Package is one bill-of-materials entry.
type Package struct {
	Ecosystem string   `json:"ecosystem,omitempty"` // apk / deb / rpm / npm / go / pypi / etc.
	Name      string   `json:"name,omitempty"`
	Version   string   `json:"version,omitempty"`
	Purl      string   `json:"purl,omitempty"`
	CPEs      []string `json:"cpes,omitempty"`
	Licenses  []string `json:"licenses,omitempty"`

	// Optional namespace metadata for vulnerability matching. Syft image scans
	// populate OS namespace fields from top-level distro metadata; package
	// managers alone are not enough to safely match distro advisories.
	NamespaceKind    string `json:"namespace_kind,omitempty"` // os / language / cpe / generic
	NamespaceName    string `json:"namespace_name,omitempty"` // ubuntu / debian / alpine / npm / pypi
	NamespaceVersion string `json:"namespace_version,omitempty"`

	// SourcePackage is the upstream/source/origin package name an OS binary
	// package was built from (e.g. binary "libssl3" -> source "openssl",
	// binary "libc6" -> source "glibc"). Distro advisories are keyed by the
	// SOURCE package, but Syft catalogues the installed BINARY name, so a
	// binary-name-only query misses every advisory recorded under the source.
	// Syft carries this as the apk/deb/rpm purl "upstream=" qualifier and in
	// package metadata (deb "source", apk "originPackage"). osPackageQueries
	// emits an additional OS query keyed by this name (within the same OS
	// namespace+version, so no cross-distro false positives).
	SourcePackage string `json:"source_package,omitempty"`

	// OSReleaseVersion is the distro release derived from the image's os-release /
	// lsb-release metadata (Syft's document-level distro), independent of whether a
	// given package carried its own NamespaceVersion. Distroless/scratch images and
	// Syft apk/deb/rpm artifacts that lack a distro qualifier leave NamespaceVersion
	// empty, which would otherwise drop their OS CVEs; this acts as the os-release
	// fallback the matcher uses, mirroring NeuVector's os-release-driven baseOS.
	OSReleaseVersion string            `json:"os_release_version,omitempty"`
	Arch             string            `json:"arch,omitempty"`
	Repository       string            `json:"repository,omitempty"`
	ImageRepository  string            `json:"image_repository,omitempty"`
	ImageTag         string            `json:"image_tag,omitempty"`
	BaseImage        string            `json:"base_image,omitempty"`
	ModuleStream     string            `json:"module_stream,omitempty"`
	Locations        []PackageLocation `json:"locations,omitempty"`

	// InBaseImage records whether this package was introduced by the image's base
	// layers (OS / distro foundation) rather than an application layer added on
	// top. It is nil when attribution could not be computed (no layer evidence and
	// no OS namespace). This mirrors NeuVector's ScanVulnerability.InBase tagging so
	// triage can separate base-image packages from app-introduced ones.
	InBaseImage *bool `json:"in_base_image,omitempty"`
}

// Finding is the canonical aggregated record. Multiple engines reporting the same
// (CVE, package, version) collapse into one Finding with merged provenance.
type Finding struct {
	VulnerabilityID string
	Aliases         []string
	Severity        string
	CVSSBase        float64
	CVSSVector      string
	KEVListed       bool
	EPSSProbability float64
	Title           string
	Description     string
	References      []string
	Package         Package
	FixedVersion    string
	AffectedRange   *AffectedRange

	// Published is the CVE/advisory publish (disclosure) date carried over from the
	// canonical matcher (RFC3339 when the source provides one, else the source's own
	// date form). Empty when no engine supplied a date. Persisted into
	// image_scan_findings.detail_json under "published" so the admission grace-window
	// can honor a "vulnerability newer than N days" allowance; missing means no grace.
	Published string

	// CanonicalEngine identifies the source that owns the vulnerability
	// semantics for this row. When VulnDB reports a matching advisory/package,
	// other scanners are evidence only.
	CanonicalEngine string

	// Provenance: which engines saw this finding, their confidence, and whether
	// they are canonical or supporting evidence.
	Engines        []EngineProvenance
	Reconciliation []ReconciliationSignal
	Reachable      *bool // nil until reachability is computed
	RiskScore      int   // composite score; computed by pkg/risk

	// InBaseImage mirrors Package.InBaseImage for the package this finding
	// matched: true when the vulnerable package was introduced by the image's
	// base layers, false when it was added by an application layer, nil when
	// attribution could not be determined. Triage uses this to separate
	// base-image vulns (fix by rebasing) from app-introduced ones (fix by
	// updating the application's own dependencies). Aligns with NeuVector's
	// ScanVulnerability.InBase field.
	InBaseImage *bool `json:"in_base_image,omitempty"`

	// BaseImageUpgrade is human-readable remediation guidance produced when a
	// finding is attributed to the image's base layers: rather than patching the
	// application's own dependencies, the operator should rebase onto a newer base
	// image (or newer base-image tag) that ships the fixed package. It is empty for
	// app-introduced findings and for base findings we cannot phrase guidance for.
	// This mirrors NeuVector's per-item Remediation/Suggestion string
	// (share/scan/scan_report.go), specialized to base-image rebasing.
	BaseImageUpgrade string `json:"base_image_upgrade,omitempty"`
}

const (
	EngineRoleCanonical = "canonical"
	EngineRoleEvidence  = "evidence"
)

// EngineProvenance records one engine's contribution.
type EngineProvenance struct {
	Engine     string  `json:"engine"`
	Confidence float64 `json:"confidence"`
	Role       string  `json:"role,omitempty"`
}

// ReconciliationSignal records a field-level disagreement between canonical
// VulnDB data and a supporting evidence engine.
type ReconciliationSignal struct {
	Engine    string `json:"engine"`
	Field     string `json:"field"`
	Canonical string `json:"canonical"`
	Evidence  string `json:"evidence"`
}

// AffectedRange is the scanner-neutral affected-version range that caused a
// vulnerability match. VulnDB fills this from its normalized package range;
// evidence engines may fill it when their output exposes comparable range data.
type AffectedRange struct {
	ID                  int64                `json:"id,omitempty"`
	Source              string               `json:"source,omitempty"`
	SourceRangeID       string               `json:"source_range_id,omitempty"`
	NamespaceKind       string               `json:"namespace_kind,omitempty"`
	NamespaceName       string               `json:"namespace_name,omitempty"`
	NamespaceVersion    string               `json:"namespace_version,omitempty"`
	VersionScheme       string               `json:"version_scheme,omitempty"`
	PackageName         string               `json:"package_name,omitempty"`
	PackagePURL         string               `json:"package_purl,omitempty"`
	PackageCPE          string               `json:"package_cpe,omitempty"`
	ModuleStream        string               `json:"module_stream,omitempty"`
	RangeType           string               `json:"range_type,omitempty"`
	IntroducedVersion   string               `json:"introduced_version,omitempty"`
	FixedVersion        string               `json:"fixed_version,omitempty"`
	LastAffectedVersion string               `json:"last_affected_version,omitempty"`
	RangeExpression     string               `json:"range_expression,omitempty"`
	Events              []AffectedRangeEvent `json:"events,omitempty"`
	AffectedStatus      string               `json:"affected_status,omitempty"`
	FixState            string               `json:"fix_state,omitempty"`
}

// AffectedRangeEvent is one OSV-style affected-range event.
type AffectedRangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// BundleMetadata identifies the VulnDB bundle used to produce a scan result.
type BundleMetadata struct {
	SchemaVersion string    `json:"schema_version,omitempty"`
	BundleVersion string    `json:"bundle_version,omitempty"`
	Producer      string    `json:"producer,omitempty"`
	MediaType     string    `json:"media_type,omitempty"`
	ExportedAt    time.Time `json:"exported_at,omitempty"`
	PayloadHash   string    `json:"payload_hash,omitempty"`
	RecordCount   int64     `json:"record_count,omitempty"`
}

// ScanResult is the aggregated output across all engines.
type ScanResult struct {
	ImageRef       string
	Packages       []Package
	Secrets        []SecretFinding
	Misconfigs     []MisconfigFinding
	Signature      *SignatureResult
	Layers         *ImageLayerMetadata
	FileRisks      *ImageFileRiskReport
	ConfigChecks   *ImageConfigCheckReport
	Findings       []Finding
	Engines        []EngineResult
	BundleMetadata *BundleMetadata `json:"bundle_metadata,omitempty"`
	StartedAt      time.Time
	EndedAt        time.Time
}
