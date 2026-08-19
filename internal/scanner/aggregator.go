package scanner

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Aggregator runs N engines in parallel and produces a single deduplicated ScanResult.
//
// Dedupe key: (canonical CVE ID, ecosystem, package name, installed version).
// When VulnDB reports a key, it owns the canonical vulnerability fields and
// Trivy/Grype findings become supporting evidence. If VulnDB is absent for the
// key, legacy scanner output is merged as an aggregate fallback.
type Aggregator struct {
	Engines         []Engine
	PackageMatchers []PackageMatcher
}

// AggregatorConfig controls which built-in engines are attached by
// NewDefaultWithConfig. The default zero value keeps every current engine on.
type AggregatorConfig struct {
	DisableSyft   bool
	DisableVulnDB bool
	DisableTrivy  bool
	DisableGrype  bool
	VulnDBPath    string
}

// NewDefault returns the v1 default aggregator: Syft (SBOM) + Trivy + Grype,
// plus the local constellation-vulndb package matcher when a store is present.
// ClairCore will join once we vendor it; the interface is engine-list-driven so adding it
// is a one-line change.
func NewDefault() *Aggregator {
	return NewDefaultWithConfig(AggregatorConfig{})
}

// NewDefaultWithConfig returns the built-in scanner pipeline with selected
// engines disabled. Syft should normally stay enabled because it is the package
// inventory source for VulnDB matching.
func NewDefaultWithConfig(cfg AggregatorConfig) *Aggregator {
	a := &Aggregator{}
	if !cfg.DisableSyft {
		a.Engines = append(a.Engines, &SyftEngine{})
	}
	if !cfg.DisableTrivy {
		a.Engines = append(a.Engines, &TrivyEngine{})
	}
	if !cfg.DisableGrype {
		a.Engines = append(a.Engines, &GrypeEngine{})
	}
	// Package matcher — required by the host/platform scan path (ScanPackages),
	// and used as the canonical matcher for image SBOMs. The removed constellation-
	// vulndb bundle used to own this slot; Grype's live DB now fills it so
	// host/platform scans still get vulnerability data (sourced from Grype's
	// maintained upstream feeds) without a static bundle.
	if !cfg.DisableGrype {
		a.PackageMatchers = append(a.PackageMatchers, &GrypePackageMatcher{})
	}
	return a
}

// Scan runs all engines and produces the aggregated result.
func (a *Aggregator) Scan(ctx context.Context, ref string, opts ScanOptions) (*ScanResult, error) {
	if len(a.Engines) == 0 {
		return nil, errors.New("scanner: no engines configured")
	}

	start := time.Now()
	type engineOut struct {
		res *EngineResult
		err error
	}
	results := make([]engineOut, len(a.Engines))
	var wg sync.WaitGroup
	for i, e := range a.Engines {
		wg.Add(1)
		go func(i int, e Engine) {
			defer wg.Done()
			r, err := e.Scan(ctx, ref, opts)
			results[i] = engineOut{res: r, err: err}
		}(i, e)
	}
	wg.Wait()

	out := &ScanResult{ImageRef: ref, StartedAt: start}

	var firstFatal error
	for i, ro := range results {
		if ro.err != nil {
			// Engine failures are non-fatal unless ALL engines fail. The error string is
			// preserved on the aggregate for audit.
			out.Engines = append(out.Engines, EngineResult{
				Engine: a.Engines[i].Name(),
				Error:  ro.err.Error(),
				Raw:    []byte(fmt.Sprintf(`{"error":%q}`, ro.err.Error())),
			})
			if firstFatal == nil {
				firstFatal = ro.err
			}
			continue
		}
		out.Engines = append(out.Engines, *ro.res)
		if out.BundleMetadata == nil && ro.res.BundleMetadata != nil {
			out.BundleMetadata = ro.res.BundleMetadata
		}
	}

	// SBOM comes from syft (the only engine with authoritative package data).
	for _, r := range out.Engines {
		if r.Engine == "syft" {
			out.Packages = r.Packages
			break
		}
	}
	for _, r := range out.Engines {
		out.Secrets = append(out.Secrets, r.Secrets...)
		out.Misconfigs = append(out.Misconfigs, r.Misconfigs...)
	}

	var vulnDBErr error
	vulnDBMatcherRan := false
	if !opts.SBOMOnly && len(out.Packages) > 0 {
		for _, matcher := range a.PackageMatchers {
			isVulnDB := isVulnDBSource(matcher.Name())
			matcherStart := time.Now()
			res, err := matcher.MatchPackages(ctx, ref, out.Packages, opts)
			if isVulnDB {
				// The matcher executed against a non-empty inventory (the loop only
				// runs when len(out.Packages) > 0); record that so the require-vulndb
				// gate can distinguish "ran" from "never ran" (empty SBOM).
				vulnDBMatcherRan = true
			}
			if err != nil {
				out.Engines = append(out.Engines, EngineResult{
					Engine:   matcher.Name(),
					ImageRef: ref,
					Error:    err.Error(),
					Raw:      []byte(fmt.Sprintf(`{"error":%q}`, err.Error())),
					Duration: time.Since(matcherStart),
				})
				if firstFatal == nil {
					firstFatal = err
				}
				if isVulnDB && vulnDBErr == nil {
					vulnDBErr = err
				}
				continue
			}
			out.Engines = append(out.Engines, *res)
			if out.BundleMetadata == nil && res.BundleMetadata != nil {
				out.BundleMetadata = res.BundleMetadata
			}
		}
	}

	out.Findings = dedupe(out.Engines)
	attributeBaseImage(out.Packages)
	applyBaseImageToFindings(out.Findings, baseImageIndex(out.Packages))

	// Fail closed BEFORE the (optional, expensive) reachability pass when the
	// required canonical VulnDB matcher did not produce authoritative data. This
	// covers both a matcher that ran and errored (store missing/corrupt) AND a
	// matcher that never ran because the SBOM was empty — a non-fatal Syft failure
	// leaves out.Packages empty, which skips the matcher loop and would otherwise
	// record an evidence-only (Trivy/Grype) success overwriting a prior good result.
	if err := requireVulnDBGate(opts, a.PackageMatchers, vulnDBErr, vulnDBMatcherRan); err != nil {
		return out, err
	}

	if opts.GoReachability {
		analyzer := goReachabilityAnalyzer{}
		// For image targets the finding binary paths point INSIDE the image and do
		// not exist on the scanner host; extract them to a host scratch dir so
		// govulncheck can read them. Directory/serverless scans already reference
		// host-resolvable paths and pass through unchanged.
		if isImageScanTarget(ref) {
			resolve, cleanup := extractImageBinaries(ctx, ref, opts, goBinaryInImagePaths(out.Findings))
			defer cleanup()
			analyzer.resolvePath = resolve
		}
		out.Findings = analyzer.analyze(ctx, out.Findings)
	}
	out.EndedAt = time.Now()

	// If every engine errored, surface the first failure.
	hasUsable := false
	for _, r := range out.Engines {
		if r.Engine == "syft" && len(r.Packages) > 0 {
			hasUsable = true
			break
		}
		if len(r.Findings) > 0 {
			hasUsable = true
			break
		}
		if len(r.Secrets) > 0 {
			hasUsable = true
			break
		}
	}
	if !hasUsable && firstFatal != nil {
		return out, fmt.Errorf("scanner: all engines failed; first error: %w", firstFatal)
	}
	return out, nil
}

// ScanPackages runs package matchers against package evidence that was collected
// elsewhere, such as runtime-agent host or workload inventory. It does not pull
// an image or execute image scanners.
func (a *Aggregator) ScanPackages(ctx context.Context, ref string, packages []Package, opts ScanOptions) (*ScanResult, error) {
	start := time.Now()
	out := &ScanResult{
		ImageRef:       ref,
		Packages:       append([]Package(nil), packages...),
		StartedAt:      start,
		EndedAt:        start,
		BundleMetadata: nil,
	}
	out.Engines = append(out.Engines, EngineResult{
		Engine:     "package-evidence",
		ImageRef:   ref,
		Packages:   append([]Package(nil), packages...),
		Confidence: 1,
		Duration:   0,
	})
	if opts.SBOMOnly {
		out.EndedAt = time.Now()
		return out, nil
	}
	if len(a.PackageMatchers) == 0 {
		return out, errors.New("scanner: no package matchers configured")
	}

	var firstFatal error
	var vulnDBErr error
	vulnDBMatcherRan := false
	for _, matcher := range a.PackageMatchers {
		isVulnDB := isVulnDBSource(matcher.Name())
		matcherStart := time.Now()
		res, err := matcher.MatchPackages(ctx, ref, packages, opts)
		if isVulnDB && len(packages) > 0 {
			// Only count the matcher as having run authoritatively when it had a
			// non-empty inventory to match; an empty package list yields no canonical
			// data and must trip the require-vulndb gate rather than report success.
			vulnDBMatcherRan = true
		}
		if err != nil {
			out.Engines = append(out.Engines, EngineResult{
				Engine:   matcher.Name(),
				ImageRef: ref,
				Error:    err.Error(),
				Raw:      []byte(fmt.Sprintf(`{"error":%q}`, err.Error())),
				Duration: time.Since(matcherStart),
			})
			if firstFatal == nil {
				firstFatal = err
			}
			if isVulnDB && vulnDBErr == nil {
				vulnDBErr = err
			}
			continue
		}
		out.Engines = append(out.Engines, *res)
		if out.BundleMetadata == nil && res.BundleMetadata != nil {
			out.BundleMetadata = res.BundleMetadata
		}
	}

	out.Findings = dedupe(out.Engines)
	attributeBaseImage(out.Packages)
	applyBaseImageToFindings(out.Findings, baseImageIndex(out.Packages))
	// See Scan: a required-but-absent/failed canonical VulnDB matcher must fail the
	// scan rather than record an evidence-only result. ScanPackages binary mode has
	// no host-resolvable binaries (the evidence comes from a remote agent), so the
	// reachability pass runs with no path resolver (paths it cannot read are simply
	// left unknown).
	if err := requireVulnDBGate(opts, a.PackageMatchers, vulnDBErr, vulnDBMatcherRan); err != nil {
		return out, err
	}
	if opts.GoReachability {
		out.Findings = goReachabilityAnalyzer{}.analyze(ctx, out.Findings)
	}
	out.EndedAt = time.Now()
	if len(out.Findings) == 0 && firstFatal != nil {
		return out, fmt.Errorf("scanner: package matchers failed; first error: %w", firstFatal)
	}
	return out, nil
}

// dedupe collapses per-engine findings into the canonical Finding list.
func dedupe(engines []EngineResult) []Finding {
	type key struct {
		cve, eco, name, ver string
	}
	bucket := map[key]*Finding{}
	prov := map[key]map[string]float64{}
	canonical := map[key]string{}

	// Resolve a canonical vulnerability identity per package via the alias sets, so a
	// VulnDB GHSA/OSV finding (alias CVE-X) and a Trivy/Grype CVE-X for the SAME
	// package collapse into one bucket instead of being double-counted. Keying on the
	// raw VulnerabilityID alone would split them.
	canonIDs := buildCanonicalIDIndex(engines)

	for _, e := range engines {
		for _, f := range e.Findings {
			source := findingSource(e.Engine, f.Engine)
			if f.Engine == "" {
				f.Engine = source
			}
			pk := pkgKey{
				eco:  strings.ToLower(f.Package.Ecosystem),
				name: f.Package.Name,
				ver:  f.Package.Version,
			}
			k := key{
				cve:  resolveCanonicalID(canonIDs, pk, f.VulnerabilityID, f.Aliases),
				eco:  pk.eco,
				name: pk.name,
				ver:  pk.ver,
			}
			cur, ok := bucket[k]
			if !ok {
				cur = &Finding{
					VulnerabilityID: f.VulnerabilityID,
					Aliases:         append([]string{}, f.Aliases...),
					Severity:        f.Severity,
					CVSSBase:        f.CVSSBase,
					CVSSVector:      f.CVSSVector,
					KEVListed:       f.KEVListed,
					EPSSProbability: f.EPSSProbability,
					Title:           f.Title,
					Description:     f.Description,
					References:      append([]string{}, f.References...),
					Package:         f.Package,
					FixedVersion:    f.FixedVersion,
					AffectedRange:   cloneAffectedRange(f.AffectedRange),
					Published:       f.Published,
					CanonicalEngine: source,
				}
				bucket[k] = cur
				prov[k] = map[string]float64{}
				canonical[k] = source
			} else {
				canonicalSource := canonical[k]
				switch {
				case isVulnDBSource(source) && !isVulnDBSource(canonicalSource):
					promoteVulnDBCanonical(cur, f)
					canonical[k] = source
					cur.CanonicalEngine = source
				case isVulnDBSource(canonicalSource):
					if isVulnDBSource(source) {
						mergeCanonicalPeer(cur, f)
					} else {
						mergeEvidenceOnly(cur, f)
					}
				default:
					mergeAggregateFallback(cur, f)
					if canonicalSource != source {
						canonical[k] = "aggregate"
						cur.CanonicalEngine = "aggregate"
					}
				}
			}
			if prev, exists := prov[k][f.Engine]; !exists || f.Confidence > prev {
				prov[k][f.Engine] = f.Confidence
			}
		}
	}

	out := make([]Finding, 0, len(bucket))
	for k, f := range bucket {
		// Boost confidence when multiple engines agree; expressed via provenance list.
		engines := []EngineProvenance{}
		for name, conf := range prov[k] {
			role := EngineRoleCanonical
			if isVulnDBSource(canonical[k]) && !isVulnDBSource(name) {
				role = EngineRoleEvidence
			}
			engines = append(engines, EngineProvenance{Engine: name, Confidence: conf, Role: role})
		}
		sort.Slice(engines, func(i, j int) bool {
			if engines[i].Role != engines[j].Role {
				return engines[i].Role == EngineRoleCanonical
			}
			return engines[i].Engine < engines[j].Engine
		})
		f.CanonicalEngine = canonical[k]
		f.Engines = engines
		out = append(out, *f)
	}
	// Stable order: severity desc, then CVSS desc, then CVE asc.
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := severityRank(out[i].Severity), severityRank(out[j].Severity)
		if si != sj {
			return si > sj
		}
		if out[i].CVSSBase != out[j].CVSSBase {
			return out[i].CVSSBase > out[j].CVSSBase
		}
		return out[i].VulnerabilityID < out[j].VulnerabilityID
	})
	return out
}

func findingSource(resultEngine, findingEngine string) string {
	if findingEngine != "" {
		return findingEngine
	}
	if resultEngine != "" {
		return resultEngine
	}
	return "unknown"
}

func isVulnDBSource(name string) bool {
	return strings.EqualFold(name, "vulndb")
}

// requireVulnDBGate fails closed when RequireVulnDB is set but the canonical
// VulnDB matcher did not produce authoritative data: it either errored, or never
// ran against a package inventory at all (empty SBOM). It is a no-op when
// RequireVulnDB is unset, when SBOMOnly is requested (the caller explicitly asked
// to skip vulnerability matching), or when no VulnDB matcher is attached (there is
// no canonical matcher to enforce — matching the documented "no effect when no
// vulndb matcher is attached" contract).
func requireVulnDBGate(opts ScanOptions, matchers []PackageMatcher, vulnDBErr error, vulnDBMatcherRan bool) error {
	if !opts.RequireVulnDB || opts.SBOMOnly {
		return nil
	}
	if vulnDBErr != nil {
		// Transient — the store may recover — so the caller should treat it as retryable.
		return fmt.Errorf("scanner: require-vulndb set but vulndb matcher failed: %w", vulnDBErr)
	}
	if hasVulnDBMatcher(matchers) && !vulnDBMatcherRan {
		return errors.New("scanner: require-vulndb set but the vulndb matcher could not run against any package inventory (empty SBOM); refusing to record an evidence-only result")
	}
	return nil
}

func hasVulnDBMatcher(matchers []PackageMatcher) bool {
	for _, m := range matchers {
		if isVulnDBSource(m.Name()) {
			return true
		}
	}
	return false
}

func promoteVulnDBCanonical(cur *Finding, f EngineFinding) {
	previous := *cur
	*cur = Finding{
		VulnerabilityID: f.VulnerabilityID,
		Aliases:         append([]string{}, f.Aliases...),
		Severity:        f.Severity,
		CVSSBase:        f.CVSSBase,
		CVSSVector:      f.CVSSVector,
		KEVListed:       f.KEVListed || previous.KEVListed,
		EPSSProbability: f.EPSSProbability,
		Title:           f.Title,
		Description:     f.Description,
		References:      append([]string{}, f.References...),
		Package:         f.Package,
		FixedVersion:    f.FixedVersion,
		AffectedRange:   cloneAffectedRange(f.AffectedRange),
		Published:       f.Published,
		Reconciliation:  append([]ReconciliationSignal{}, previous.Reconciliation...),
		Reachable:       previous.Reachable,
		RiskScore:       previous.RiskScore,
	}
	fillMissingCanonical(cur, previous)
	addFindingDisagreements(cur, previous.CanonicalEngine, previous.Severity, previous.CVSSBase, previous.FixedVersion, previous.AffectedRange)
	cur.Aliases = mergeStrings(cur.Aliases, previous.Aliases)
	cur.References = mergeStrings(cur.References, previous.References)
	if previous.EPSSProbability > cur.EPSSProbability {
		cur.EPSSProbability = previous.EPSSProbability
	}
}

func mergeCanonicalPeer(cur *Finding, f EngineFinding) {
	if f.CVSSBase > cur.CVSSBase {
		cur.CVSSBase = f.CVSSBase
		cur.CVSSVector = f.CVSSVector
	}
	if severityRank(f.Severity) > severityRank(cur.Severity) {
		cur.Severity = f.Severity
	}
	if cur.Description == "" {
		cur.Description = f.Description
	}
	if cur.Title == "" {
		cur.Title = f.Title
	}
	if cur.FixedVersion == "" {
		cur.FixedVersion = f.FixedVersion
	}
	if cur.AffectedRange == nil {
		cur.AffectedRange = cloneAffectedRange(f.AffectedRange)
	}
	if cur.Published == "" {
		cur.Published = f.Published
	}
	cur.References = mergeStrings(cur.References, f.References)
	cur.Aliases = mergeStrings(cur.Aliases, f.Aliases)
	if f.KEVListed {
		cur.KEVListed = true
	}
	if f.EPSSProbability > cur.EPSSProbability {
		cur.EPSSProbability = f.EPSSProbability
	}
}

func mergeEvidenceOnly(cur *Finding, f EngineFinding) {
	addFindingDisagreements(cur, f.Engine, f.Severity, f.CVSSBase, f.FixedVersion, f.AffectedRange)
	fillMissingCanonical(cur, Finding{
		VulnerabilityID: f.VulnerabilityID,
		Severity:        f.Severity,
		CVSSBase:        f.CVSSBase,
		CVSSVector:      f.CVSSVector,
		Title:           f.Title,
		Description:     f.Description,
		Package:         f.Package,
		FixedVersion:    f.FixedVersion,
		AffectedRange:   cloneAffectedRange(f.AffectedRange),
		Published:       f.Published,
	})
	cur.References = mergeStrings(cur.References, f.References)
	cur.Aliases = mergeStrings(cur.Aliases, f.Aliases)
	if f.KEVListed {
		cur.KEVListed = true
	}
	if f.EPSSProbability > cur.EPSSProbability {
		cur.EPSSProbability = f.EPSSProbability
	}
}

func mergeAggregateFallback(cur *Finding, f EngineFinding) {
	// Legacy fallback for scans without VulnDB: take the higher CVSS/severity
	// and fill descriptive fields from the first scanner that provided them.
	if f.CVSSBase > cur.CVSSBase {
		cur.CVSSBase = f.CVSSBase
		cur.CVSSVector = f.CVSSVector
	}
	if severityRank(f.Severity) > severityRank(cur.Severity) {
		cur.Severity = f.Severity
	}
	if cur.Description == "" {
		cur.Description = f.Description
	}
	if cur.Title == "" {
		cur.Title = f.Title
	}
	if cur.FixedVersion == "" {
		cur.FixedVersion = f.FixedVersion
	}
	if cur.AffectedRange == nil {
		cur.AffectedRange = cloneAffectedRange(f.AffectedRange)
	}
	if cur.Published == "" {
		cur.Published = f.Published
	}
	cur.References = mergeStrings(cur.References, f.References)
	cur.Aliases = mergeStrings(cur.Aliases, f.Aliases)
	if f.KEVListed {
		cur.KEVListed = true
	}
	if f.EPSSProbability > cur.EPSSProbability {
		cur.EPSSProbability = f.EPSSProbability
	}
}

func fillMissingCanonical(cur *Finding, fallback Finding) {
	if cur.VulnerabilityID == "" {
		cur.VulnerabilityID = fallback.VulnerabilityID
	}
	if cur.Severity == "" || strings.EqualFold(cur.Severity, "unknown") {
		cur.Severity = fallback.Severity
	}
	if cur.CVSSBase == 0 {
		cur.CVSSBase = fallback.CVSSBase
		cur.CVSSVector = fallback.CVSSVector
	}
	if cur.CVSSVector == "" {
		cur.CVSSVector = fallback.CVSSVector
	}
	if cur.Title == "" {
		cur.Title = fallback.Title
	}
	if cur.Description == "" {
		cur.Description = fallback.Description
	}
	if cur.Package.Name == "" {
		cur.Package = fallback.Package
	}
	if cur.FixedVersion == "" {
		cur.FixedVersion = fallback.FixedVersion
	}
	if cur.AffectedRange == nil {
		cur.AffectedRange = cloneAffectedRange(fallback.AffectedRange)
	}
	if cur.Published == "" {
		cur.Published = fallback.Published
	}
}

func addFindingDisagreements(cur *Finding, source, severity string, cvss float64, fixedVersion string, affectedRange *AffectedRange) {
	if source == "" {
		source = "evidence"
	}
	if cur.Severity != "" && severity != "" && !strings.EqualFold(cur.Severity, severity) {
		addReconciliationSignal(cur, source, "severity", cur.Severity, severity)
	}
	if cur.CVSSBase > 0 && cvss > 0 && cur.CVSSBase != cvss {
		addReconciliationSignal(cur, source, "cvss_base", fmt.Sprintf("%g", cur.CVSSBase), fmt.Sprintf("%g", cvss))
	}
	if cur.FixedVersion != fixedVersion && (cur.FixedVersion != "" || fixedVersion != "") {
		addReconciliationSignal(cur, source, "fixed_version", cur.FixedVersion, fixedVersion)
	}
	if cur.AffectedRange != nil && affectedRange != nil {
		canonicalRange := affectedRangeFingerprint(cur.AffectedRange)
		evidenceRange := affectedRangeFingerprint(affectedRange)
		if canonicalRange != evidenceRange {
			addReconciliationSignal(cur, source, "affected_range", affectedRangeSummary(cur.AffectedRange), affectedRangeSummary(affectedRange))
		}
	}
}

func addReconciliationSignal(cur *Finding, source, field, canonical, evidence string) {
	for _, existing := range cur.Reconciliation {
		if existing.Engine == source && existing.Field == field && existing.Canonical == canonical && existing.Evidence == evidence {
			return
		}
	}
	cur.Reconciliation = append(cur.Reconciliation, ReconciliationSignal{
		Engine:    source,
		Field:     field,
		Canonical: canonical,
		Evidence:  evidence,
	})
}

func cloneAffectedRange(in *AffectedRange) *AffectedRange {
	if in == nil {
		return nil
	}
	out := *in
	if len(in.Events) > 0 {
		out.Events = append([]AffectedRangeEvent{}, in.Events...)
	}
	return &out
}

func affectedRangeFingerprint(r *AffectedRange) string {
	if r == nil {
		return ""
	}
	parts := []string{
		r.Source,
		r.SourceRangeID,
		r.NamespaceKind,
		r.NamespaceName,
		r.NamespaceVersion,
		r.VersionScheme,
		r.PackageName,
		r.PackagePURL,
		r.PackageCPE,
		r.ModuleStream,
		r.RangeType,
		r.IntroducedVersion,
		r.FixedVersion,
		r.LastAffectedVersion,
		r.RangeExpression,
		r.AffectedStatus,
		r.FixState,
	}
	for _, event := range r.Events {
		parts = append(parts, event.Introduced, event.Fixed, event.LastAffected, event.Limit)
	}
	return strings.Join(parts, "\x00")
}

func affectedRangeSummary(r *AffectedRange) string {
	if r == nil {
		return ""
	}
	if r.RangeExpression != "" {
		return fmt.Sprintf("%s:%s:%s", r.Source, r.RangeType, r.RangeExpression)
	}
	if len(r.Events) > 0 {
		eventParts := make([]string, 0, len(r.Events))
		for _, event := range r.Events {
			eventParts = append(eventParts, strings.Join([]string{event.Introduced, event.Fixed, event.LastAffected, event.Limit}, "/"))
		}
		return fmt.Sprintf("%s:%s:%s", r.Source, r.RangeType, strings.Join(eventParts, ","))
	}
	bounds := []string{}
	if r.IntroducedVersion != "" {
		bounds = append(bounds, "introduced="+r.IntroducedVersion)
	}
	if r.FixedVersion != "" {
		bounds = append(bounds, "fixed="+r.FixedVersion)
	}
	if r.LastAffectedVersion != "" {
		bounds = append(bounds, "last_affected="+r.LastAffectedVersion)
	}
	if len(bounds) == 0 {
		return fmt.Sprintf("%s:%s", r.Source, r.RangeType)
	}
	return fmt.Sprintf("%s:%s:%s", r.Source, r.RangeType, strings.Join(bounds, ","))
}

// canonicalCVE normalizes ids ("cve-2024-0001" -> "CVE-2024-0001"). GHSAs etc pass through.
func canonicalCVE(id string) string {
	up := strings.ToUpper(id)
	return up
}

// pkgKey identifies the package a finding matched (ecosystem lower-cased). Alias
// resolution is scoped per package: a single CVE can affect multiple packages and
// those must remain distinct findings.
type pkgKey struct {
	eco, name, ver string
}

// vulnIDSet returns the distinct, upper-cased, non-empty vulnerability identifiers
// a finding is known by (primary id + aliases).
func vulnIDSet(id string, aliases []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(aliases)+1)
	add := func(s string) {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	add(id)
	for _, a := range aliases {
		add(a)
	}
	return out
}

// idUnionFind is a tiny string union-find used to merge co-occurring vuln ids.
type idUnionFind struct {
	parent map[string]string
}

func (u *idUnionFind) find(x string) string {
	if u.parent == nil {
		u.parent = map[string]string{}
	}
	if _, ok := u.parent[x]; !ok {
		u.parent[x] = x
	}
	for u.parent[x] != x {
		u.parent[x] = u.parent[u.parent[x]]
		x = u.parent[x]
	}
	return x
}

func (u *idUnionFind) union(a, b string) {
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u.parent[ra] = rb
	}
}

// buildCanonicalIDIndex maps, per package, every vulnerability id seen across all
// engine findings to a single canonical id for its alias-connected component
// (preferring a CVE id). Findings whose id sets intersect — directly or transitively
// — through aliases share one canonical id and therefore one dedupe bucket.
func buildCanonicalIDIndex(engines []EngineResult) map[pkgKey]map[string]string {
	ufs := map[pkgKey]*idUnionFind{}
	for _, e := range engines {
		for _, f := range e.Findings {
			pk := pkgKey{
				eco:  strings.ToLower(f.Package.Ecosystem),
				name: f.Package.Name,
				ver:  f.Package.Version,
			}
			ids := vulnIDSet(f.VulnerabilityID, f.Aliases)
			if len(ids) == 0 {
				continue
			}
			uf := ufs[pk]
			if uf == nil {
				uf = &idUnionFind{parent: map[string]string{}}
				ufs[pk] = uf
			}
			uf.find(ids[0])
			for i := 1; i < len(ids); i++ {
				uf.union(ids[0], ids[i])
			}
		}
	}

	out := make(map[pkgKey]map[string]string, len(ufs))
	for pk, uf := range ufs {
		groups := map[string][]string{}
		for id := range uf.parent {
			root := uf.find(id)
			groups[root] = append(groups[root], id)
		}
		m := make(map[string]string, len(uf.parent))
		for _, ids := range groups {
			canon := preferredCanonicalID(ids)
			for _, id := range ids {
				m[id] = canon
			}
		}
		out[pk] = m
	}
	return out
}

// preferredCanonicalID picks the representative id for an alias-connected component:
// a CVE id if present (lexically smallest among CVEs), otherwise the lexically
// smallest id. The choice is deterministic so bucketing is stable across runs.
func preferredCanonicalID(ids []string) string {
	best := ""
	bestIsCVE := false
	for _, id := range ids {
		isCVE := strings.HasPrefix(id, "CVE-")
		switch {
		case best == "":
			best, bestIsCVE = id, isCVE
		case isCVE && !bestIsCVE:
			best, bestIsCVE = id, true
		case isCVE == bestIsCVE && id < best:
			best = id
		}
	}
	return best
}

// resolveCanonicalID returns the canonical bucket id for a finding, joining it to
// any alias-equivalent peers for the same package. Falls back to the normalized
// primary id when no alias index entry exists (e.g. a lone id).
func resolveCanonicalID(index map[pkgKey]map[string]string, pk pkgKey, id string, aliases []string) string {
	if m := index[pk]; m != nil {
		for _, candidate := range vulnIDSet(id, aliases) {
			if canon, ok := m[candidate]; ok {
				return canon
			}
		}
	}
	return canonicalCVE(id)
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	case "info", "negligible", "unknown", "":
		return 0
	}
	return 0
}

func mergeStrings(a, b []string) []string {
	seen := map[string]struct{}{}
	out := a[:0:0]
	out = append(out, a...)
	for _, v := range a {
		seen[v] = struct{}{}
	}
	for _, v := range b {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
