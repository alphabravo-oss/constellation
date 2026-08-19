// E1 declarative response-rule evaluation for the scan-completion ingest path.
//
// When a scan job completes (ScanJobs.Complete), the org's enabled EventScan response rules
// are evaluated against the folded scan result and their ordered actions applied. This is the
// NeuVector EventCVEReport parity: a rule keyed on "scan" fires when a scan's findings match
// its conditions (max severity, cve_count, fixable_count, image, ...).
//
// Webhook actions fire inside the injected evaluator (which owns the notify dispatcher, like
// the runtime path). The returned non-webhook actions are applied here: quarantine reuses the
// origin='auto' quarantine_entries bridge (scoped to the image, NeuVector's "block this
// vulnerable image at admission" primitive); suppress_log/tag stay audit-recorded.
package scanning

import (
	"context"
	"log/slog"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/imageid"
	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/quarantine"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// scanSeverityRank orders the normalized severities so the per-scan max can be computed.
func scanSeverityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

// scanResponseRuleEvent folds a completed scan's findings down to the E1 EventScan shape. It
// is pure (no DB / receiver) so the field derivation is unit-testable. Fields are the
// string-valued attributes an EventScan rule's Condition.Field can reference:
//
//	image, image_repository, image_digest, namespace, workload_id, source_type,
//	severity (max severity across findings), cve_count, fixable_count, kev_count, highest_cve.
func scanResponseRuleEvent(target handler.ScanTarget, identity scanImageIdentity, findings []scanner.Finding) *responserule.Event {
	maxRank := 0
	maxSev := "info"
	highestCVE := ""
	fixable := 0
	kev := 0
	for i := range findings {
		f := findings[i]
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if sev == "" || sev == "negligible" || sev == "unknown" {
			sev = "info"
		}
		if r := scanSeverityRank(sev); r > maxRank {
			maxRank = r
			maxSev = sev
			highestCVE = strings.TrimSpace(f.VulnerabilityID)
		}
		if strings.TrimSpace(f.FixedVersion) != "" {
			fixable++
		}
		if f.KEVListed {
			kev++
		}
	}

	image := strings.TrimSpace(identity.Ref)
	if image == "" {
		image = strings.TrimSpace(target.ImageRef)
	}
	if image == "" {
		image = strings.TrimSpace(target.Ref)
	}

	fields := map[string]string{
		"image":            image,
		"image_repository": strings.TrimSpace(identity.Repository),
		"image_digest":     strings.TrimSpace(identity.Digest),
		"namespace":        "",
		"workload_id":      strings.TrimSpace(target.Ref),
		"source_type":      strings.TrimSpace(target.SourceType),
		"target_type":      strings.TrimSpace(target.Type),
		"severity":         maxSev,
		"cve_count":        strconv.Itoa(len(findings)),
		"fixable_count":    strconv.Itoa(fixable),
		"kev_count":        strconv.Itoa(kev),
		"highest_cve":      highestCVE,
	}
	return &responserule.Event{Type: responserule.EventScan, Fields: fields}
}

// dispatchScanResponseRules evaluates the org's enabled EventScan rules against the scan
// result and applies the ordered matching actions. Panic-isolated/best-effort so a buggy rule
// can never roll back or 500 the scan ingest (it runs after the txn commit).
func (h *ScanJobs) dispatchScanResponseRules(ctx context.Context, orgID uuid.UUID, target handler.ScanTarget, identity scanImageIdentity, findings []scanner.Finding) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Default().Error("scan response-rule dispatch panic", slog.Any("recover", rec))
		}
	}()
	ev := scanResponseRuleEvent(target, identity, findings)
	actions, err := h.evalResponseRules(ctx, orgID, ev)
	if err != nil {
		slog.Default().Warn("scan response-rule evaluate", slog.Any("err", err))
		return
	}
	h.applyScanResponseRuleActions(ctx, orgID, target, identity, ev, actions)
}

// applyScanResponseRuleActions applies the ordered E1 actions in the data plane. quarantine
// records an origin='auto', scope='image' quarantine_entries row (the same insert the runtime
// bridge uses) so the vulnerable image is blocked at next admission — but only when the scan
// is attributable to a cluster (target.ClusterID); a registry/repository scan with no cluster
// has nowhere to enforce, so it is audit-recorded only. suppress_log/tag are metadata-only and
// stay audit-recorded. Webhook delivery already happened inside the evaluator.
func (h *ScanJobs) applyScanResponseRuleActions(ctx context.Context, orgID uuid.UUID, target handler.ScanTarget, identity scanImageIdentity, ev *responserule.Event, actions []responserule.Action) {
	for i := range actions {
		a := actions[i]
		oid := orgID
		after := map[string]any{
			"action":      string(a.Type),
			"order":       i,
			"severity":    ev.Fields["severity"],
			"cve_count":   ev.Fields["cve_count"],
			"image":       ev.Fields["image"],
			"target_type": target.Type,
			"target_ref":  target.Ref,
		}
		for k, v := range a.Params {
			after["param_"+k] = v
		}
		if a.Type == responserule.ActionQuarantine {
			matchKey := scanImageMatchKey(target, identity)
			switch {
			case target.Type != "image":
				after["enforced"] = "skipped"
				after["enforce_skip_reason"] = "non-image scan target"
			case matchKey == "":
				after["enforced"] = "skipped"
				after["enforce_skip_reason"] = "no image match key"
			case target.ClusterID != nil:
				if err := h.recordImageQuarantine(ctx, orgID, *target.ClusterID, matchKey, "response_rule: scan "+ev.Fields["severity"]); err != nil {
					after["enforce_error"] = err.Error()
					slog.Default().Warn("scan response-rule quarantine", slog.Any("err", err), slog.String("image", matchKey))
				} else {
					after["enforced"] = "quarantine"
					after["enforce_match_key"] = matchKey
				}
			default:
				// Registry/repository scan (cluster_id NULL): block the image on every cluster
				// currently running it, resolved via image_workload_links the same way
				// scanTargetClusters does. This is the canonical "scan in registry, block at
				// admission" case — without this it audit-logged enforced=skipped and the
				// vulnerable image was never quarantined.
				clusters, err := h.quarantineImageClusters(ctx, orgID, target, identity)
				switch {
				case err != nil:
					after["enforce_error"] = err.Error()
					slog.Default().Warn("scan response-rule quarantine cluster resolve", slog.Any("err", err), slog.String("image", matchKey))
				case len(clusters) == 0:
					after["enforced"] = "skipped"
					after["enforce_skip_reason"] = "image not running on any cluster"
				default:
					enforced := make([]string, 0, len(clusters))
					for _, cid := range clusters {
						if err := h.recordImageQuarantine(ctx, orgID, cid, matchKey, "response_rule: scan "+ev.Fields["severity"]); err != nil {
							after["enforce_error"] = err.Error()
							slog.Default().Warn("scan response-rule quarantine", slog.Any("err", err), slog.String("image", matchKey), slog.String("cluster", cid.String()))
							continue
						}
						enforced = append(enforced, cid.String())
					}
					if len(enforced) > 0 {
						after["enforced"] = "quarantine"
						after["enforce_match_key"] = matchKey
						after["enforce_clusters"] = enforced
					}
				}
			}
		}
		_, _, _ = h.audit.Log(ctx, audit.Event{
			OrgID:      &oid,
			Action:     "response_rule.action." + string(a.Type),
			TargetKind: "image",
			TargetID:   ev.Fields["image"],
			After:      after,
		})
	}
}

// scanImageMatchKey derives the scope='image' quarantine match key (a prefix matched against
// a pod's container image at admission). Prefer the repository so every tag of the vulnerable
// image is blocked; fall back to the concrete ref.
func scanImageMatchKey(target handler.ScanTarget, identity scanImageIdentity) string {
	if v := strings.TrimSpace(identity.Repository); v != "" {
		return v
	}
	if v := strings.TrimSpace(identity.Ref); v != "" {
		return v
	}
	if v := strings.TrimSpace(target.ImageRef); v != "" {
		return v
	}
	return strings.TrimSpace(target.Ref)
}

// quarantineImageClusters resolves the distinct clusters currently running the scanned image
// via image_workload_links, used to enforce a quarantine for registry/repository scans that
// carry no cluster_id. It mirrors scanTargetClusters' link query but runs on the pool (this
// path executes post-commit, outside the ingest transaction).
func (h *ScanJobs) quarantineImageClusters(ctx context.Context, orgID uuid.UUID, target handler.ScanTarget, identity scanImageIdentity) ([]uuid.UUID, error) {
	ref := strings.TrimSpace(identity.Ref)
	if ref == "" {
		ref = strings.TrimSpace(target.ImageRef)
	}
	if ref == "" {
		ref = strings.TrimSpace(target.Ref)
	}
	normalized := strings.TrimSpace(identity.NormalizedRef)
	if normalized == "" {
		normalized = imageid.Parse(ref).Normalized
	}
	rows, err := h.db.Pool().Query(ctx, `
SELECT DISTINCT cluster_id
  FROM image_workload_links
 WHERE org_id = $1
   AND cluster_id IS NOT NULL
   AND (
        ($2 <> '' AND image_digest = $2)
     OR ($3 <> '' AND image_ref = $3)
     OR ($4 <> '' AND image_ref_normalized = $4)
     OR ($5 <> '' AND image_repository = $5 AND ($6 = '' OR image_tag = $6))
   )
 ORDER BY cluster_id`,
		orgID, identity.Digest, ref, normalized, identity.Repository, identity.Tag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	clusters := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		clusters = append(clusters, id)
	}
	return clusters, rows.Err()
}

// recordImageQuarantine inserts an origin='auto', scope='image' quarantine entry, reusing the
// exact schema/semantics of the runtime quarantine bridge (response_runtime.go record): a
// duplicate active entry (collapsed by uniq_quarantine_active_target) is treated as success.
func (h *ScanJobs) recordImageQuarantine(ctx context.Context, orgID, clusterID uuid.UUID, matchKey, reason string) error {
	matchKey = strings.TrimSpace(matchKey)
	if matchKey == "" || clusterID == uuid.Nil {
		return nil
	}
	if strings.TrimSpace(reason) == "" {
		reason = "auto-response"
	}
	_, err := h.db.Pool().Exec(ctx, `
INSERT INTO quarantine_entries
    (org_id, cluster_id, scope, match_key, reason, origin, source_kind, expires_at)
VALUES ($1, $2, $3, $4, $5, 'auto', 'scan', NOW() + INTERVAL '24 hours')`,
		orgID, clusterID, string(quarantine.ScopeImage), matchKey, reason)
	if err != nil && strings.Contains(err.Error(), "uniq_quarantine_active_target") {
		return nil
	}
	return err
}
