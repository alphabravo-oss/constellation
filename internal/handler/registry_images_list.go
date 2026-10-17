package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

type registryImageRow struct {
	ID            uuid.UUID         `json:"id"`
	Repository    string            `json:"repository"`
	Tags          []string          `json:"tags"`
	Digests       map[string]string `json:"digests"`
	LastPushedAt  string            `json:"last_pushed_at,omitempty"`
	FirstSeenAt   time.Time         `json:"first_seen_at"`
	LastSeenAt    time.Time         `json:"last_seen_at"`
	Scanned       bool              `json:"scanned"`
	FindingCount  int               `json:"finding_count"`
	LastScannedAt *time.Time        `json:"last_scanned_at,omitempty"`
	Critical      int               `json:"critical"`
	High          int               `json:"high"`
}

func registryImageDefinition(r *http.Request, org, registry uuid.UUID) (inventorylist.Definition, inventorylist.Options, error) {
	values, err := inventorylist.Query(r)
	if err != nil {
		return inventorylist.Definition{}, inventorylist.Options{}, err
	}
	options, err := inventorylist.Parse(values, map[string]string{"repository": "lower(repository)", "scanned": "scanned", "vulnerabilities": "ROW(critical,high,finding_count)", "findings": "ROW(finding_count,last_seen_at)", "last_scanned": "last_scanned_at", "last_seen": "last_seen_at"}, "findings")
	if err != nil {
		return inventorylist.Definition{}, options, err
	}
	scan, err := inventorylist.Filter(values, "scan_status", "scanned", "unscanned")
	if err != nil {
		return inventorylist.Definition{}, options, err
	}
	severity, err := inventorylist.Filter(values, "severity", "critical", "high", "none")
	if err != nil {
		return inventorylist.Definition{}, options, err
	}
	args := []any{org, registry}
	where := []string{"true"}
	if q := strings.TrimSpace(values.Get("q")); q != "" {
		args = append(args, q)
		where = append(where, "strpos(lower(repository),lower($3::text))>0")
	}
	switch scan {
	case "scanned":
		where = append(where, "scanned")
	case "unscanned":
		where = append(where, "NOT scanned")
	}
	switch severity {
	case "critical":
		where = append(where, "critical>0")
	case "high":
		where = append(where, "high>0")
	case "none":
		where = append(where, "scanned AND critical=0 AND high=0")
	}
	return inventorylist.Definition{
		SQL: `SELECT ri.id,ri.repository,ri.tags,COALESCE(ri.digests,'{}'::jsonb),COALESCE(ri.last_pushed_at,''),ri.first_seen_at,ri.last_seen_at,
 sr.id IS NOT NULL,COALESCE(sr.finding_count,0),sr.last_scanned_at,f.critical,f.high
 FROM registry_images ri
 LEFT JOIN LATERAL (
 SELECT r.id,r.finding_count,r.last_scanned_at FROM image_scan_results r
 WHERE r.org_id=$1 AND r.image_repository=ri.repository
 ORDER BY r.last_scanned_at DESC NULLS LAST,r.id DESC LIMIT 1
 ) sr ON true
 LEFT JOIN LATERAL (
 SELECT count(*) FILTER(WHERE severity='critical') AS critical,count(*) FILTER(WHERE severity='high') AS high
 FROM image_scan_findings WHERE org_id=$1 AND image_scan_result_id=sr.id
 ) f ON true
 WHERE ri.org_id=$1 AND ri.registry_id=$2`,
		Columns: "id,repository,tags,digests,last_pushed_at,first_seen_at,last_seen_at,scanned,finding_count,last_scanned_at,critical,high",
		Args:    args, Where: strings.Join(where, " AND "), Summary: `jsonb_build_object('total',count(*),'scanned',count(*) FILTER(WHERE scanned),'unscanned',count(*) FILTER(WHERE NOT scanned),'critical',COALESCE(sum(critical),0),'high',COALESCE(sum(high),0))`,
	}, options, nil
}

func scanRegistryImage(row inventorylist.Row) (registryImageRow, error) {
	var image registryImageRow
	var raw []byte
	err := row.Scan(&image.ID, &image.Repository, &image.Tags, &raw, &image.LastPushedAt, &image.FirstSeenAt, &image.LastSeenAt, &image.Scanned, &image.FindingCount, &image.LastScannedAt, &image.Critical, &image.High)
	if err != nil {
		return image, err
	}
	if image.Tags == nil {
		image.Tags = []string{}
	}
	image.Digests = map[string]string{}
	if err := json.Unmarshal(raw, &image.Digests); err != nil {
		return image, err
	}
	if image.Digests == nil {
		image.Digests = map[string]string{}
	}
	return image, nil
}

func (h *Registries) Images(w http.ResponseWriter, r *http.Request) {
	h.readRegistryImages(w, r, false)
}
func (h *Registries) ImagesCSV(w http.ResponseWriter, r *http.Request) {
	h.readRegistryImages(w, r, true)
}
func (h *Registries) readRegistryImages(w http.ResponseWriter, r *http.Request, export bool) {
	subject, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var exists bool
	if err := h.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM registries WHERE org_id=$1 AND id=$2)`, subject.OrgID, id).Scan(&exists); err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	if !exists {
		jsonError(w, 404, "registry not found")
		return
	}
	definition, options, err := registryImageDefinition(r, subject.OrgID, id)
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	if export {
		body, metadata, err := inventorylist.CSV(r.Context(), h.db.Pool(), definition, options, scanRegistryImage, []string{"ID", "Registry ID", "Repository", "Tags", "Digests", "Scanned", "Finding count", "Critical", "High", "Last scanned at", "Last pushed at", "First seen at", "Last seen at"}, func(image registryImageRow) []string {
			digests, _ := json.Marshal(image.Digests)
			lastScanned := ""
			if image.LastScannedAt != nil {
				lastScanned = image.LastScannedAt.UTC().Format(time.RFC3339Nano)
			}
			return []string{image.ID.String(), id.String(), image.Repository, strings.Join(image.Tags, "; "), string(digests), strconv.FormatBool(image.Scanned), strconv.Itoa(image.FindingCount), strconv.Itoa(image.Critical), strconv.Itoa(image.High), lastScanned, image.LastPushedAt, image.FirstSeenAt.UTC().Format(time.RFC3339Nano), image.LastSeenAt.UTC().Format(time.RFC3339Nano)}
		})
		if err != nil {
			jsonError(w, 500, err.Error())
			return
		}
		inventorylist.WriteCSV(w, "constellation-registry-images.csv", body, metadata)
		return
	}
	images, metadata, err := inventorylist.Read(r.Context(), h.db.Pool(), definition, options, scanRegistryImage)
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"registry_id": id.String(), "images": images, "total": metadata.Total, "summary": metadata.Summary, "limit": options.Limit, "offset": options.Offset, "has_more": metadata.HasMore, "sort": options.Sort, "order": options.Order})
}
