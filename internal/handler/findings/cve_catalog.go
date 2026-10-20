package findings

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	searchdsl "github.com/alphabravocompany/constellation/pkg/search/dsl"
)

type cveCatalogQuery struct {
	where, order  string
	args          []any
	limit, offset int
}

// Catalog intelligence is global, not organization finding evidence. Both reads
// use the same authenticated read-findings route permission and exact predicate.
func parseCVECatalog(r *http.Request, export bool) (cveCatalogQuery, error) {
	v, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return cveCatalogQuery{}, fmt.Errorf("invalid query")
	}
	for _, values := range v {
		if len(values) != 1 {
			return cveCatalogQuery{}, fmt.Errorf("duplicate query parameter")
		}
	}
	out := cveCatalogQuery{limit: 50, order: "kev_listed DESC, epss_probability DESC NULLS LAST, cvss_base DESC NULLS LAST, published_at DESC NULLS LAST, cve_id ASC"}
	if !export {
		if value := v.Get("limit"); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil {
				return out, fmt.Errorf("invalid limit")
			}
			if n > 0 && n <= 200 {
				out.limit = n
			}
		}
		if value := v.Get("offset"); value != "" {
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 || n > inventorylist.MaxOffset {
				return out, fmt.Errorf("invalid offset")
			}
			out.offset = int(n)
		}
	}
	if key := strings.ToLower(strings.TrimSpace(v.Get("sort"))); key != "" {
		col, ok := cveSortColumns[key]
		if !ok {
			return out, fmt.Errorf("unsupported sort")
		}
		direction := strings.ToLower(strings.TrimSpace(v.Get("dir")))
		if direction == "" {
			direction = "desc"
		}
		if direction != "asc" && direction != "desc" {
			return out, fmt.Errorf("unsupported sort direction")
		}
		out.order = col + " " + strings.ToUpper(direction) + " NULLS LAST, cve_id ASC"
	} else if direction := strings.ToLower(strings.TrimSpace(v.Get("dir"))); direction != "" && direction != "asc" && direction != "desc" {
		return out, fmt.Errorf("unsupported sort direction")
	}
	clauses := []string{}
	q := strings.TrimSpace(v.Get("q"))
	if strings.Contains(q, ":") {
		compiled, err := searchdsl.Compile(q, cvesSearchSchema)
		if err != nil {
			return out, fmt.Errorf("search: %w", err)
		}
		if !compiled.Empty() {
			out.args = append(out.args, compiled.Args...)
			clauses = append(clauses, "("+compiled.Where+")")
		}
	} else if q != "" {
		out.args = append(out.args, q)
		i := strconv.Itoa(len(out.args))
		expression := []string{"cve_id ILIKE '%' || $" + i + " || '%'", "$" + i + " = ANY(aliases)", "COALESCE(title,'') ILIKE '%' || $" + i + " || '%'", "COALESCE(description,'') ILIKE '%' || $" + i + " || '%'"}
		if canonical := resolveNickname(q); canonical != "" {
			out.args = append(out.args, canonical)
			expression = append(expression, "cve_id = $"+strconv.Itoa(len(out.args)))
		}
		clauses = append(clauses, "("+strings.Join(expression, " OR ")+")")
	}
	switch v.Get("kev") {
	case "", "false", "0":
	case "true", "1":
		clauses = append(clauses, "kev_listed = TRUE")
	default:
		return out, fmt.Errorf("invalid kev")
	}
	for _, filter := range []struct {
		key, column string
		max         float64
	}{{"epss_gt", "epss_probability", 1}, {"cvss_gt", "cvss_base", 10}} {
		if value := v.Get(filter.key); value != "" {
			threshold, err := strconv.ParseFloat(value, 64)
			if err != nil || math.IsNaN(threshold) || math.IsInf(threshold, 0) || threshold < 0 || threshold > filter.max {
				return out, fmt.Errorf("invalid %s", filter.key)
			}
			if threshold > 0 {
				out.args = append(out.args, threshold)
				clauses = append(clauses, filter.column+" > $"+strconv.Itoa(len(out.args)))
			}
		}
	}
	if severity := strings.ToLower(strings.TrimSpace(v.Get("severity"))); severity != "" {
		lo, hi, ok := severityRange(severity)
		if !ok {
			return out, fmt.Errorf("unsupported severity")
		}
		out.args = append(out.args, lo, hi)
		clauses = append(clauses, "cvss_base >= $"+strconv.Itoa(len(out.args)-1)+" AND cvss_base < $"+strconv.Itoa(len(out.args)))
	}
	if source := strings.TrimSpace(v.Get("source")); source != "" {
		out.args = append(out.args, source)
		clauses = append(clauses, "$"+strconv.Itoa(len(out.args))+" = ANY(sources)")
	}
	if len(clauses) > 0 {
		out.where = "WHERE " + strings.Join(clauses, " AND ")
	}
	if export {
		out.limit = inventorylist.ExportLimit + 1
		out.offset = 0
	}
	return out, nil
}

func (c *CVE) Search(w http.ResponseWriter, r *http.Request)    { c.catalogRead(w, r, false) }
func (c *CVE) SearchCSV(w http.ResponseWriter, r *http.Request) { c.catalogRead(w, r, true) }
func (c *CVE) catalogRead(w http.ResponseWriter, r *http.Request, export bool) {
	if _, ok := authctx.SubjectFrom(r.Context()); !ok {
		apiutil.WriteStatus(r.Context(), w, 401, "subject required")
		return
	}
	options, err := parseCVECatalog(r, export)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, 400, err.Error())
		return
	}
	args := append([]any{}, options.args...)
	args = append(args, options.limit, options.offset)
	// CSV omits the potentially large affected metadata document; the catalog ID
	// preserves the exact detail destination. Every exported scalar keeps precision.
	affected := "affected"
	if export {
		affected = "'null'::jsonb"
	}
	query := `SELECT cve_id,COALESCE(title,''),COALESCE(description,''),cvss_base,cvss_vector,kev_listed,kev_added,epss_probability,epss_updated_at,aliases,` + affected + `,sources,published_at,modified_at FROM cve_records ` + options.where + ` ORDER BY ` + options.order + ` LIMIT $` + strconv.Itoa(len(args)-1) + ` OFFSET $` + strconv.Itoa(len(args))
	rows, err := c.db.Pool().Query(r.Context(), query, args...)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, 500, "CVE catalog could not be loaded")
		return
	}
	defer rows.Close()
	out := make([]cveDTO, 0)
	for rows.Next() {
		var item cveDTO
		var affected []byte
		if err := rows.Scan(&item.CVEID, &item.Title, &item.Description, &item.CVSSBase, &item.CVSSVector, &item.KEVListed, &item.KEVAdded, &item.EPSSProbability, &item.EPSSUpdatedAt, &item.Aliases, &affected, &item.Sources, &item.PublishedAt, &item.ModifiedAt); err != nil {
			apiutil.WriteStatus(r.Context(), w, 500, "CVE catalog could not be loaded")
			return
		}
		item.Affected = affected
		out = append(out, item)
	}
	if rows.Err() != nil {
		apiutil.WriteStatus(r.Context(), w, 500, "CVE catalog could not be loaded")
		return
	}
	if !export {
		httpx.WriteJSON(w, 200, map[string]any{"results": out, "limit": options.limit, "offset": options.offset})
		return
	}
	truncated := len(out) > inventorylist.ExportLimit
	if truncated {
		out = out[:inventorylist.ExportLimit]
	}
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	_ = writer.Write([]string{"cve_id", "title", "description", "cvss_base", "cvss_vector", "kev_listed", "kev_added", "epss_probability", "epss_updated_at", "aliases", "sources", "published_at", "modified_at"})
	for _, item := range out {
		_ = writer.Write([]string{item.CVEID, item.Title, item.Description, catalogFloat(item.CVSSBase), catalogString(item.CVSSVector), strconv.FormatBool(item.KEVListed), catalogTime(item.KEVAdded), catalogFloat(item.EPSSProbability), catalogTime(item.EPSSUpdatedAt), catalogJSON(item.Aliases), catalogJSON(item.Sources), catalogTime(item.PublishedAt), catalogTime(item.ModifiedAt)})
	}
	writer.Flush()
	if writer.Error() != nil {
		apiutil.WriteStatus(r.Context(), w, 500, "CVE catalog export could not be prepared")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="constellation-cve-catalog.csv"`)
	w.Header().Set("X-Export-Rows", strconv.Itoa(len(out)))
	w.Header().Set("X-Export-Limit", strconv.Itoa(inventorylist.ExportLimit))
	w.Header().Set("X-Export-Truncated", strconv.FormatBool(truncated))
	w.WriteHeader(200)
	_, _ = w.Write(buffer.Bytes())
}
func catalogFloat(value *float64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatFloat(*value, 'g', -1, 64)
}
func catalogString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func catalogTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func catalogJSON(value []string) string { body, _ := json.Marshal(value); return string(body) }
