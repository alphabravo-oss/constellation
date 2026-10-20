package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Dashboard links carry the exact returned IDs so new organization activity
// cannot replace the records an operator selected. An empty set stays empty.
func auditEventCohort(r *http.Request) ([]int64, bool, error) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, false, fmt.Errorf("invalid query")
	}
	if !values.Has("event_ids") {
		return nil, false, nil
	}
	if len(values["event_ids"]) != 1 {
		return nil, true, fmt.Errorf("event_ids must occur once")
	}
	for _, key := range []string{"cluster_id", "event_id", "support_bundle_job_id", "action", "framework", "control"} {
		if values.Get(key) != "" {
			return nil, true, fmt.Errorf("event_ids cannot be combined with %s", key)
		}
	}
	ids := []int64{}
	raw := values.Get("event_ids")
	if raw == "" {
		return ids, true, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 20 {
		return nil, true, fmt.Errorf("event_ids supports at most 20 IDs")
	}
	seen := map[int64]bool{}
	for _, part := range parts {
		id, err := strconv.ParseInt(part, 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != part {
			return nil, true, fmt.Errorf("invalid event_ids")
		}
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	return ids, true, nil
}
