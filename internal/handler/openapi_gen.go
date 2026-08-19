package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Route is a single registered (method, path) pair discovered by introspecting
// the chi router. The server package produces these via chi.Walk and hands them
// to MergeOpenAPI so the spec is generated MECHANICALLY from the live router and
// therefore cannot drift from the routes the server actually serves.
type Route struct {
	Method string // upper-case HTTP method, e.g. "GET"
	Path   string // chi route pattern, e.g. "/api/v1/system/config"
}

// publicRoutes are paths whose operations carry no bearer security requirement
// (the global security applies otherwise). Mirrors the `security: []` overrides
// in the hand-written spec so regeneration keeps them unauthenticated.
var publicRoutes = map[string]bool{
	"GET /healthz":                   true,
	"GET /readyz":                    true,
	"GET /metrics":                   true,
	"GET /version":                   true,
	"GET /openapi.json":              true,
	"POST /api/v1/auth/login":        true,
	"POST /api/v1/auth/ldap/login":   true,
	"GET /api/v1/auth/saml/login":    true,
	"POST /api/v1/auth/saml/acs":     true,
	"GET /api/v1/auth/oidc/start":    true,
	"GET /api/v1/auth/oidc/callback": true,
}

// stubSummary derives a human-ish summary for a route that has no hand-written
// entry yet. It is intentionally mechanical — the gate only requires presence,
// not prose; an author can later replace the stub with a richer description and
// regeneration will preserve it.
func stubSummary(method, path string) string {
	verb := map[string]string{
		"GET": "Get", "POST": "Create", "PUT": "Replace",
		"PATCH": "Update", "DELETE": "Delete",
	}[method]
	if verb == "" {
		verb = method
	}
	// Last non-parameter path segment as the noun.
	noun := path
	for _, seg := range strings.Split(path, "/") {
		if seg == "" || strings.HasPrefix(seg, "{") {
			continue
		}
		noun = seg
	}
	return fmt.Sprintf("%s %s", verb, noun)
}

// MergeOpenAPI regenerates the spec from the live route set, preserving every
// existing hand-written operation (summary/description/schemas/security) and
// adding a stub operation for any route+method that lacks one. Routes that are
// no longer registered are dropped, so the spec is an exact mirror of the
// router. The result is deterministic (sorted) and pretty-printed.
func MergeOpenAPI(existing []byte, routes []Route) ([]byte, error) {
	doc, err := parseOpenAPI(existing)
	if err != nil {
		return nil, err
	}

	// Index the live routes by path so we keep only registered operations.
	live := map[string]map[string]bool{} // path -> set of upper methods
	for _, rt := range routes {
		if live[rt.Path] == nil {
			live[rt.Path] = map[string]bool{}
		}
		live[rt.Path][strings.ToUpper(rt.Method)] = true
	}

	newPaths := map[string]map[string]json.RawMessage{}
	for path, methods := range live {
		item := map[string]json.RawMessage{}
		// Preserve any non-method keys (e.g. "parameters") from the old item.
		if old, ok := doc.paths[path]; ok {
			for k, v := range old {
				if !httpMethods[strings.ToLower(k)] {
					item[k] = v
				}
			}
		}
		for upper := range methods {
			lower := strings.ToLower(upper)
			// Reuse a hand-written operation if present (case-insensitive on method).
			if old, ok := doc.paths[path]; ok {
				if op, ok := old[lower]; ok {
					item[lower] = op
					continue
				}
				if op, ok := old[upper]; ok {
					item[lower] = op
					continue
				}
			}
			// Otherwise emit a stub. Public routes drop the bearer requirement.
			op := map[string]any{
				"summary":   stubSummary(upper, path),
				"responses": map[string]any{"200": map[string]any{"description": "ok"}},
			}
			if publicRoutes[upper+" "+path] {
				op["security"] = []any{}
			}
			raw, err := json.Marshal(op)
			if err != nil {
				return nil, err
			}
			item[lower] = raw
		}
		newPaths[path] = item
	}

	// Reassemble the top-level document, preserving every non-paths field.
	out := map[string]json.RawMessage{}
	for k, v := range doc.rest {
		out[k] = v
	}
	pathsRaw, err := marshalSorted(newPaths)
	if err != nil {
		return nil, err
	}
	out["paths"] = pathsRaw

	return marshalSortedTop(out)
}

// marshalSorted marshals the paths map with deterministic key ordering so the
// generated file is diff-stable across runs.
func marshalSorted(paths map[string]map[string]json.RawMessage) (json.RawMessage, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	keys := make([]string, 0, len(paths))
	for k := range paths {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, p := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		pk, _ := json.Marshal(p)
		buf.Write(pk)
		buf.WriteByte(':')
		item := paths[p]
		mkeys := make([]string, 0, len(item))
		for m := range item {
			mkeys = append(mkeys, m)
		}
		sort.Strings(mkeys)
		buf.WriteByte('{')
		for j, m := range mkeys {
			if j > 0 {
				buf.WriteByte(',')
			}
			mk, _ := json.Marshal(m)
			buf.Write(mk)
			buf.WriteByte(':')
			buf.Write(item[m])
		}
		buf.WriteByte('}')
	}
	buf.WriteByte('}')
	return json.RawMessage(buf.Bytes()), nil
}

// marshalSortedTop emits the whole document with stable top-level key ordering
// and 2-space indentation, matching the existing checked-in file's style.
func marshalSortedTop(top map[string]json.RawMessage) ([]byte, error) {
	// Stable, readable order: spec metadata first, paths last.
	order := []string{"openapi", "info", "servers", "components", "security", "paths"}
	seen := map[string]bool{}
	var buf bytes.Buffer
	buf.WriteByte('{')
	first := true
	emit := func(k string) {
		v, ok := top[k]
		if !ok || seen[k] {
			return
		}
		seen[k] = true
		if !first {
			buf.WriteByte(',')
		}
		first = false
		kk, _ := json.Marshal(k)
		buf.Write(kk)
		buf.WriteByte(':')
		buf.Write(v)
	}
	for _, k := range order {
		emit(k)
	}
	// Any unexpected extra top-level keys, sorted, so nothing is lost.
	extra := make([]string, 0)
	for k := range top {
		if !seen[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		emit(k)
	}
	buf.WriteByte('}')

	// Re-indent through the standard encoder for a clean, stable layout.
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, buf.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	pretty.WriteByte('\n')
	return pretty.Bytes(), nil
}
