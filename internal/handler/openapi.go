package handler

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

//go:embed openapi.json
var openapiJSON []byte

// OpenAPISpec serves the OpenAPI 3.1 spec at /openapi.json.
//
// The spec is MECHANICALLY generated from the live chi router (see
// internal/server/openapi.go + the openapigen generator) and merged with any
// hand-written summaries/schemas kept under paths. TestOpenAPICompleteness in
// internal/server walks the router and fails the build if any registered
// route+method lacks a spec entry, so the spec cannot silently drift.
func OpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write(openapiJSON)
}

// OpenAPIBytes returns the embedded spec bytes. Used by the generator and the
// completeness gate so they operate on the exact spec the server serves.
func OpenAPIBytes() []byte { return openapiJSON }

// openAPIDoc is the minimal shape we introspect: a map of path -> (method ->
// operation object). Operations are kept as raw JSON so hand-written
// descriptions/schemas are preserved verbatim when the spec is regenerated.
type openAPIDoc struct {
	rest  map[string]json.RawMessage // every top-level key except "paths"
	paths map[string]map[string]json.RawMessage
}

// parseOpenAPI decodes the spec into an introspectable form, preserving every
// top-level field and every per-operation object as raw JSON.
func parseOpenAPI(b []byte) (*openAPIDoc, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return nil, err
	}
	doc := &openAPIDoc{rest: map[string]json.RawMessage{}, paths: map[string]map[string]json.RawMessage{}}
	for k, v := range top {
		if k == "paths" {
			if err := json.Unmarshal(v, &doc.paths); err != nil {
				return nil, err
			}
			continue
		}
		doc.rest[k] = v
	}
	if doc.paths == nil {
		doc.paths = map[string]map[string]json.RawMessage{}
	}
	return doc, nil
}

// httpMethods are the HTTP verbs an OpenAPI path-item may carry as operations.
// Anything else under a path item (e.g. "parameters") is not a method.
var httpMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"patch": true, "head": true, "options": true, "trace": true,
}

// DocumentedRoutes returns the set of "METHOD path" keys (method upper-cased)
// the embedded spec documents. Used by the completeness gate.
func DocumentedRoutes() (map[string]bool, error) {
	doc, err := parseOpenAPI(openapiJSON)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for path, item := range doc.paths {
		for method := range item {
			if !httpMethods[strings.ToLower(method)] {
				continue
			}
			out[strings.ToUpper(method)+" "+path] = true
		}
	}
	return out, nil
}

// operationIsStub reports whether an operation object is a content-free
// auto-generated stub rather than real documentation. A stub is what
// MergeOpenAPI emits for a new route: a summary plus a single {"200":{...}}
// response and nothing else (no requestBody, no parameters, no non-2xx
// responses, no schema-bearing content). The classifier is deliberately strict
// so that the moment an author adds ANY substance the operation is no longer a
// stub — that is what lets the gate ratchet down the stub count over time.
func operationIsStub(raw json.RawMessage) bool {
	var op struct {
		RequestBody json.RawMessage            `json:"requestBody"`
		Parameters  json.RawMessage            `json:"parameters"`
		Responses   map[string]json.RawMessage `json:"responses"`
	}
	if err := json.Unmarshal(raw, &op); err != nil {
		return false // unparseable: treat as non-stub so it surfaces elsewhere
	}
	if len(op.RequestBody) > 0 || len(op.Parameters) > 0 {
		return false
	}
	// Any response other than a lone 2xx, or a 2xx that carries a content body
	// (schemas), means the author documented something real.
	if len(op.Responses) != 1 {
		return false
	}
	for code, body := range op.Responses {
		if !strings.HasPrefix(code, "2") {
			return false // a documented error response is real content
		}
		var r struct {
			Content json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal(body, &r); err == nil && len(r.Content) > 0 {
			return false // a response schema is real content
		}
	}
	return true
}

// StubRoutes returns the set of "METHOD path" keys whose operation is a
// content-free stub (see operationIsStub). The completeness gate uses this to
// report the real documented-vs-stub ratio and to ratchet the stub count down.
func StubRoutes() (map[string]bool, error) {
	doc, err := parseOpenAPI(openapiJSON)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for path, item := range doc.paths {
		for method, op := range item {
			if !httpMethods[strings.ToLower(method)] {
				continue
			}
			if operationIsStub(op) {
				out[strings.ToUpper(method)+" "+path] = true
			}
		}
	}
	return out, nil
}

// DocumentedRouteCount returns how many distinct route+method operations the
// embedded spec documents. Used for coverage reporting.
func DocumentedRouteCount() int {
	docs, err := DocumentedRoutes()
	if err != nil {
		return 0
	}
	return len(docs)
}

// SortedDocumentedRoutes returns the documented "METHOD path" keys sorted, for
// stable diagnostics.
func SortedDocumentedRoutes() []string {
	docs, _ := DocumentedRoutes()
	out := make([]string, 0, len(docs))
	for k := range docs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
