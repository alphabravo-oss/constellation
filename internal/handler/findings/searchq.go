package findings

import (
	searchdsl "github.com/alphabravocompany/constellation/pkg/search/dsl"
)

// Search-DSL schemas for the findings domain. Keys are the user-visible field
// names (case-insensitive); values are SQL column expressions that must already
// be in scope for the wrapping query.

var findingsSearchSchema = searchdsl.Schema{
	Fields: map[string]searchdsl.Field{
		"severity":    {Column: "severity", Type: searchdsl.FieldString},
		"kind":        {Column: "kind", Type: searchdsl.FieldString},
		"lifecycle":   {Column: "lifecycle", Type: searchdsl.FieldString},
		"title":       {Column: "title", Type: searchdsl.FieldString},
		"external_id": {Column: "external_id", Type: searchdsl.FieldString},
		// "cve" is an ergonomic alias for external_id since 90% of users will type that.
		// Both `cve:CVE-2021-44228` and `external_id:CVE-2021-44228` should work.
		"cve":              {Column: "external_id", Type: searchdsl.FieldString},
		"risk":             {Column: "risk_score", Type: searchdsl.FieldInt},
		"canonical_engine": {Column: "COALESCE(canonical_engine,'')", Type: searchdsl.FieldString},
		"engine":           {Column: "COALESCE(engines::text,'')", Type: searchdsl.FieldString},
		"package": {
			Column: "COALESCE(detail_json->'package'->>'name', detail_json->'package'->>'Name', detail_json->'affected_range'->>'package_name', '')",
			Type:   searchdsl.FieldString,
		},
		"purl": {
			Column: "COALESCE(detail_json->'package'->>'purl', detail_json->'package'->>'Purl', detail_json->'affected_range'->>'package_purl', '')",
			Type:   searchdsl.FieldString,
		},
		"fixed": {
			Column: "COALESCE(detail_json->>'fixed', detail_json->'affected_range'->>'fixed_version', '')",
			Type:   searchdsl.FieldString,
		},
		"disagreement": {
			Column: "(CASE WHEN jsonb_typeof(detail_json->'reconciliation') = 'array' THEN jsonb_array_length(detail_json->'reconciliation') > 0 ELSE false END)",
			Type:   searchdsl.FieldBool,
		},
		// `reachable:true` matches a finding whose risk_inputs JSONB has any of the
		// reachable_* truthy flags populated by the reachability ingest endpoint.
		// We cast the bool to text and compare to a literal so the DSL bool emitter
		// can stay generic. NULL-safe via COALESCE.
		"reachable": {
			Column: "(COALESCE((risk_inputs->>'reachable_runtime')::boolean,false) OR COALESCE((risk_inputs->>'reachable_static')::boolean,false))",
			Type:   searchdsl.FieldBool,
		},
		"last_seen":  {Column: "last_seen_at", Type: searchdsl.FieldTime},
		"first_seen": {Column: "first_seen_at", Type: searchdsl.FieldTime},
	},
}

var cvesSearchSchema = searchdsl.Schema{
	Fields: map[string]searchdsl.Field{
		"cve":         {Column: "cve_id", Type: searchdsl.FieldString},
		"title":       {Column: "COALESCE(title,'')", Type: searchdsl.FieldString},
		"description": {Column: "COALESCE(description,'')", Type: searchdsl.FieldString},
		"cvss":        {Column: "COALESCE(cvss_base,0)", Type: searchdsl.FieldFloat},
		"epss":        {Column: "COALESCE(epss_probability,0)", Type: searchdsl.FieldFloat},
		"kev":         {Column: "kev_listed", Type: searchdsl.FieldBool},
		"published":   {Column: "published_at", Type: searchdsl.FieldTime},
	},
}
