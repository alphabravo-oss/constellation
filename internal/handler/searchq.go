package handler

import (
	searchdsl "github.com/alphabravocompany/constellation/pkg/search/dsl"
)

// Schemas exposed to the search DSL parser, one per first-class resource list.
// Keys are the user-visible field names (case-insensitive); values are SQL
// column expressions that must already be in scope for the wrapping query.

var assetsSearchSchema = searchdsl.Schema{
	Fields: map[string]searchdsl.Field{
		"name":        {Column: "a.name", Type: searchdsl.FieldString},
		"kind":        {Column: "a.kind", Type: searchdsl.FieldString},
		"criticality": {Column: "a.criticality", Type: searchdsl.FieldString},
		"digest":      {Column: "COALESCE(a.digest,'')", Type: searchdsl.FieldString},
		"registry":    {Column: "COALESCE(i.registry,'')", Type: searchdsl.FieldString},
		"repository":  {Column: "COALESCE(i.repository,'')", Type: searchdsl.FieldString},
		"tag":         {Column: "COALESCE(i.tag,'')", Type: searchdsl.FieldString},
		"ai":          {Column: "a.ai_workload", Type: searchdsl.FieldBool},
		"last_seen":   {Column: "a.last_seen_at", Type: searchdsl.FieldTime},
	},
}
