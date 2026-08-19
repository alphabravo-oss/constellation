// Bench V2 tags ported from neuvector/controller/rest/bench.go.
//
// Each compliance check carries a TagsV2 map: tag (e.g. "PCI-DSS") → ProfileTag
// (profile id + description + references). Callers can filter the check stream
// by profile, e.g. /api/v1/compliance/checks?profile=pci-dss-4.0.
package compliance

import (
	"sort"
)

// ProfileTag is one (framework, control-references) annotation on a check.
type ProfileTag struct {
	Profile     string   `json:"profile"`
	Description string   `json:"description,omitempty"`
	References  []string `json:"references,omitempty"`
}

// TagsV2 is the JSONB column shape: framework id → ProfileTag.
type TagsV2 map[string]ProfileTag

// BuildTagsV2 expands one internal check ID into its TagsV2 map using the existing
// CoreMappings table — every framework the check maps to becomes a tag with the
// control ID as the only reference, and the mapping title as the description.
func BuildTagsV2(internalID string) TagsV2 {
	for _, m := range CoreMappings {
		if m.InternalID != internalID {
			continue
		}
		out := TagsV2{}
		for fw, controlID := range m.Controls {
			out[fw] = ProfileTag{
				Profile:     fw,
				Description: m.Title,
				References:  []string{controlID},
			}
		}
		return out
	}
	return TagsV2{}
}

// FilterByProfile is a small helper consumed by the /compliance/checks handler:
// returns true iff the check has a tag matching the requested profile (or the
// profile filter is empty).
func FilterByProfile(tags TagsV2, profile string) bool {
	if profile == "" {
		return true
	}
	_, ok := tags[profile]
	return ok
}

// SortedProfiles lists every framework id present in the tag map (sorted).
func SortedProfiles(tags TagsV2) []string {
	out := make([]string, 0, len(tags))
	for k := range tags {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
