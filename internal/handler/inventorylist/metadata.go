package inventorylist

import (
	"encoding/json"
	"regexp"
	"strconv"
)

var metadataCount = regexp.MustCompile(`^[0-9]{1,9}$`)

// MetadataFields isolates invalid fields instead of discarding independent source
// identity or posture when one producer writes a differently typed value.
func MetadataFields(raw []byte) map[string]json.RawMessage {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil
	}
	return fields
}
func MetadataText(fields map[string]json.RawMessage, key string) string {
	var text string
	if json.Unmarshal(fields[key], &text) != nil {
		return ""
	}
	return text
}

// MetadataPackageCount matches the bounded digit grammar in inventory SQL. Both
// JSON integers and numeric strings are accepted; malformed values are unknown.
func MetadataPackageCount(fields map[string]json.RawMessage) int {
	raw := fields["package_count"]
	text := string(raw)
	if len(raw) > 0 && raw[0] == '"' {
		text = MetadataText(fields, "package_count")
	}
	if !metadataCount.MatchString(text) {
		return 0
	}
	count, err := strconv.Atoi(text)
	if err != nil {
		return 0
	}
	return count
}
