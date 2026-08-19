package admission

import "encoding/json"

// jsonUnmarshal is a single-callsite wrapper so tests can inject a decoder error.
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
