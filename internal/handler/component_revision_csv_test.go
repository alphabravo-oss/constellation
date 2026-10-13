package handler

import (
	"encoding/json"
	"math"
	"testing"
)

func TestComponentReportedConfigRevision(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
		want  string
	}{
		{"number", float64(9), "9"}, {"zero", float64(0), "0"}, {"negative zero", math.Copysign(0, -1), "0"},
		{"integer", int64(9), "9"}, {"number exponent", json.Number("1e1"), "10"},
		{"numeric string", " 0009 ", "9"}, {"all zero string", "0000", "0"}, {"unicode trim", "\ufeff\u00a09\u3000", "9"},
		{"maximum safe", "9007199254740991", "9007199254740991"}, {"unsafe string", "9007199254740992", ""}, {"unsafe number", float64(9007199254740992), ""},
		{"negative", float64(-1), ""}, {"fraction", 1.5, ""}, {"NaN", math.NaN(), ""}, {"infinity", math.Inf(1), ""},
		{"empty", " ", ""}, {"signed string", "+9", ""}, {"exponent string", "1e1", ""}, {"fraction string", "9.0", ""},
		{"boolean", true, ""}, {"array", []any{9}, ""}, {"object", map[string]any{"value": 9}, ""}, {"null", nil, ""}, {"non-JS whitespace", "\u00859\u0085", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := map[string]any{"system_config_revision": test.value, "config_revision": 99, "api_token": "private"}
			if got := componentReportedConfigRevision(metadata); got != test.want {
				t.Fatalf("got %q want %q", got, test.want)
			}
			public := componentPublicMetadata(metadata)
			if got := componentReportedConfigRevision(public); got != test.want {
				t.Fatalf("public JSON/CSV mismatch: %q want %q", got, test.want)
			}
			if _, found := public["api_token"]; found {
				t.Fatal("unrelated secret exposed")
			}
			if _, found := public["config_revision"]; found {
				t.Fatal("unrelated revision exposed")
			}
		})
	}
	if got := componentReportedConfigRevision(map[string]any{"config_revision": 9}); got != "" {
		t.Fatalf("unrelated metadata became revision evidence: %s", got)
	}
}
