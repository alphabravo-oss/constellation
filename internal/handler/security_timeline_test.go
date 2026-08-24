package handler

import "testing"

func TestParseTimelineSources(t *testing.T) {
	all := parseTimelineSources("")
	for _, source := range allTimelineSources {
		if !all[source] {
			t.Fatalf("empty source filter did not enable %q: %+v", source, all)
		}
	}

	got := parseTimelineSources("audit,dpi_threat,unknown,AUDIT")
	if !got["audit"] || !got["dpi_threat"] {
		t.Fatalf("known sources missing from filter: %+v", got)
	}
	if got["runtime_event"] || got["network_violation"] || got["unknown"] {
		t.Fatalf("unexpected sources enabled: %+v", got)
	}
}
