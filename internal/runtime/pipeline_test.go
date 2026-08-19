package runtime_test

// This test simulates the end-to-end userspace pipeline (no kernel) — a "canned L7
// event" → DPI parser → WAF rule engine → DLP rule engine → verdict. It's intended
// as the smoke-test the deliverables list calls out under VERIFICATION.

import (
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dlp"
	"github.com/alphabravocompany/constellation/internal/runtime/dpi"
	"github.com/alphabravocompany/constellation/internal/runtime/waf"
	"github.com/alphabravocompany/constellation/pkg/runtime/baseline"
)

func TestPipelineDPIWAFDLPSimulator(t *testing.T) {
	wafEng := waf.NewEngine()
	if err := wafEng.AddSensor(waf.BuiltinCRS()); err != nil {
		t.Fatalf("waf: %v", err)
	}
	wafEng.SetMode("default/app", baseline.ModeEnforce)

	dlpEng := dlp.NewEngine()
	if err := dlpEng.AddSensor(dlp.BuiltinSensor()); err != nil {
		t.Fatalf("dlp: %v", err)
	}
	dlpEng.SetMode("default/app", baseline.ModeEnforce)

	// Pipeline sink: WAF/DLP take parsed L7Events.
	var seen []dpi.L7Event
	dpiEng := dpi.NewEngine(func(e dpi.L7Event) { seen = append(seen, e) })

	cases := []struct {
		name      string
		payload   []byte
		wafAction string
		dlpAction string
	}{
		{
			name:      "clean GET",
			payload:   []byte("GET /health HTTP/1.1\r\nHost: api\r\n\r\n"),
			wafAction: "allow",
			dlpAction: "allow",
		},
		{
			name:      "SQLi via query string",
			payload:   []byte("GET /users?id=1+UNION+SELECT+password+FROM+users HTTP/1.1\r\nHost: api\r\n\r\n"),
			wafAction: "block",
			dlpAction: "allow",
		},
		{
			name:      "Credit card leak in body",
			payload:   []byte("POST /pay HTTP/1.1\r\nHost: api\r\nContent-Length: 27\r\n\r\n{\"card\":\"4111111111111111\"}"),
			wafAction: "allow",
			dlpAction: "block",
		},
		{
			name:      "Scanner UA",
			payload:   []byte("GET / HTTP/1.1\r\nHost: api\r\nUser-Agent: sqlmap/1.6\r\n\r\n"),
			wafAction: "alert",
			dlpAction: "allow",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evt := dpiEng.Process(dpi.Flow{WorkloadID: "default/app"}, dpi.DirRequest, c.payload)
			if evt == nil || evt.HTTP == nil {
				t.Fatalf("DPI failed to parse")
			}
			gotWAF := wafEng.Evaluate("default/app", *evt)
			if gotWAF.Action != c.wafAction {
				t.Fatalf("WAF action: got %s want %s (matches=%+v)", gotWAF.Action, c.wafAction, gotWAF.Matches)
			}
			gotDLP := dlpEng.Inspect("default/app", *evt)
			if gotDLP.Action != c.dlpAction {
				t.Fatalf("DLP action: got %s want %s (matches=%+v)", gotDLP.Action, c.dlpAction, gotDLP.Matches)
			}
		})
	}
	if len(seen) == 0 {
		t.Fatalf("DPI sink never fired")
	}
}
