package forensics

import (
	"testing"
	"time"
)

func TestRuntimeArtifactsRoundTrip(t *testing.T) {
	env := Envelope{
		Trigger:    "quarantine",
		CapturedAt: time.Now().UTC(),
		Annotations: map[string]string{
			"runtime": EncodeRuntimeArtifacts(RuntimeArtifacts{
				ManifestSHA256: "deadbeef",
				Components:     []string{"pcap", "proc", "logs"},
				Trigger:        RuntimeTrigger{Source: "waf", Reason: "SQLi", Severity: "critical"},
				Target:         RuntimeTarget{Namespace: "default", Pod: "web-1", PID: 1234},
			}),
		},
	}
	gz, _, err := Capture(env)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Restore(gz)
	if err != nil {
		t.Fatal(err)
	}
	art, ok := DecodeRuntimeArtifacts(got)
	if !ok {
		t.Fatalf("DecodeRuntimeArtifacts missing: %+v", got.Annotations)
	}
	if art.ManifestSHA256 != "deadbeef" || art.Trigger.Source != "waf" || art.Target.PID != 1234 {
		t.Fatalf("bad decode: %+v", art)
	}
}

func TestDecodeRuntimeArtifactsAbsent(t *testing.T) {
	env := &Envelope{}
	if _, ok := DecodeRuntimeArtifacts(env); ok {
		t.Fatal("expected absent")
	}
}
