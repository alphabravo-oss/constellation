package attest

import (
	"encoding/json"
	"testing"
	"time"
)

func TestProvenance_Shape(t *testing.T) {
	in := ProvenanceInput{
		ArtifactName:   "ghcr.io/alphabravocompany/constellation-api",
		ArtifactSHA256: "deadbeef",
		SourceURI:      "git+https://github.com/alphabravocompany/constellation",
		SourceCommit:   "gitCommit:abc123",
		BuilderID:      "https://github.com/actions/runner",
		BuilderVersion: map[string]string{"actions/runner": "2.319.1"},
		BuildType:      "https://slsa.dev/buildtype/github-actions/v1",
		InvocationID:   "1234567890",
		Started:        time.Now().Add(-10 * time.Minute),
		Finished:       time.Now(),
	}
	prov := BuildProvenance(in)
	stmt := WrapStatement(in, prov)
	if stmt.Type != InTotoStatementType {
		t.Fatalf("statement type: %q", stmt.Type)
	}
	if stmt.PredicateType != SLSAv1PredicateType {
		t.Fatalf("predicate type: %q", stmt.PredicateType)
	}
	if len(stmt.Subject) != 1 || stmt.Subject[0].Digest["sha256"] != "deadbeef" {
		t.Fatalf("subject: %+v", stmt.Subject)
	}

	b, err := Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip parses as JSON.
	var roundtrip map[string]any
	if err := json.Unmarshal(b, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if roundtrip["predicateType"] != SLSAv1PredicateType {
		t.Fatalf("roundtrip lost predicate type: %v", roundtrip)
	}
}

func TestNonEmptyDigest_SplitsAlgAndVal(t *testing.T) {
	d := nonEmptyDigest("sha256", "gitCommit:abc")
	if d["gitCommit"] != "abc" {
		t.Fatalf("expected alg=gitCommit, got %+v", d)
	}
}
