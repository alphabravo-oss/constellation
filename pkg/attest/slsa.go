// Package attest emits SLSA Provenance v1.0 + in-toto Statement attestations.
//
// SLSA v1.0 (https://slsa.dev/spec/v1.0/provenance) describes how an artifact was built.
// in-toto Statement (https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
// is the envelope; SLSA Provenance is one of several predicate types it carries.
//
// We emit:
//   - a Provenance struct ready to be wrapped in a Statement
//   - a Statement struct with PredicateType=SLSA, Subject=our artifact digest
//   - JSON serializers that produce signing-ready bytes for cosign attest --predicate
package attest

import (
	"encoding/json"
	"strings"
	"time"
)

// Statement is the in-toto v1 attestation envelope. Subjects identify the artifact(s);
// predicate is type-discriminated by predicateType.
type Statement struct {
	Type          string      `json:"_type"`
	Subject       []Subject   `json:"subject"`
	PredicateType string      `json:"predicateType"`
	Predicate     interface{} `json:"predicate"`
}

// Subject is one artifact the attestation is about.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"` // {"sha256": "<hex>"}
}

// Provenance is the SLSA v1.0 predicate.
type Provenance struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

type BuildDefinition struct {
	BuildType            string                 `json:"buildType"`
	ExternalParameters   map[string]interface{} `json:"externalParameters"`
	InternalParameters   map[string]interface{} `json:"internalParameters,omitempty"`
	ResolvedDependencies []ResourceDescriptor   `json:"resolvedDependencies,omitempty"`
}

type RunDetails struct {
	Builder   Builder              `json:"builder"`
	Metadata  Metadata             `json:"metadata"`
	Byproducts []ResourceDescriptor `json:"byproducts,omitempty"`
}

type Builder struct {
	ID       string                 `json:"id"`
	Version  map[string]string      `json:"version,omitempty"`
	BuilderDependencies []ResourceDescriptor `json:"builderDependencies,omitempty"`
}

type Metadata struct {
	InvocationID string    `json:"invocationId"`
	StartedOn    time.Time `json:"startedOn"`
	FinishedOn   time.Time `json:"finishedOn"`
}

type ResourceDescriptor struct {
	Name   string            `json:"name,omitempty"`
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

const (
	InTotoStatementType = "https://in-toto.io/Statement/v1"
	SLSAv1PredicateType = "https://slsa.dev/provenance/v1"
)

// ProvenanceInput is what the caller passes in to BuildProvenance.
type ProvenanceInput struct {
	// ArtifactName is the canonical name of the built artifact (image ref, package id, etc.).
	ArtifactName string

	// ArtifactSHA256 is the hex sha256 digest (without "sha256:" prefix).
	ArtifactSHA256 string

	// SourceURI is the source-control URL the build was run from (e.g. git+https://…).
	SourceURI string

	// SourceCommit is the commit hash the source was at.
	SourceCommit string

	// BuilderID identifies the builder (e.g. "https://github.com/actions/runner" for GHA).
	BuilderID string

	// BuilderVersion is the builder version map (e.g. {"actions/runner": "2.319.1"}).
	BuilderVersion map[string]string

	// BuildType is the SLSA build-type URI (e.g. https://slsa.dev/buildtype/github-actions/v1).
	BuildType string

	// InvocationID is the unique-per-build identifier (e.g. GHA run id).
	InvocationID string

	// Started + Finished are the wall-clock window of the build.
	Started, Finished time.Time
}

// BuildProvenance constructs a SLSA Provenance v1.0 predicate from the input.
func BuildProvenance(in ProvenanceInput) Provenance {
	deps := []ResourceDescriptor{}
	if in.SourceURI != "" || in.SourceCommit != "" {
		deps = append(deps, ResourceDescriptor{
			URI:    in.SourceURI,
			Digest: nonEmptyDigest("gitCommit", in.SourceCommit),
		})
	}
	return Provenance{
		BuildDefinition: BuildDefinition{
			BuildType: in.BuildType,
			ExternalParameters: map[string]interface{}{
				"source": in.SourceURI,
			},
			ResolvedDependencies: deps,
		},
		RunDetails: RunDetails{
			Builder: Builder{
				ID:      in.BuilderID,
				Version: in.BuilderVersion,
			},
			Metadata: Metadata{
				InvocationID: in.InvocationID,
				StartedOn:    in.Started.UTC(),
				FinishedOn:   in.Finished.UTC(),
			},
		},
	}
}

// WrapStatement places the predicate (typically a Provenance) inside an in-toto v1 Statement.
func WrapStatement(in ProvenanceInput, predicate interface{}) Statement {
	return Statement{
		Type:          InTotoStatementType,
		Subject:       []Subject{{Name: in.ArtifactName, Digest: map[string]string{"sha256": in.ArtifactSHA256}}},
		PredicateType: SLSAv1PredicateType,
		Predicate:     predicate,
	}
}

// Marshal returns the canonical JSON bytes for the statement, ready to be signed by
// `cosign attest --predicate <file>`.
func Marshal(s Statement) ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

func nonEmptyDigest(alg, val string) map[string]string {
	if val == "" {
		return nil
	}
	// Allow callers to pass "<alg>:<val>"; split if so.
	if i := strings.Index(val, ":"); i > 0 {
		alg = val[:i]
		val = val[i+1:]
	}
	return map[string]string{alg: val}
}
