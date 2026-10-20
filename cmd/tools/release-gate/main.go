// release-gate gates and promotes digest-pinned release images using an unsuppressed Grype scan.
//
//	release-gate gate    --image repo@sha256:... --report out/scan.json --receipt out/gate.json [--reuse-report]
//	release-gate promote --image repo@sha256:... --tag repo:vX.Y.Z --report out/scan.json --receipt out/gate.json
//
// Candidate images may exist in the registry; release tags are only created after a passing
// gate. The policy is "no fixable critical or high" — known fixes, not exploitability.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	digestRe = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	tagRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	maxDBAge = 5 * 24 * time.Hour
)

type identity struct {
	Image           string `json:"image"`
	RuntimeManifest string `json:"runtime_manifest"`
	Configuration   string `json:"configuration"`
}

type receipt struct {
	identity
	Passed         bool             `json:"passed"`
	Policy         string           `json:"policy"`
	ScannerVersion string           `json:"scanner_version"`
	Database       map[string]any   `json:"database"`
	Counts         map[string]int   `json:"counts"`
	Blockers       []map[string]any `json:"blockers"`
	EvaluatedAt    string           `json:"evaluated_at"`
	ReportSHA256   string           `json:"report_sha256"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "gate":
		err = runGate(os.Args[2:])
	case "promote":
		err = runPromote(os.Args[2:])
	default:
		usage()
	}
	var exit exitCode
	if errors.As(err, &exit) {
		os.Exit(int(exit))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "release-gate:", err)
		os.Exit(1)
	}
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func usage() {
	fmt.Fprintln(os.Stderr, "usage: release-gate gate|promote [flags]")
	os.Exit(2)
}

func runGate(args []string) error {
	fs := flag.NewFlagSet("gate", flag.ExitOnError)
	image := fs.String("image", "", "repository@sha256 digest")
	report := fs.String("report", "", "Grype JSON report path (written unless --reuse-report)")
	receiptPath := fs.String("receipt", "", "gate receipt path")
	reuse := fs.Bool("reuse-report", false, "validate an existing report against the registry image")
	_ = fs.Parse(args)
	if *image == "" || *report == "" || *receiptPath == "" {
		return errors.New("--image, --report and --receipt are required")
	}
	// A failed rerun must not leave a previous passing receipt behind.
	_ = os.Remove(*receiptPath)
	id, err := imageIdentity(*image)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*report), 0o750); err != nil {
		return err
	}
	if !*reuse {
		_ = os.Remove(*report)
		if err := runGrype(*image, *report); err != nil {
			return err
		}
	}
	raw, err := os.ReadFile(*report)
	if err != nil {
		return err
	}
	rec, err := evaluate(raw, id, time.Now().UTC())
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	rec.ReportSHA256 = hex.EncodeToString(sum[:])
	if err := os.MkdirAll(filepath.Dir(*receiptPath), 0o750); err != nil {
		return err
	}
	out, _ := json.MarshalIndent(rec, "", "  ")
	if err := os.WriteFile(*receiptPath, append(out, '\n'), 0o600); err != nil {
		return err
	}
	summary, _ := json.Marshal(map[string]any{"passed": rec.Passed, "counts": rec.Counts, "blockers": len(rec.Blockers)})
	fmt.Println(string(summary))
	if !rec.Passed {
		return exitCode(2)
	}
	return nil
}

func runPromote(args []string) error {
	fs := flag.NewFlagSet("promote", flag.ExitOnError)
	image := fs.String("image", "", "repository@sha256 digest")
	tag := fs.String("tag", "", "release tag to create (same repository)")
	report := fs.String("report", "", "Grype JSON report path")
	receiptPath := fs.String("receipt", "", "gate receipt path")
	_ = fs.Parse(args)
	if *image == "" || *tag == "" || *report == "" || *receiptPath == "" {
		return errors.New("--image, --tag, --report and --receipt are required")
	}
	id, err := imageIdentity(*image)
	if err != nil {
		return err
	}
	repository, digest, _ := strings.Cut(*image, "@")
	if !strings.HasPrefix(*tag, repository+":") || !tagRe.MatchString(strings.TrimPrefix(*tag, repository+":")) {
		return errors.New("release tag must belong to the scanned repository")
	}
	raw, err := os.ReadFile(*report)
	if err != nil {
		return err
	}
	recRaw, err := os.ReadFile(*receiptPath)
	if err != nil {
		return err
	}
	var rec receipt
	if err := json.Unmarshal(recRaw, &rec); err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if !rec.Passed || rec.ReportSHA256 != hex.EncodeToString(sum[:]) || rec.identity != id {
		return errors.New("passing receipt does not bind this image and report")
	}
	// Re-check the report instead of trusting a boolean or an expired receipt.
	fresh, err := evaluate(raw, id, time.Now().UTC())
	if err != nil {
		return err
	}
	if !fresh.Passed {
		return errors.New("image does not pass the current release gate")
	}
	existing, err := remoteDigest(*tag)
	if err != nil {
		return err
	}
	if existing != "" && existing != digest {
		return errors.New("refusing to overwrite an existing release tag")
	}
	if existing == "" {
		if _, err := docker("buildx", "imagetools", "create", "--prefer-index=false", "--tag", *tag, *image); err != nil {
			return err
		}
	}
	if got, err := remoteDigest(*tag); err != nil || got != digest {
		return errors.New("promoted release differs from scanned OCI digest")
	}
	out, _ := json.Marshal(map[string]any{"image": *image, "release_tag": *tag, "verified": true})
	fmt.Println(string(out))
	return nil
}

func docker(args ...string) ([]byte, error) {
	cmd := exec.Command("docker", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// remoteDigest returns the manifest digest a tag resolves to, or "" when the tag does not exist.
func remoteDigest(ref string) (string, error) {
	out, err := docker("buildx", "imagetools", "inspect", "--format", "{{.Manifest.Digest}}", ref)
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "not found") || strings.Contains(msg, "manifest unknown") || strings.Contains(msg, "no such manifest") {
			return "", nil
		}
		return "", err
	}
	d := strings.TrimSpace(string(out))
	if !digestRe.MatchString(d) {
		return "", fmt.Errorf("unexpected digest %q for %s", d, ref)
	}
	return d, nil
}

func imageIdentity(image string) (identity, error) {
	repository, digest, ok := strings.Cut(image, "@")
	if !ok || repository == "" || strings.HasPrefix(repository, "-") || !digestRe.MatchString(digest) {
		return identity{}, errors.New("release image must be a repository@sha256 digest")
	}
	raw, err := docker("buildx", "imagetools", "inspect", "--raw", image)
	if err != nil {
		return identity{}, err
	}
	var root struct {
		Manifests []struct {
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
			Platform    struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		return identity{}, err
	}
	runtimeDigest := digest
	if len(root.Manifests) > 0 {
		var runtimes []string
		for _, m := range root.Manifests {
			if m.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
				continue
			}
			if m.Platform.OS != "linux" || m.Platform.Architecture != "amd64" {
				return identity{}, errors.New("gate currently requires exactly one linux/amd64 runtime; other platforms need separate scans")
			}
			runtimes = append(runtimes, m.Digest)
		}
		if len(runtimes) != 1 {
			return identity{}, errors.New("gate currently requires exactly one linux/amd64 runtime; other platforms need separate scans")
		}
		runtimeDigest = runtimes[0]
		if !digestRe.MatchString(runtimeDigest) {
			return identity{}, errors.New("invalid runtime manifest digest")
		}
		raw, err = docker("buildx", "imagetools", "inspect", "--raw", repository+"@"+runtimeDigest)
		if err != nil {
			return identity{}, err
		}
		root.Config.Digest = ""
		if err := json.Unmarshal(raw, &root); err != nil {
			return identity{}, err
		}
	}
	if !digestRe.MatchString(root.Config.Digest) {
		return identity{}, errors.New("invalid image configuration digest")
	}
	return identity{Image: image, RuntimeManifest: runtimeDigest, Configuration: root.Config.Digest}, nil
}

func runGrype(image, report string) error {
	// Ignore user/CI Grype and Syft policy overrides (ignore rules, package exclusions, VEX
	// suppressions, stale-database overrides).
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GRYPE_") || strings.HasPrefix(kv, "SYFT_") {
			continue
		}
		env = append(env, kv)
	}
	scratch, err := os.MkdirTemp("", "release-gate")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)
	cfg := filepath.Join(scratch, "grype.yaml")
	if err := os.WriteFile(cfg, []byte("{}\n"), 0o600); err != nil {
		return err
	}
	cmd := exec.Command("grype", "registry:"+image, "--platform", "linux/amd64", "--config", cfg,
		"--scope", "squashed", "--output", "json", "--file", report)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

type grypeReport struct {
	Source struct {
		Type   string `json:"type"`
		Target struct {
			UserInput    string `json:"userInput"`
			ImageID      string `json:"imageID"`
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		} `json:"target"`
	} `json:"source"`
	Descriptor struct {
		Name          string         `json:"name"`
		Version       string         `json:"version"`
		Configuration map[string]any `json:"configuration"`
		DB            struct {
			Status map[string]any `json:"status"`
		} `json:"db"`
	} `json:"descriptor"`
	IgnoredMatches []any `json:"ignoredMatches"`
	Matches        *[]struct {
		Vulnerability struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Fix      struct {
				State    string `json:"state"`
				Versions *[]any `json:"versions"`
			} `json:"fix"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifact"`
	} `json:"matches"`
}

func evaluate(raw []byte, id identity, now time.Time) (receipt, error) {
	var r grypeReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return receipt{}, fmt.Errorf("parse report: %w", err)
	}
	if r.Source.Type != "image" || r.Source.Target.UserInput != id.Image || r.Source.Target.ImageID != id.Configuration {
		return receipt{}, errors.New("scan report does not match the selected immutable image")
	}
	if r.Source.Target.OS != "linux" || r.Source.Target.Architecture != "amd64" {
		return receipt{}, errors.New("report must cover linux/amd64")
	}
	cfg := r.Descriptor.Configuration
	for _, opt := range []string{"exclude", "only-fixed", "only-notfixed", "ignore-wontfix", "vex-documents", "vex-add", "distro"} {
		if truthy(cfg[opt]) {
			return receipt{}, errors.New("filtered scan configuration is not permitted: " + opt)
		}
	}
	if search, _ := cfg["search"].(map[string]any); search == nil || search["scope"] != "squashed" {
		return receipt{}, errors.New("report must scan the final filesystem")
	}
	if len(r.IgnoredMatches) > 0 {
		return receipt{}, errors.New("suppressed findings are not permitted in release evidence")
	}
	if r.Descriptor.Name != "grype" {
		return receipt{}, errors.New("unsupported vulnerability report")
	}
	db := r.Descriptor.DB.Status
	if db["valid"] != true {
		return receipt{}, errors.New("invalid vulnerability database")
	}
	builtRaw, _ := db["built"].(string)
	built, err := time.Parse(time.RFC3339Nano, builtRaw)
	if err != nil || now.Sub(built) > maxDBAge || built.Sub(now) > 5*time.Minute {
		return receipt{}, errors.New("vulnerability database is stale or has an invalid build time")
	}
	if !truthy(db["from"]) {
		return receipt{}, errors.New("database provenance is missing")
	}
	if r.Matches == nil {
		return receipt{}, errors.New("matches must be an explicit list, including for clean scans")
	}
	counts := map[string]int{}
	blockers := []map[string]any{}
	for _, m := range *r.Matches {
		sev := strings.ToLower(m.Vulnerability.Severity)
		switch sev {
		case "unknown", "negligible", "low", "medium", "high", "critical":
		default:
			return receipt{}, errors.New("unrecognized severity")
		}
		if m.Vulnerability.Fix.Versions == nil {
			return receipt{}, errors.New("invalid fix versions")
		}
		versions := make([]string, 0, len(*m.Vulnerability.Fix.Versions))
		for _, v := range *m.Vulnerability.Fix.Versions {
			s, ok := v.(string)
			if !ok || s == "" {
				return receipt{}, errors.New("invalid fix versions")
			}
			versions = append(versions, s)
		}
		if m.Vulnerability.Fix.State == "fixed" && len(versions) == 0 {
			return receipt{}, errors.New("fixed finding is missing its fixed version")
		}
		counts[sev]++
		if (sev == "critical" || sev == "high") && len(versions) > 0 {
			blockers = append(blockers, map[string]any{
				"id": m.Vulnerability.ID, "severity": sev, "package": m.Artifact.Name,
				"version": m.Artifact.Version, "fixed_versions": versions,
			})
		}
	}
	return receipt{
		identity: id, Passed: len(blockers) == 0, Policy: "no-fixable-critical-or-high",
		ScannerVersion: r.Descriptor.Version, Database: db, Counts: counts, Blockers: blockers,
		EvaluatedAt: now.Format(time.RFC3339Nano),
	}, nil
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}
