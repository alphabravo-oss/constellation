package sigverify

// Multiple named roots-of-trust.
//
// A single global cosign trust policy (identities/issuers/key) is fine for one org that
// trusts one signing setup. Air-gapped and multi-tenant installs need MORE than one:
// NeuVector exposes a REST-managed SigstoreRootOfTrust collection where each named root
// carries its own verifiers plus an optional private Rekor/Fulcio/TUF configuration.
//
// This file adds that shape on top of the existing cosign shell-out: a config type holding
// N named roots (RootsOfTrust), each embedding a TrustPolicy and optional private-sigstore
// endpoints, and VerifyWithRoots which trusts an image if ANY configured root verifies its
// signature. The legacy single-policy path is the N=1 default-root case (see Verify).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RootOfTrust is a single named root-of-trust: a cosign TrustPolicy (identities / issuers /
// key) plus optional private-sigstore endpoint overrides for air-gapped installs. It mirrors
// one entry of NeuVector's SigstoreRootOfTrust collection.
type RootOfTrust struct {
	Name        string // unique name, e.g. "default" or "airgap-internal" (display / reason only)
	TrustPolicy        // embedded: Identities/Issuers/Mode/PublicKey*/RequireRekor/RequireAttestations
	RekorURL    string // private Rekor transparency-log URL ("" = public Rekor)
	TUFMirror   string // private TUF mirror URL for air-gapped roots ("" = public Sigstore TUF)
	TUFRootJSON string // TUF root.json material bootstrapping the mirror (inline JSON text)
	TUFRootPath string // path to a TUF root.json on disk (takes precedence over TUFRootJSON)
}

// RootsOfTrust is an ordered, named collection of roots. An image is trusted if ANY root
// verifies its signature. A legacy single TrustPolicy is the N=1 case via SingleRoot.
type RootsOfTrust []RootOfTrust

// SingleRoot wraps one legacy TrustPolicy as a single default root, so existing callers can
// move to VerifyWithRoots without behaviour change.
func SingleRoot(policy TrustPolicy) RootsOfTrust {
	return RootsOfTrust{{Name: "default", TrustPolicy: policy}}
}

// rootName is the root's name for reason strings, defaulting to "default".
func rootName(r RootOfTrust) string {
	if n := strings.TrimSpace(r.Name); n != "" {
		return n
	}
	return "default"
}

// VerifyWithRoots verifies imageRef against an ordered collection of named roots-of-trust and
// returns the FIRST result that is trusted (multi-root "ANY root verifies" semantics). cosign
// is invoked once per root because each root may point at a different private Rekor/Fulcio/TUF
// endpoint. If no root trusts the image the last-evaluated result is returned untrusted with an
// aggregated, per-root reason. An empty collection returns an untrusted result.
func (v *Verifier) VerifyWithRoots(ctx context.Context, imageRef string, roots []RootOfTrust) (*Result, error) {
	return selectTrustedRoot(imageRef, roots, func(root RootOfTrust) (*Result, error) {
		return v.verifyRoot(ctx, imageRef, root)
	})
}

// selectTrustedRoot is the cosign-independent core of VerifyWithRoots: run verify against each
// named root in order and return the first trusted result, else the last result with an
// aggregated reason. verify is a seam so the ANY-root aggregation is unit-testable without cosign.
func selectTrustedRoot(imageRef string, roots []RootOfTrust, verify func(RootOfTrust) (*Result, error)) (*Result, error) {
	if len(roots) == 0 {
		return &Result{ImageRef: imageRef, Reason: "no roots-of-trust configured"}, nil
	}
	var last *Result
	reasons := make([]string, 0, len(roots))
	for _, root := range roots {
		res, err := verify(root)
		if errors.Is(err, ErrCosignMissing) {
			return nil, err
		}
		if res != nil && res.Trusted {
			res.Reason = fmt.Sprintf("%s (root %q)", res.Reason, rootName(root))
			return res, nil
		}
		switch {
		case res != nil:
			last = res
			reasons = append(reasons, fmt.Sprintf("%s: %s", rootName(root), res.Reason))
		case err != nil:
			reasons = append(reasons, fmt.Sprintf("%s: %v", rootName(root), err))
		}
	}
	if last == nil {
		last = &Result{ImageRef: imageRef}
	}
	last.Trusted = false
	last.Reason = "no root-of-trust verified the signature [" + strings.Join(reasons, "; ") + "]"
	return last, nil
}

// privateSigstoreArgs applies a root's private Rekor/Fulcio/TUF configuration to a cosign
// invocation. It appends verify flags, returns extra environment (KEY=VALUE, layered over
// os.Environ), and a cleanup for any temp files. For air-gapped roots (TUFMirror/TUFRoot set)
// it bootstraps an isolated TUF cache via `cosign initialize --mirror --root` so the following
// verify validates against the private trust root instead of the public Sigstore TUF.
func privateSigstoreArgs(ctx context.Context, v *Verifier, args []string, root RootOfTrust) ([]string, []string, func(), error) {
	cleanup := func() {}
	var env []string

	if u := strings.TrimSpace(root.RekorURL); u != "" {
		args = append(args, "--rekor-url", u)
	}

	tufMirror := strings.TrimSpace(root.TUFMirror)
	tufRootPath, rootCleanup, err := tufRootFile(root)
	if err != nil {
		return nil, nil, cleanup, err
	}
	if tufMirror == "" && tufRootPath == "" {
		return args, env, cleanup, nil
	}

	// Isolated TUF cache so different roots (and the public default) don't clobber each other.
	cacheDir, err := os.MkdirTemp("", "constellation-tuf-cache-*")
	if err != nil {
		rootCleanup()
		return nil, nil, cleanup, fmt.Errorf("tuf cache: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(cacheDir); rootCleanup() }
	env = append(env, "TUF_ROOT="+cacheDir)

	if err := v.initPrivateTUF(ctx, cacheDir, tufMirror, tufRootPath); err != nil {
		cleanup()
		return nil, nil, func() {}, err
	}
	return args, env, cleanup, nil
}

// tufRootFile resolves a root's TUF root.json to a filesystem path, writing inline TUFRootJSON
// to a temp file when no on-disk path is given. Returns ("", noop, nil) when the root has none.
func tufRootFile(root RootOfTrust) (string, func(), error) {
	cleanup := func() {}
	if p := strings.TrimSpace(root.TUFRootPath); p != "" {
		return p, cleanup, nil
	}
	inline := strings.TrimSpace(root.TUFRootJSON)
	if inline == "" {
		return "", cleanup, nil
	}
	dir, err := os.MkdirTemp("", "constellation-tuf-root-*")
	if err != nil {
		return "", cleanup, fmt.Errorf("write TUF root: %w", err)
	}
	path := filepath.Join(dir, "root.json")
	if err := os.WriteFile(path, []byte(inline), 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", func() {}, fmt.Errorf("write TUF root: %w", err)
	}
	return path, func() { _ = os.RemoveAll(dir) }, nil
}

// initPrivateTUF runs `cosign initialize` to seed an isolated TUF cache (TUF_ROOT=cacheDir)
// from a private mirror and/or root.json, the idiomatic air-gapped bootstrap.
func (v *Verifier) initPrivateTUF(ctx context.Context, cacheDir, mirror, rootPath string) error {
	initArgs := []string{"initialize"}
	if mirror != "" {
		initArgs = append(initArgs, "--mirror", mirror)
	}
	if rootPath != "" {
		initArgs = append(initArgs, "--root", rootPath)
	}
	cmd := exec.CommandContext(ctx, v.CosignBinary, initArgs...)
	cmd.Env = append(os.Environ(), "TUF_ROOT="+cacheDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cosign initialize private TUF: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
