package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

func VerifyArchive(ctx context.Context, opts RestoreOptions) (*RestoreResult, error) {
	result, _, err := readAndVerifyArchive(ctx, opts)
	return result, err
}

func readAndVerifyArchive(ctx context.Context, opts RestoreOptions) (*RestoreResult, map[string][]byte, error) {
	files, err := readTarGz(opts.In)
	if err != nil {
		return nil, nil, fmt.Errorf("read archive: %w", err)
	}
	manifestBytes, exists := files["manifest.json"]
	if !exists {
		return nil, nil, errors.New("manifest.json missing")
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, nil, errors.New("invalid manifest JSON")
	}
	if manifest.FormatVersion != FormatVersion {
		return nil, nil, errors.New("unsupported backup format version")
	}
	supported := make(map[string]bool, len(OrderedTables))
	for _, table := range OrderedTables {
		supported[table] = true
	}
	for _, table := range manifest.Tables {
		if !supported[table.Name] {
			return nil, nil, fmt.Errorf("unsupported backup table %q", table.Name)
		}
	}
	if err := verifyTableDigests(files, manifest); err != nil {
		return nil, nil, err
	}
	if opts.DestOrgID != "" && !orgIdentityMatches(manifest, files["tables/orgs.jsonl"], opts.DestOrgName) {
		return nil, nil, errors.New("archive org does not match caller org")
	}
	result := &RestoreResult{Manifest: manifest}
	signature, certificate := files["manifest.json.sig"], files["manifest.json.cert"]
	if opts.Verify.Mode == "" && len(signature) > 0 {
		opts.Verify.Mode = SignModeStaticKey
		if len(certificate) > 0 {
			opts.Verify.Mode = SignModeKeyless
		}
	}
	if opts.Verify.Mode == "" || opts.Verify.Mode == SignModeNone {
		if !opts.AllowUnverified {
			return nil, nil, errors.New("signature required; unsigned restore must be explicitly enabled by the operator")
		}
		return result, files, nil
	}
	identity, err := Verify(ctx, manifestBytes, signature, certificate, opts.Verify)
	if err != nil {
		if !opts.AllowUnverified {
			return nil, nil, fmt.Errorf("signature verify: %w", err)
		}
		return result, files, nil
	}
	result.Verified = true
	result.SignerIdentity = identity
	return result, files, nil
}
