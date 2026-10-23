package inventoryarchive

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/backup"
)

func keys(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	private, public := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")
	if err := backup.GenerateEd25519Keypair(private, public); err != nil {
		t.Fatal(err)
	}
	return private, public
}

func fixture() (record, targetIdentity) {
	target := targetIdentity{Type: "image", Ref: "example.invalid/app@sha256:123", SourceType: "manual"}
	now := time.Now().UTC().Truncate(time.Microsecond)
	return record{ID: uuid.New(), OrgID: uuid.New(), TargetID: uuid.New(), TargetType: target.Type, TargetRef: target.Ref, SourceType: target.SourceType, EvidenceType: "package-inventory", InventoryHash: "inventory-hash", PackageCount: 1, Payload: json.RawMessage(`{"packages":[{"name":"private-package","version":"1.0"}]}`), ObservedAt: now, CreatedAt: now}, target
}

func TestOfflineArtifactTrustAndTampering(t *testing.T) {
	t.Parallel()
	private, public := keys(t)
	row, target := fixture()
	data, report, err := encode(t.Context(), row, target, private, public)
	if err != nil {
		t.Fatal(err)
	}
	if report.EvidenceID != row.ID || report.PackageCount != 1 {
		t.Fatal("incorrect report")
	}
	encoded, _ := json.Marshal(report)
	if bytes.Contains(encoded, []byte("private-package")) {
		t.Fatal("report leaks payload")
	}
	_, wrong := keys(t)
	if _, err = Verify(t.Context(), bytes.NewReader(data), wrong); err == nil {
		t.Fatal("wrong key accepted")
	}
	for _, part := range []string{"manifest", "signature", "data"} {
		t.Run(part, func(t *testing.T) {
			t.Parallel()
			var e envelope
			if err := json.Unmarshal(data, &e); err != nil {
				t.Fatal(err)
			}
			switch part {
			case "manifest":
				e.Manifest = bytes.Replace(e.Manifest, []byte(formatVersion), []byte("constellation-inventory-evidence/v2"), 1)
			case "signature":
				e.Signature[0] ^= 1
			case "data":
				e.Data[len(e.Data)/2] ^= 1
			}
			changed, _ := json.Marshal(e)
			if _, err := Verify(t.Context(), bytes.NewReader(changed), public); err == nil {
				t.Fatal("tamper accepted")
			}
		})
	}
	for _, bad := range [][]byte{append(append([]byte{}, data...), []byte(" {}")...), []byte(`{"unknown":true}`), bytes.Repeat([]byte(" "), MaxArtifactBytes+1)} {
		if _, err := Verify(t.Context(), bytes.NewReader(bad), public); err == nil {
			t.Fatal("malformed/oversized archive accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Verify(ctx, bytes.NewReader(data), public); err == nil {
		t.Fatal("canceled verification accepted")
	}
	row.ID = uuid.Nil
	if _, _, err = encode(t.Context(), row, target, private, public); err == nil {
		t.Fatal("signed invalid identity accepted")
	}
}
