package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"
)

// testFedSigner builds a FedSigner from a fresh RSA keypair, mirroring how
// LoadFedSigningKeysPEM feeds NewFedSigner in production.
func testFedSigner(t *testing.T) *FedSigner {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	s, err := NewFedSigner(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFedSigner_JoinTokenRoundTrip(t *testing.T) {
	s := testFedSigner(t)
	org := uuid.New()
	tok, err := s.IssueJoinToken(org, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.VerifyJoinToken(tok)
	if err != nil {
		t.Fatalf("verify join token: %v", err)
	}
	if claims.OrgID != org {
		t.Fatalf("org = %v, want %v", claims.OrgID, org)
	}
	if claims.Purpose != FedPurposeJoin {
		t.Fatalf("purpose = %q, want %q", claims.Purpose, FedPurposeJoin)
	}
	// A join token must not validate as a sync ticket (purposes are not interchangeable).
	if _, err := s.VerifySyncTicket(tok); err == nil {
		t.Fatal("join token wrongly accepted as a sync ticket")
	}
}

func TestFedSigner_SyncTicketRoundTrip(t *testing.T) {
	s := testFedSigner(t)
	org := uuid.New()
	tok, err := s.IssueSyncTicket(org, "edge-1", 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.VerifySyncTicket(tok)
	if err != nil {
		t.Fatalf("verify sync ticket: %v", err)
	}
	if claims.ClusterID != "edge-1" || claims.Epoch != 7 {
		t.Fatalf("claims = %+v, want cid=edge-1 epoch=7", claims)
	}
	if _, err := s.VerifyJoinToken(tok); err == nil {
		t.Fatal("sync ticket wrongly accepted as a join token")
	}
}

func TestFedSigner_ExpiredTicketRejected(t *testing.T) {
	s := testFedSigner(t)
	tok, err := s.IssueSyncTicket(uuid.New(), "edge-1", 0, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := s.VerifySyncTicket(tok); err == nil {
		t.Fatal("expired sync ticket was accepted")
	}
}

func TestFedSigner_ForeignKeyRejected(t *testing.T) {
	a := testFedSigner(t)
	b := testFedSigner(t)
	tok, err := a.IssueJoinToken(uuid.New(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// A token signed by a different fed key (modeling a user session JWT signed by the
	// session key, or another cluster's fed key) must not verify.
	if _, err := b.VerifyJoinToken(tok); err == nil {
		t.Fatal("token signed by a foreign key was accepted")
	}
}
