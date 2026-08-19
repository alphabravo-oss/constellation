package gcp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// fakeHTTP serves canned response bodies keyed by URL substring match.
type fakeHTTP struct {
	responses map[string]string
}

func (f *fakeHTTP) Do(req *http.Request) (*http.Response, error) {
	for needle, body := range f.responses {
		if strings.Contains(req.URL.String(), needle) {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader([]byte(body))),
				Header:     http.Header{},
			}, nil
		}
	}
	return &http.Response{StatusCode: 404, Body: io.NopCloser(bytes.NewReader(nil))}, nil
}

func TestScanIAM_FlagsOverPrivilegedHumanBindings(t *testing.T) {
	c := &Connector{
		Token:     "t",
		ProjectID: "demo-proj",
		HTTP: &fakeHTTP{responses: map[string]string{
			"getIamPolicy": `{"bindings":[
				{"role":"roles/owner","members":["user:alice@example.com","serviceAccount:robot@example.iam.gserviceaccount.com"]},
				{"role":"roles/viewer","members":["user:bob@example.com"]}
			]}`,
		}},
	}
	out, err := c.ScanIAM(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding (alice owner), got %d: %+v", len(out), out)
	}
	if !strings.Contains(out[0].Title, "alice@example.com") {
		t.Fatalf("alice not in title: %s", out[0].Title)
	}
}

func TestScanStorage_FlagsAllUsersBinding(t *testing.T) {
	c := &Connector{
		Token: "t", ProjectID: "demo-proj",
		HTTP: &fakeHTTP{responses: map[string]string{
			"storage/v1/b?project": `{"items":[{"name":"public-bucket"},{"name":"private-bucket"}]}`,
			"public-bucket/iam":    `{"bindings":[{"role":"roles/storage.objectViewer","members":["allUsers"]}]}`,
			"private-bucket/iam":   `{"bindings":[{"role":"roles/storage.objectAdmin","members":["user:alice@example.com"]}]}`,
		}},
	}
	out, err := c.ScanStorage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 public-bucket finding, got %d", len(out))
	}
	if !strings.Contains(out[0].ExternalID, "public-bucket") {
		t.Fatalf("wrong bucket flagged: %s", out[0].ExternalID)
	}
}
