package handler

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/backup"
)

func invalidBackupSigningRequests() []string {
	return []string{
		`{"sign_mode":"static_key"}`, `{"sign_mode":"STATIC-KEY"}`, `{"sign_mode":" none"}`,
		`{"sign_mode":null}`, `{"sign_mode":42}`, `{"sign_mode":true}`, `{"sign_mode":{}}`,
		`null`, `[]`, `"static-key"`, `{`, `{"sign_mode":"static-key"`,
		`{"sign_mode":"none"} {"sign_mode":"static-key"}`, `{} garbage`,
		`{"sign_mode":"static-key","sign_mode":"none"}`, `{"sign_mode":"static-key","sign_\u006dode":"none"}`,
		`{"signMode":"static-key"}`, `{"SIGN_MODE":"static-key"}`, `{"sign_mode":"none","credential_sentinel":"private-value"}`,
	}
}

func TestBackupSigningRequestsRejectInvalidBeforeDatabaseOrAudit(t *testing.T) {
	for _, schedule := range []bool{false, true} {
		name := "create"
		if schedule {
			name = "schedule"
		}
		t.Run(name, func(t *testing.T) {
			for i, body := range invalidBackupSigningRequests() {
				t.Run(string(rune('a'+i)), func(t *testing.T) { assertInvalidBackupSigningRequest(t, schedule, body, http.StatusBadRequest) })
			}
			assertInvalidBackupSigningRequest(t, schedule, strings.Repeat(" ", maxBackupRequestBytes+1), http.StatusRequestEntityTooLarge)
			if schedule {
				assertInvalidBackupSigningRequest(t, true, " \n\t", http.StatusBadRequest)
			}
		})
	}
}

func assertInvalidBackupSigningRequest(t *testing.T, schedule bool, body string, wantStatus int) {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/backups", strings.NewReader(body))
	request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: uuid.New(), UserID: uuid.New()}))
	response := httptest.NewRecorder()
	// Deliberately absent database/audit: validation must return before either is
	// used. No constructor is invoked, so rejection cannot create managed roots.
	h := &Backups{}
	if schedule {
		h.PutSchedule(response, request)
	} else {
		h.Create(response, request)
	}
	if response.Code != wantStatus || strings.Contains(response.Body.String(), "private-value") || strings.Contains(response.Body.String(), "credential_sentinel") {
		t.Fatalf("status=%d want=%d body=%s", response.Code, wantStatus, response.Body.String())
	}
}

func TestBackupSigningRequestDefaultsAndScheduleDTOCompatibility(t *testing.T) {
	for _, body := range []string{"", " \n\t\r", `{}`, `{"sign_mode":""}`, `{"sign_mode":"none"}`} {
		request := httptest.NewRequestWithContext(t.Context(), "POST", "/backups", strings.NewReader(body))
		response := httptest.NewRecorder()
		var decoded createBackupRequest
		if !decodeBackupRequest(response, request, &decoded, true, "sign_mode") {
			t.Fatalf("legacy create rejected: %q", body)
		}
		mode, err := backup.ResolveSignMode(decoded.SignMode, backup.SignModeNone)
		if err != nil || mode != backup.SignModeNone {
			t.Fatalf("one-off default changed: %q %v", mode, err)
		}
	}
	body := `{"cron_expr":"0 3 * * *","enabled":false,"s3_bucket":"","s3_prefix":"","s3_endpoint":"","sign_mode":"","last_run_at":"2026-10-17T00:00:00Z","last_status":"succeeded","next_run_at":null}`
	request := httptest.NewRequestWithContext(t.Context(), "POST", "/backups/schedule", strings.NewReader(body))
	response := httptest.NewRecorder()
	var decoded scheduleDTO
	if !decodeBackupRequest(response, request, &decoded, false, "cron_expr", "enabled", "s3_bucket", "s3_prefix", "s3_endpoint", "sign_mode", "last_run_at", "last_status", "next_run_at") {
		t.Fatal("existing schedule DTO repost rejected")
	}
	mode, err := backup.ResolveSignMode(decoded.SignMode, backup.SignModeStaticKey)
	if err != nil || mode != backup.SignModeStaticKey || decoded.LastRunAt == nil || decoded.LastStatus != "succeeded" {
		t.Fatalf("schedule compatibility/default changed: %+v mode=%q error=%v", decoded, mode, err)
	}
}

type backupRequestReadFailure struct{}

func (backupRequestReadFailure) Read([]byte) (int, error) {
	return 0, errors.New("credential_sentinel private-value")
}

func TestBackupSigningRequestReadFailureIsCategorical(t *testing.T) {
	request := httptest.NewRequestWithContext(t.Context(), "POST", "/backups", nil)
	request.Body = io.NopCloser(backupRequestReadFailure{})
	response := httptest.NewRecorder()
	var destination createBackupRequest
	if decodeBackupRequest(response, request, &destination, true, "sign_mode") || response.Code != 400 || strings.Contains(response.Body.String(), "private-value") {
		t.Fatalf("read failure exposed/accepted: %d %s", response.Code, response.Body.String())
	}
}
