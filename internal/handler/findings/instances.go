package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

	"github.com/alphabravocompany/constellation/pkg/notify"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type instanceError struct {
	status        int
	code, message string
}

func (e *instanceError) Error() string { return e.message }
func writeInstanceError(w http.ResponseWriter, err error) {
	var e *instanceError
	if errors.As(err, &e) {
		apiutil.WriteStatusCode(context.Background(), w, e.status, e.code, e.message)
		return
	}
	apiutil.WriteStatus(context.Background(), w, 500, "finding instance unavailable")
}

type instanceSelector struct {
	ID        uuid.UUID
	FirstSeen *time.Time
	ClusterID *uuid.UUID
	Exact     bool
}

func parseInstanceSelector(r *http.Request) (instanceSelector, error) {
	s := instanceSelector{Exact: strings.Contains(r.URL.Path, "/finding-instances/")}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return s, &instanceError{400, "invalid_finding_id", "invalid finding ID"}
	}
	s.ID = id
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return s, &instanceError{400, "invalid_selector", "invalid finding selector"}
	}
	for _, entries := range values {
		if len(entries) != 1 {
			return s, &instanceError{400, "invalid_selector", "duplicate finding selector"}
		}
	}
	if raw, provided := values["first_seen_at"]; provided {
		t, e := time.Parse(time.RFC3339Nano, raw[0])
		if e != nil || t.IsZero() || t.Nanosecond()%1000 != 0 {
			return s, &instanceError{400, "invalid_selector", "first_seen_at must be an exact RFC3339 timestamp with at most microsecond precision"}
		}
		t = t.UTC()
		s.FirstSeen = &t
	}
	if s.Exact && s.FirstSeen == nil {
		return s, &instanceError{400, "missing_selector", "first_seen_at is required"}
	}
	if raw, provided := values["cluster_id"]; provided {
		id, e := uuid.Parse(raw[0])
		if e != nil {
			return s, &instanceError{400, "invalid_selector", "invalid cluster_id"}
		}
		s.ClusterID = &id
	}
	return s, nil
}
func findingRowID(id uuid.UUID, t time.Time) string {
	micros := t.UnixMicro()
	sec, part := micros/1000000, micros%1000000
	prefix := strconv.FormatInt(sec, 10)
	if part < 0 {
		part = -part
		if sec == 0 {
			prefix = "-0"
		}
	}
	return id.String() + ":" + prefix + fmt.Sprintf(".%06d", part)
}

type instanceIdentity struct {
	ID              uuid.UUID  `json:"id"`
	RowID           string     `json:"row_id"`
	FirstSeen       time.Time  `json:"first_seen_at"`
	Revision        string     `json:"revision"`
	SourceClusterID *uuid.UUID `json:"source_cluster_id"`
	TargetClusterID *uuid.UUID `json:"target_cluster_id"`
}
type reviewedInstance struct {
	instanceIdentity
	RiskScore                        int
	Title, Severity, Kind, Lifecycle string
	AssetID                          uuid.UUID
	AcceptedUntil                    *time.Time
	RiskInputs                       []byte
	AssigneeID                       *uuid.UUID
	Priority                         string
}
type instanceQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func resolveInstance(ctx context.Context, q instanceQuerier, org uuid.UUID, s instanceSelector, lock bool) (reviewedInstance, error) {
	var result reviewedInstance
	sql := `SELECT id,first_seen_at,revision::text,cluster_id,target_cluster_id,title,severity,kind,asset_id,lifecycle,accepted_until,risk_inputs,assignee_id,COALESCE(priority,''),risk_score FROM findings WHERE org_id=$1 AND id=$2`
	args := []any{org, s.ID}
	if s.FirstSeen != nil {
		sql += ` AND first_seen_at=$3`
		args = append(args, *s.FirstSeen)
	}
	sql += ` ORDER BY first_seen_at LIMIT 2`
	if lock {
		sql += ` FOR UPDATE`
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
		if err = rows.Scan(&result.ID, &result.FirstSeen, &result.Revision, &result.SourceClusterID, &result.TargetClusterID, &result.Title, &result.Severity, &result.Kind, &result.AssetID, &result.Lifecycle, &result.AcceptedUntil, &result.RiskInputs, &result.AssigneeID, &result.Priority, &result.RiskScore); err != nil {
			return result, err
		}
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	if n == 0 {
		return result, &instanceError{404, "finding_not_found", "finding instance not found"}
	}
	if n > 1 {
		return result, &instanceError{409, "ambiguous_finding_id", "finding UUID identifies multiple instances; select an exact first_seen_at"}
	}
	result.FirstSeen = result.FirstSeen.UTC()
	result.RowID = findingRowID(result.ID, result.FirstSeen)
	if s.ClusterID != nil {
		var owned bool
		if err = q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM clusters WHERE org_id=$1 AND id=$2)`, org, *s.ClusterID).Scan(&owned); err != nil {
			return result, err
		}
		effective := result.TargetClusterID
		if effective == nil {
			effective = result.SourceClusterID
		}
		if !owned || (result.SourceClusterID == nil || *result.SourceClusterID != *s.ClusterID) && (effective == nil || *effective != *s.ClusterID) {
			return result, &instanceError{404, "finding_not_found", "finding instance not found in cluster"}
		}
	}
	return result, nil
}
func checkReviewedRevision(exact bool, reviewed string, actual string) error {
	if reviewed == "" {
		if exact {
			return &instanceError{428, "review_required", "reviewed_revision is required"}
		}
		return nil
	}
	n, err := strconv.ParseInt(reviewed, 10, 64)
	if err != nil || n < 1 || strconv.FormatInt(n, 10) != reviewed {
		return &instanceError{400, "invalid_revision", "reviewed_revision must be a positive decimal string"}
	}
	if reviewed != actual {
		return &instanceError{409, "finding_changed", "finding changed; refresh and review the exact instance before saving"}
	}
	return nil
}
func (f *Findings) beginMutation(r *http.Request, reviewed string) (pgx.Tx, reviewedInstance, authctx.Subject, error) {
	var found reviewedInstance
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		return nil, found, subj, &instanceError{401, "subject_required", "subject required"}
	}
	s, err := parseInstanceSelector(r)
	if err != nil {
		return nil, found, subj, err
	}
	tx, err := f.db.Pool().BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, found, subj, err
	}
	found, err = resolveInstance(r.Context(), tx, subj.OrgID, s, true)
	if err == nil {
		err = checkReviewedRevision(s.Exact, reviewed, found.Revision)
	}
	if err != nil {
		_ = tx.Rollback(context.WithoutCancel(r.Context()))
		return nil, found, subj, err
	}
	return tx, found, subj, nil
}
func instanceAuditFields(found reviewedInstance, body any) map[string]any {
	// Keep existing reason/approver/body fields readable by legacy consumers.
	fields := map[string]any{}
	raw, _ := json.Marshal(body)
	_ = json.Unmarshal(raw, &fields)
	fields["finding_row_id"] = found.RowID
	fields["finding_first_seen_at"] = found.FirstSeen
	fields["finding_revision"] = found.Revision
	fields["finding_source_cluster_id"] = found.SourceClusterID
	fields["finding_target_cluster_id"] = found.TargetClusterID
	return fields
}
func (f *Findings) finishMutation(w http.ResponseWriter, r *http.Request, tx pgx.Tx, found reviewedInstance, subj authctx.Subject, action string, body any) bool {
	if err := tx.QueryRow(r.Context(), `SELECT revision::text,risk_inputs,risk_score FROM findings WHERE org_id=$1 AND id=$2 AND first_seen_at=$3`, subj.OrgID, found.ID, found.FirstSeen).Scan(&found.Revision, &found.RiskInputs, &found.RiskScore); err != nil {
		writeInstanceError(w, err)
		return false
	}
	if f.auditLog != nil {
		oid, uid := subj.OrgID, subj.UserID
		if _, _, err := f.auditLog.LogInTx(r.Context(), tx, audit.Event{OrgID: &oid, ActorID: &uid, Action: action, TargetKind: "finding", TargetID: found.ID.String(), After: instanceAuditFields(found, body)}); err != nil {
			writeInstanceError(w, err)
			return false
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeInstanceError(w, err)
		return false
	}
	f.dispatchInstance(r.Context(), subj.OrgID, action, found, body)
	httpx.WriteJSON(w, 200, map[string]any{"status": "ok", "id": found.ID, "row_id": found.RowID, "first_seen_at": found.FirstSeen, "revision": found.Revision, "source_cluster_id": found.SourceClusterID, "target_cluster_id": found.TargetClusterID, "risk_inputs": json.RawMessage(found.RiskInputs), "risk_score": found.RiskScore})
	return true
}

func (f *Findings) dispatchInstance(ctx context.Context, org uuid.UUID, action string, found reviewedInstance, body any) {
	if f.dispatcher == nil {
		return
	}
	path := "/findings/" + found.ID.String()
	if found.SourceClusterID != nil {
		path = "/clusters/" + found.SourceClusterID.String() + path
	} else if found.TargetClusterID != nil {
		path = "/clusters/" + found.TargetClusterID.String() + path
	}
	_, _ = f.dispatcher.Dispatch(ctx, notify.Event{Kind: action, OrgID: org, Severity: found.Severity, Title: found.Title, Workload: found.ID.String(), Labels: map[string]string{"finding_kind": found.Kind, "severity": found.Severity, "lifecycle": action}, Payload: instanceAuditFields(found, body), URL: path + "?first_seen_at=" + url.QueryEscape(found.FirstSeen.Format(time.RFC3339Nano))})
}
