package findings

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type Comments struct {
	db    *db.DB
	audit *audit.Logger
}

func NewComments(d *db.DB, a *audit.Logger) *Comments { return &Comments{d, a} }

type commentDTO struct {
	ID              uuid.UUID  `json:"id"`
	FindingID       uuid.UUID  `json:"finding_id"`
	AuthorID        uuid.UUID  `json:"author_id"`
	Body            string     `json:"body"`
	CreatedAt       time.Time  `json:"created_at"`
	FirstSeen       *time.Time `json:"first_seen_at,omitempty"`
	RowID           string     `json:"row_id,omitempty"`
	Revision        string     `json:"revision,omitempty"`
	SourceClusterID *uuid.UUID `json:"source_cluster_id"`
	TargetClusterID *uuid.UUID `json:"target_cluster_id"`
}

func (c *Comments) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		writeInstanceError(w, &instanceError{401, "subject_required", "subject required"})
		return
	}
	selector, err := parseInstanceSelector(r)
	if err != nil {
		writeInstanceError(w, err)
		return
	}
	tx, err := c.db.Pool().BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		writeInstanceError(w, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(r.Context()))
	found, err := resolveInstance(r.Context(), tx, subj.OrgID, selector, false)
	if err != nil {
		writeInstanceError(w, err)
		return
	}
	rows, err := tx.Query(r.Context(), `SELECT id,finding_id,author_id,body,created_at,finding_first_seen_at FROM finding_comments WHERE finding_id=$1 AND org_id=$2 AND deleted_at IS NULL AND (finding_first_seen_at=$3 OR finding_first_seen_at IS NULL) ORDER BY created_at,id`, found.ID, subj.OrgID, found.FirstSeen)
	if err != nil {
		writeInstanceError(w, err)
		return
	}
	defer rows.Close()
	exact, legacy := []commentDTO{}, []commentDTO{}
	for rows.Next() {
		var row commentDTO
		if err = rows.Scan(&row.ID, &row.FindingID, &row.AuthorID, &row.Body, &row.CreatedAt, &row.FirstSeen); err != nil {
			writeInstanceError(w, err)
			return
		}
		if row.FirstSeen == nil {
			legacy = append(legacy, row)
		} else {
			row.RowID = found.RowID
			row.Revision = found.Revision
			row.SourceClusterID = found.SourceClusterID
			row.TargetClusterID = found.TargetClusterID
			exact = append(exact, row)
		}
	}
	if err = rows.Err(); err != nil {
		writeInstanceError(w, err)
		return
	}
	// Bare unique legacy callers retain their historical comments array. Exact
	// consumers receive a separate explicit UUID-history section, never a merge.
	if !selector.Exact && selector.FirstSeen == nil {
		exact = append(exact, legacy...)
		sort.Slice(exact, func(i, j int) bool {
			if exact[i].CreatedAt.Equal(exact[j].CreatedAt) {
				return exact[i].ID.String() < exact[j].ID.String()
			}
			return exact[i].CreatedAt.Before(exact[j].CreatedAt)
		})
	}
	httpx.WriteJSON(w, 200, map[string]any{"comments": exact, "legacy_comments": legacy, "legacy_history_scope": "uuid", "row_id": found.RowID, "first_seen_at": found.FirstSeen, "revision": found.Revision})
}
func (c *Comments) Create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Body             string `json:"body"`
		ReviewedRevision string `json:"reviewed_revision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeInstanceError(w, &instanceError{400, "invalid_body", "invalid body"})
		return
	}
	body.Body = strings.TrimSpace(body.Body)
	if body.Body == "" || len(body.Body) > 16000 {
		writeInstanceError(w, &instanceError{400, "invalid_body", "comment body must contain 1 to 16000 bytes"})
		return
	}
	f := Findings{db: c.db, auditLog: c.audit}
	tx, found, subj, err := f.beginMutation(r, body.ReviewedRevision)
	if err != nil {
		writeInstanceError(w, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(r.Context()))
	row := commentDTO{ID: uuid.New(), FindingID: found.ID, AuthorID: subj.UserID, Body: body.Body, FirstSeen: &found.FirstSeen, RowID: found.RowID, Revision: found.Revision, SourceClusterID: found.SourceClusterID, TargetClusterID: found.TargetClusterID}
	if err = tx.QueryRow(r.Context(), `INSERT INTO finding_comments(id,finding_id,org_id,author_id,body,finding_first_seen_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING created_at`, row.ID, row.FindingID, subj.OrgID, subj.UserID, row.Body, found.FirstSeen).Scan(&row.CreatedAt); err != nil {
		writeInstanceError(w, err)
		return
	}
	if c.audit != nil {
		uid, oid := subj.UserID, subj.OrgID
		if _, _, err = c.audit.LogInTx(r.Context(), tx, audit.Event{OrgID: &oid, ActorID: &uid, Action: "finding.comment", TargetKind: "finding", TargetID: found.ID.String(), After: instanceAuditFields(found, map[string]any{"comment_id": row.ID, "body_len": len(row.Body)})}); err != nil {
			writeInstanceError(w, err)
			return
		}
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeInstanceError(w, err)
		return
	}
	httpx.WriteJSON(w, 201, row)
}
