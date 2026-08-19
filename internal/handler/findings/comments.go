// Finding comments thread.
//
//	GET  /api/v1/findings/{id}/comments    — list comments (verb=read-findings)
//	POST /api/v1/findings/{id}/comments    — add comment (verb=triage-findings)
package findings

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// Comments handler.
type Comments struct {
	db    *db.DB
	audit *audit.Logger
}

func NewComments(d *db.DB, a *audit.Logger) *Comments {
	return &Comments{db: d, audit: a}
}

type commentDTO struct {
	ID        uuid.UUID `json:"id"`
	FindingID uuid.UUID `json:"finding_id"`
	AuthorID  uuid.UUID `json:"author_id"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// List returns active comments for a finding, oldest-first (so the UI can append).
func (c *Comments) List(w http.ResponseWriter, r *http.Request) {
	findingID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())

	rows, err := c.db.Pool().Query(r.Context(), `
SELECT id, finding_id, author_id, body, created_at
  FROM finding_comments
 WHERE finding_id = $1 AND org_id = $2 AND deleted_at IS NULL
 ORDER BY created_at ASC`, findingID, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	out := []commentDTO{}
	for rows.Next() {
		var d commentDTO
		if err := rows.Scan(&d.ID, &d.FindingID, &d.AuthorID, &d.Body, &d.CreatedAt); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out = append(out, d)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"comments": out})
}

// Create adds a new comment. Body is required; trailing/leading whitespace is trimmed.
func (c *Comments) Create(w http.ResponseWriter, r *http.Request) {
	findingID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	var body struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	body.Body = strings.TrimSpace(body.Body)
	if body.Body == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "comment body required"})
		return
	}
	if len(body.Body) > 16000 {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "comment too long (max 16000 chars)"})
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())

	id := uuid.New()
	if _, err := c.db.Pool().Exec(r.Context(), `
INSERT INTO finding_comments (id, finding_id, org_id, author_id, body)
VALUES ($1, $2, $3, $4, $5)`, id, findingID, subj.OrgID, subj.UserID, body.Body); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	uid := subj.UserID
	oid := subj.OrgID
	_, _, _ = c.audit.Log(r.Context(), audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action:     "finding.comment",
		TargetKind: "finding",
		TargetID:   findingID.String(),
		After:      map[string]any{"comment_id": id, "body_len": len(body.Body)},
	})
	httpx.WriteJSON(w, http.StatusCreated, commentDTO{
		ID: id, FindingID: findingID, AuthorID: subj.UserID, Body: body.Body, CreatedAt: time.Now().UTC(),
	})
}
