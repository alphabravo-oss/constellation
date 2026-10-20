package apiutil

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// Cursor is the opaque page token: the (created_at, id) of the last row of
// the previous page, so list queries paginate with a keyset predicate
// (created_at, id) < ($1, $2) ORDER BY created_at DESC, id DESC instead of OFFSET.
type Cursor struct {
	CreatedAt time.Time `json:"t"`
	ID        uuid.UUID `json:"i"`
}

// Encode returns the base64url page token for c.
func (c Cursor) Encode() string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeCursor parses a page token; an empty token is the first page.
func DecodeCursor(token string) (Cursor, bool, error) {
	if token == "" {
		return Cursor{}, false, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return Cursor{}, false, Invalid("invalid page_token")
	}
	var c Cursor
	if err := json.Unmarshal(b, &c); err != nil || c.ID == uuid.Nil {
		return Cursor{}, false, Invalid("invalid page_token")
	}
	return c, true, nil
}

// Page is the parsed list request: a capped page size and the cursor.
type Page struct {
	Size   int
	Cursor Cursor
	// HasCursor is false on the first page.
	HasCursor bool
}

const (
	DefaultPageSize = 50
	MaxPageSize     = 500
)

// ParsePage reads page_size / page_token from the query string, defaulting
// and capping the size (guide ch.03: capped, opaque tokens).
func ParsePage(r *http.Request) (Page, error) {
	return ParsePageValues(r.URL.Query().Get("page_size"), r.URL.Query().Get("page_token"), DefaultPageSize, MaxPageSize)
}

// ParsePageValues is ParsePage over raw values with explicit bounds.
func ParsePageValues(rawSize, token string, def, maxSize int) (Page, error) {
	p := Page{Size: def}
	if rawSize != "" {
		n, err := strconv.Atoi(rawSize)
		if err != nil || n <= 0 {
			return p, Invalid("page_size must be a positive integer")
		}
		p.Size = min(n, maxSize)
	}
	c, ok, err := DecodeCursor(token)
	if err != nil {
		return p, err
	}
	p.Cursor, p.HasCursor = c, ok
	return p, nil
}

// NextToken returns the token for the page after rows, given the fetched rows
// were requested with size+1 to detect the end: it returns "" when there is
// no next page and trims the extra row from items via the returned count.
func NextToken(fetched int, size int, last func() Cursor) (string, int) {
	if fetched <= size {
		return "", fetched
	}
	return last().Encode(), size
}
