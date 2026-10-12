// Package inventorylist implements the read-only continuation and export contract
// shared by image, repository and serverless scan inventories.
package inventorylist

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const ExportLimit = 100000

// MaxOffset supports deep retained-history pages without exceeding int32 clients.
const MaxOffset = 2147483647

type Options struct {
	Limit, Offset         int
	Sort, Order, OrderSQL string
}
type Metadata struct {
	Total   int64            `json:"total"`
	HasMore bool             `json:"has_more"`
	Summary map[string]int64 `json:"summary"`
}
type Definition struct {
	SQL, Columns, Where, Summary string
	Args                         []any
}
type Row interface{ Scan(...any) error }

func Query(r *http.Request) (url.Values, error) { return url.ParseQuery(r.URL.RawQuery) }

func Parse(values url.Values, sorts map[string]string, defaultSort string) (Options, error) {
	limit, _ := strconv.Atoi(values.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset, _ := strconv.Atoi(values.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	key := values.Get("sort")
	if key == "" {
		key = defaultSort
	}
	expression, ok := sorts[key]
	if !ok {
		return Options{}, fmt.Errorf("unsupported sort")
	}
	order := strings.ToLower(values.Get("order"))
	if order == "" {
		order = "desc"
	}
	if order != "asc" && order != "desc" {
		return Options{}, fmt.Errorf("order must be asc or desc")
	}
	return Options{Limit: limit, Offset: offset, Sort: key, Order: order, OrderSQL: expression + " " + strings.ToUpper(order) + " NULLS LAST, id ASC"}, nil
}

func Filter(values url.Values, key string, allowed ...string) (string, error) {
	value := strings.TrimSpace(values.Get(key))
	if value == "all" {
		value = ""
	}
	if value == "" {
		return "", nil
	}
	for _, item := range allowed {
		if value == item {
			return value, nil
		}
	}
	return "", fmt.Errorf("unsupported %s", key)
}

// Read obtains the summary and rows from one read-only repeatable-read snapshot.
// An empty page still receives the full matching total and summary.
func Read[T any](ctx context.Context, pool *pgxpool.Pool, d Definition, o Options, scan func(Row) (T, error)) ([]T, Metadata, error) {
	items := make([]T, 0)
	meta, err := run(ctx, pool, d, o, scan, func(item T) error { items = append(items, item); return nil })
	return items, meta, err
}

func CSV[T any](ctx context.Context, pool *pgxpool.Pool, d Definition, o Options, scan func(Row) (T, error), headers []string, cells func(T) []string) ([]byte, Metadata, error) {
	o.Limit = ExportLimit
	o.Offset = 0
	var body bytes.Buffer
	writer := csv.NewWriter(&body)
	if err := writer.Write(headers); err != nil {
		return nil, Metadata{}, err
	}
	meta, err := run(ctx, pool, d, o, scan, func(item T) error { return writer.Write(cells(item)) })
	writer.Flush()
	if err == nil {
		err = writer.Error()
	}
	if err != nil {
		return nil, Metadata{}, err
	}
	return body.Bytes(), meta, nil
}

func run[T any](ctx context.Context, pool *pgxpool.Pool, d Definition, o Options, scan func(Row) (T, error), visit func(T) error) (Metadata, error) {
	meta := Metadata{}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return meta, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	prefix := "WITH inventory(" + d.Columns + ") AS (" + d.SQL + ") "
	where := d.Where
	if where == "" {
		where = "true"
	}
	var summary []byte
	if err := tx.QueryRow(ctx, prefix+"SELECT count(*), "+d.Summary+" FROM inventory WHERE "+where, d.Args...).Scan(&meta.Total, &summary); err != nil {
		return meta, err
	}
	if err := json.Unmarshal(summary, &meta.Summary); err != nil {
		return meta, err
	}
	args := append(append([]any{}, d.Args...), o.Limit, o.Offset)
	query := fmt.Sprintf("%s SELECT * FROM inventory WHERE %s ORDER BY %s LIMIT $%d OFFSET $%d", prefix, where, o.OrderSQL, len(d.Args)+1, len(d.Args)+2)
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return meta, err
	}
	for rows.Next() {
		item, e := scan(rows)
		if e != nil {
			rows.Close()
			return meta, e
		}
		if e = visit(item); e != nil {
			rows.Close()
			return meta, e
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return meta, err
	}
	if err = tx.Commit(ctx); err != nil {
		return meta, err
	}
	meta.HasMore = int64(o.Offset) < meta.Total && meta.Total-int64(o.Offset) > int64(o.Limit)
	return meta, nil
}

func WriteCSV(w http.ResponseWriter, filename string, body []byte, meta Metadata) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("X-Export-Limit", strconv.Itoa(ExportLimit))
	w.Header().Set("X-Export-Total", strconv.FormatInt(meta.Total, 10))
	w.Header().Set("X-Export-Truncated", strconv.FormatBool(meta.Total > ExportLimit))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
