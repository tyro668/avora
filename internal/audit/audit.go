// Package audit is the desktop's local, per-connection request log: one row
// per task served to a paired SaaS (connection, model, timing, token usage,
// outcome). Prompt and completion content is never recorded. It backs the
// usage statistics shown in the app and the CLI (docs/lmbp-spec.md §20).
package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS requests(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,              -- unix ms, task start
  connection_id TEXT NOT NULL,      -- lmbp device_id of the pairing
  gateway TEXT NOT NULL,            -- issuer origin
  tenant TEXT NOT NULL,             -- SaaS (tenant) id
  saas_name TEXT NOT NULL DEFAULT '',
  task_id TEXT NOT NULL,
  model TEXT NOT NULL,
  adapter TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,             -- ok | error | cancelled
  error_code TEXT NOT NULL DEFAULT '',
  prompt_tokens INTEGER NOT NULL DEFAULT 0,
  completion_tokens INTEGER NOT NULL DEFAULT 0,
  usage_reported INTEGER NOT NULL DEFAULT 0,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  ttft_ms INTEGER NOT NULL DEFAULT 0,
  e2ee INTEGER NOT NULL DEFAULT 0,
  tools INTEGER NOT NULL DEFAULT 0,
  images INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS requests_at ON requests(at);
CREATE INDEX IF NOT EXISTS requests_tenant_at ON requests(tenant, at);
CREATE INDEX IF NOT EXISTS requests_gateway_tenant_at ON requests(gateway, tenant, at);
`

// Status values.
const (
	StatusOK        = "ok"
	StatusError     = "error"
	StatusCancelled = "cancelled"
)

// DefaultRetention is how long rows are kept unless configured otherwise.
const DefaultRetention = 90 * 24 * time.Hour

type Record struct {
	ID               int64     `json:"id"`
	At               time.Time `json:"at"`
	ConnectionID     string    `json:"connection_id"`
	Gateway          string    `json:"gateway"`
	Tenant           string    `json:"tenant"`
	SaaSName         string    `json:"saas_name,omitempty"`
	TaskID           string    `json:"task_id"`
	Model            string    `json:"model"`
	Adapter          string    `json:"adapter,omitempty"`
	Status           string    `json:"status"`
	ErrorCode        string    `json:"error_code,omitempty"`
	PromptTokens     int       `json:"prompt_tokens"`
	CompletionTokens int       `json:"completion_tokens"`
	UsageReported    bool      `json:"usage_reported"` // false: the runtime reported no token counts
	LatencyMS        int64     `json:"latency_ms"`
	TTFTMS           int64     `json:"ttft_ms"` // time to first delta; 0 if none
	E2EE             bool      `json:"e2ee"`
	Tools            bool      `json:"tools"`
	Images           int       `json:"images"`
}

type Log struct{ db *sql.DB }

// Open opens (or creates) the audit database; ":memory:" for tests.
func Open(path string) (*Log, error) {
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Log{db: db}, nil
}

func (l *Log) Close() error { return l.db.Close() }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (l *Log) Record(ctx context.Context, r Record) error {
	if r.Status != StatusOK && r.Status != StatusError && r.Status != StatusCancelled {
		return errors.New("invalid status")
	}
	_, err := l.db.ExecContext(ctx, `INSERT INTO requests(at,connection_id,gateway,tenant,saas_name,task_id,model,adapter,status,error_code,
		prompt_tokens,completion_tokens,usage_reported,latency_ms,ttft_ms,e2ee,tools,images) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.At.UnixMilli(), r.ConnectionID, r.Gateway, r.Tenant, r.SaaSName, r.TaskID, r.Model, r.Adapter, r.Status, r.ErrorCode,
		r.PromptTokens, r.CompletionTokens, b2i(r.UsageReported), r.LatencyMS, r.TTFTMS, b2i(r.E2EE), b2i(r.Tools), r.Images)
	return err
}

// Filter narrows List and Stats. Zero values match everything.
type Filter struct {
	Tenant       string    `json:"tenant,omitempty"`
	Gateway      string    `json:"gateway,omitempty"`   // issuer origin
	SaaSName     string    `json:"saas_name,omitempty"` // display name
	ConnectionID string    `json:"connection_id,omitempty"`
	Model        string    `json:"model,omitempty"`
	Status       string    `json:"status,omitempty"`
	Since        time.Time `json:"since,omitempty"`
	Until        time.Time `json:"until,omitempty"`
	Limit        int       `json:"limit,omitempty"` // List only; default 100, max 1000
}

func (f Filter) where() (string, []any) {
	var w []string
	var a []any
	add := func(c string, v any) { w = append(w, c); a = append(a, v) }
	if f.Tenant != "" {
		add("tenant=?", f.Tenant)
	}
	if f.Gateway != "" {
		add("gateway=?", f.Gateway)
	}
	if f.SaaSName != "" {
		add("saas_name=?", f.SaaSName)
	}
	if f.ConnectionID != "" {
		add("connection_id=?", f.ConnectionID)
	}
	if f.Model != "" {
		add("model=?", f.Model)
	}
	if f.Status != "" {
		add("status=?", f.Status)
	}
	if !f.Since.IsZero() {
		add("at>=?", f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		add("at<?", f.Until.UnixMilli())
	}
	if len(w) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(w, " AND "), a
}

// List returns the newest matching rows first.
func (l *Log) List(ctx context.Context, f Filter) ([]Record, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Limit > 1000 {
		f.Limit = 1000
	}
	w, args := f.where()
	rows, err := l.db.QueryContext(ctx, `SELECT id,at,connection_id,gateway,tenant,saas_name,task_id,model,adapter,status,error_code,prompt_tokens,
		completion_tokens,usage_reported,latency_ms,ttft_ms,e2ee,tools,images FROM requests`+w+` ORDER BY at DESC, id DESC LIMIT ?`, append(args, f.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var r Record
		var at int64
		var ur, e2, tl int
		if err := rows.Scan(&r.ID, &at, &r.ConnectionID, &r.Gateway, &r.Tenant, &r.SaaSName, &r.TaskID, &r.Model, &r.Adapter, &r.Status, &r.ErrorCode,
			&r.PromptTokens, &r.CompletionTokens, &ur, &r.LatencyMS, &r.TTFTMS, &e2, &tl, &r.Images); err != nil {
			return nil, err
		}
		r.At, r.UsageReported, r.E2EE, r.Tools = time.UnixMilli(at).UTC(), ur == 1, e2 == 1, tl == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// Group-by dimensions accepted by Stats.
const (
	BySaaS    = "saas" // tenant (+ display name)
	ByModel   = "model"
	ByAdapter = "adapter" // local adapter (方案) id
	ByDay     = "day"     // YYYY-MM-DD
	ByHour    = "hour"    // YYYY-MM-DDTHH:00
	ByStatus  = "status"
	ByConn    = "connection"
)

// Bucket is one aggregated row.
type Bucket struct {
	SaaS       string `json:"saas,omitempty"`
	SaaSName   string `json:"saas_name,omitempty"`
	Gateway    string `json:"gateway,omitempty"` // with saas: one bucket per gateway + tenant
	Model      string `json:"model,omitempty"`
	Adapter    string `json:"adapter,omitempty"`
	Day        string `json:"day,omitempty"`
	Hour       string `json:"hour,omitempty"`
	Status     string `json:"status,omitempty"`
	Connection string `json:"connection,omitempty"`
	// A device id is only unique per gateway + tenant: a connection bucket
	// is keyed by all three.
	ConnectionGateway string  `json:"connection_gateway,omitempty"`
	ConnectionTenant  string  `json:"connection_tenant,omitempty"`
	Requests          int64   `json:"requests"`
	Errors            int64   `json:"errors"`
	PromptTokens      int64   `json:"prompt_tokens"`
	CompletionTokens  int64   `json:"completion_tokens"`
	TotalTokens       int64   `json:"total_tokens"`
	AvgLatencyMS      float64 `json:"avg_latency_ms"`
	MaxLatencyMS      int64   `json:"max_latency_ms"`
	Unmetered         int64   `json:"unmetered"` // requests without reported usage
}

// Stats aggregates rows. Time buckets are UTC unless local is true.
func (l *Log) Stats(ctx context.Context, f Filter, groupBy []string, local bool) ([]Bucket, error) {
	mod := ""
	if local {
		mod = ",'localtime'"
	}
	cols := map[string]string{BySaaS: "tenant", ByModel: "model", ByAdapter: "adapter", ByStatus: "status", ByConn: "connection_id",
		ByDay: "strftime('%Y-%m-%d', at/1000, 'unixepoch'" + mod + ")", ByHour: "strftime('%Y-%m-%dT%H:00', at/1000, 'unixepoch'" + mod + ")"}
	var sel, grp, dims []string
	seen := map[string]bool{}
	for _, g := range groupBy {
		c, ok := cols[g]
		if !ok {
			return nil, fmt.Errorf("unknown group %q (want saas, model, adapter, day, hour, status, connection)", g)
		}
		if seen[g] {
			continue
		}
		seen[g] = true
		dims, sel, grp = append(dims, g), append(sel, c), append(grp, c)
		if g == BySaaS { // tenant ids are only unique per gateway
			sel, grp = append(sel, "MAX(saas_name)", "gateway"), append(grp, "gateway")
		}
		if g == ByConn { // device ids may repeat across gateways
			sel, grp = append(sel, "gateway", "tenant"), append(grp, "gateway", "tenant")
		}
	}
	w, args := f.where()
	q := "SELECT " + strings.Join(append(sel, "COUNT(*)", "SUM(status<>'ok')", "SUM(prompt_tokens)", "SUM(completion_tokens)", "AVG(latency_ms)", "MAX(latency_ms)", "SUM(usage_reported=0)"), ",") + " FROM requests" + w
	if len(grp) > 0 {
		q += " GROUP BY " + strings.Join(grp, ",") + " ORDER BY " + strings.Join(grp, ",")
	}
	rows, err := l.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Bucket{}
	for rows.Next() {
		var b Bucket
		var dst []any
		for _, g := range dims {
			switch g {
			case BySaaS:
				dst = append(dst, &b.SaaS, &b.SaaSName, &b.Gateway)
			case ByModel:
				dst = append(dst, &b.Model)
			case ByAdapter:
				dst = append(dst, &b.Adapter)
			case ByDay:
				dst = append(dst, &b.Day)
			case ByHour:
				dst = append(dst, &b.Hour)
			case ByStatus:
				dst = append(dst, &b.Status)
			case ByConn:
				dst = append(dst, &b.Connection, &b.ConnectionGateway, &b.ConnectionTenant)
			}
		}
		var errs, pt, ct, maxL, unm sql.NullInt64
		var avg sql.NullFloat64
		dst = append(dst, &b.Requests, &errs, &pt, &ct, &avg, &maxL, &unm)
		if err := rows.Scan(dst...); err != nil {
			return nil, err
		}
		b.Errors, b.PromptTokens, b.CompletionTokens, b.AvgLatencyMS, b.MaxLatencyMS, b.Unmetered = errs.Int64, pt.Int64, ct.Int64, avg.Float64, maxL.Int64, unm.Int64
		b.TotalTokens = b.PromptTokens + b.CompletionTokens
		if b.Requests > 0 || len(grp) > 0 {
			out = append(out, b)
		}
	}
	return out, rows.Err()
}

// Purge deletes rows older than cutoff and returns how many were removed.
func (l *Log) Purge(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := l.db.ExecContext(ctx, `DELETE FROM requests WHERE at<?`, cutoff.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RunRetention purges rows older than keep every interval until ctx ends.
func (l *Log) RunRetention(ctx context.Context, keep, every time.Duration) {
	if keep <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		_, _ = l.Purge(ctx, time.Now().Add(-keep))
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
