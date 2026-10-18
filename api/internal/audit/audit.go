// Package audit writes append-only, hash-chained audit events.
// Each row stores sha256(prev_hash || canonical row) so tampering is detectable
// by Verify, in addition to the database trigger that blocks UPDATE/DELETE.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const chainLockID = 0x52424155 // "RBAU"

type Event struct {
	ActorUserID   *string
	ActorAPIKeyID *string
	ActorType     string // user | api_key | system | worker | anonymous
	OrgID         *string
	Action        string // e.g. auth.login
	TargetType    string
	TargetID      string
	Outcome       string // success | failure | denied
	IP            string
	UserAgent     string
	Metadata      map[string]any
}

type Logger struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Logger { return &Logger{pool: pool} }

type canonical struct {
	At       string         `json:"at"`
	User     *string        `json:"user"`
	Key      *string        `json:"key"`
	Type     string         `json:"type"`
	Org      *string        `json:"org"`
	Action   string         `json:"action"`
	TType    string         `json:"ttype"`
	TID      string         `json:"tid"`
	Outcome  string         `json:"outcome"`
	Metadata map[string]any `json:"md"`
}

func rowHash(prev []byte, c canonical) []byte {
	b, _ := json.Marshal(c)
	h := sha256.New()
	h.Write(prev)
	h.Write(b)
	return h.Sum(nil)
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Record writes an event. Failures are returned so callers on security-critical
// paths can fail closed; most callers log and continue.
func (l *Logger) Record(ctx context.Context, e Event) error {
	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}
	if e.ActorType == "" {
		e.ActorType = "anonymous"
	}
	var ip *string
	if parsed := net.ParseIP(e.IP); parsed != nil {
		s := parsed.String()
		ip = &s
	}
	ua := e.UserAgent
	if len(ua) > 512 {
		ua = ua[:512]
	}
	at := time.Now().UTC().Truncate(time.Microsecond)

	return pgx.BeginFunc(ctx, l.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, chainLockID); err != nil {
			return err
		}
		var prev []byte
		err := tx.QueryRow(ctx, `SELECT row_hash FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&prev)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		c := canonical{At: at.Format(time.RFC3339Nano), User: e.ActorUserID, Key: e.ActorAPIKeyID, Type: e.ActorType,
			Org: e.OrgID, Action: e.Action, TType: e.TargetType, TID: e.TargetID, Outcome: e.Outcome, Metadata: e.Metadata}
		md, _ := json.Marshal(e.Metadata)
		_, err = tx.Exec(ctx, `
			INSERT INTO audit_events (occurred_at, actor_user_id, actor_api_key_id, actor_type, organization_id,
			  action, target_type, target_id, outcome, ip_address, user_agent, metadata, prev_hash, row_hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			at, e.ActorUserID, e.ActorAPIKeyID, e.ActorType, e.OrgID, e.Action, nullIfEmpty(e.TargetType),
			nullIfEmpty(e.TargetID), e.Outcome, ip, ua, md, prev, rowHash(prev, c))
		return err
	})
}

// Verify walks the chain and returns the first event id whose prev_hash does
// not match its predecessor's row_hash (detects deleted or inserted rows), or 0.
// In-place modification is blocked by the database trigger; full row-hash
// recomputation is not done here because account deletion legitimately nulls
// actor foreign keys after the hash was written.
func (l *Logger) Verify(ctx context.Context) (brokenID int64, checked int, err error) {
	rows, err := l.pool.Query(ctx, `SELECT id, prev_hash, row_hash FROM audit_events ORDER BY id`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	var last []byte
	for rows.Next() {
		var id int64
		var prev, row []byte
		if err := rows.Scan(&id, &prev, &row); err != nil {
			return 0, checked, err
		}
		if checked > 0 && string(prev) != string(last) {
			return id, checked, nil
		}
		last = row
		checked++
	}
	return 0, checked, rows.Err()
}

func (l *Logger) String() string { return fmt.Sprintf("audit.Logger(%p)", l.pool) }
