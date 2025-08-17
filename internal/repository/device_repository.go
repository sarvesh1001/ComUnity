package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DeviceFingerprintDB mirrors the persisted model
type DeviceFingerprintDB struct {
	ID         string          // UUID
	DeviceKey  string
	Platform   string
	FirstSeen  time.Time
	LastSeen   time.Time
	TrustLevel int             // 0..3 (or choose your scheme)
	RiskScore  int             // 0..100
	Signals    json.RawMessage // JSONB
	UpdatedAt  time.Time
}

// DeviceTrustEvent is an append-only event referencing device_id (UUID)
type DeviceTrustEvent struct {
	ID       string          // UUID (unused on insert)
	DeviceID string          // FK to device_fingerprints.id
	UserID   *string         // nullable
	Type     string          // e.g., "success_biometric", "failed_biometric", "otp_only"
	TS       time.Time
	Meta     json.RawMessage // JSONB, privacy-preserving (bucket/hash)
}

var (
	ErrNotFound = errors.New("not found")
)

// DeviceRepository provides persistence operations
type DeviceRepository interface {
	UpsertDeviceByKey(ctx context.Context, deviceKey string, platform string, signals map[string]any, observedAt time.Time) (*DeviceFingerprintDB, error)
	GetByKey(ctx context.Context, deviceKey string) (*DeviceFingerprintDB, error)
	UpdateTrustAndRisk(ctx context.Context, deviceID string, trustDelta int, riskDelta int) error
	SetTrustAndRisk(ctx context.Context, deviceID string, trustLevel int, riskScore int) error
	RecordTrustEvent(ctx context.Context, evt DeviceTrustEvent) error
	TouchLastSeen(ctx context.Context, deviceID string, ts time.Time) error

	// Batch event operations
	StartEventWorker(ctx context.Context)
	QueueEvent(evt DeviceTrustEvent)
	FlushEvents(ctx context.Context) error

	// Optional: inject metadata encryption (KMS adapter)
	SetEncryptor(fn func(ctx context.Context, b []byte) ([]byte, error))
}

// CockroachDB repository implementation
type cockroachDeviceRepository struct {
	db *sql.DB

	// event batching
	evMu     sync.Mutex
	evBuf    []DeviceTrustEvent
	evSize   int
	evTicker *time.Ticker

	encryptMeta func(ctx context.Context, b []byte) ([]byte, error)
}

// Constructor with connection pooling tuned
func NewCockroachDeviceRepository(db *sql.DB) DeviceRepository {
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)

	return &cockroachDeviceRepository{
		db:         db,
		evBuf:      make([]DeviceTrustEvent, 0, 1024),
		evSize:     500, // flush when >=500 events
		evTicker:   time.NewTicker(2 * time.Second),
		encryptMeta: nil,
	}
}

func (r *cockroachDeviceRepository) SetEncryptor(fn func(ctx context.Context, b []byte) ([]byte, error)) {
	r.encryptMeta = fn
}

// UpsertDeviceByKey updates last_seen and merges signals; does not overwrite trust/risk.
func (r *cockroachDeviceRepository) UpsertDeviceByKey(ctx context.Context, deviceKey string, platform string, signals map[string]any, observedAt time.Time) (*DeviceFingerprintDB, error) {
	sigJSON, err := json.Marshal(signals)
	if err != nil {
		return nil, err
	}

	const q = `
INSERT INTO device_fingerprints (device_key, platform, first_seen, last_seen, signals)
VALUES ($1, $2, $3, $3, $4)
ON CONFLICT (device_key) DO UPDATE
SET
  platform = CASE 
    WHEN device_fingerprints.platform = 'unknown' AND EXCLUDED.platform <> 'unknown'
      THEN EXCLUDED.platform
    ELSE device_fingerprints.platform
  END,
  last_seen = GREATEST(device_fingerprints.last_seen, EXCLUDED.last_seen),
  signals = device_fingerprints.signals || EXCLUDED.signals,
  updated_at = now()
RETURNING id, device_key, platform, first_seen, last_seen, trust_level, risk_score, signals, updated_at
`
	row := r.db.QueryRowContext(ctx, q, deviceKey, platform, observedAt, sigJSON)

	var d DeviceFingerprintDB
	if err := row.Scan(
		&d.ID, &d.DeviceKey, &d.Platform, &d.FirstSeen, &d.LastSeen,
		&d.TrustLevel, &d.RiskScore, &d.Signals, &d.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &d, nil
}

func (r *cockroachDeviceRepository) GetByKey(ctx context.Context, deviceKey string) (*DeviceFingerprintDB, error) {
	const q = `
SELECT id, device_key, platform, first_seen, last_seen, trust_level, risk_score, signals, updated_at
FROM device_fingerprints WHERE device_key = $1
`
	var d DeviceFingerprintDB
	if err := r.db.QueryRowContext(ctx, q, deviceKey).Scan(
		&d.ID, &d.DeviceKey, &d.Platform, &d.FirstSeen, &d.LastSeen,
		&d.TrustLevel, &d.RiskScore, &d.Signals, &d.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &d, nil
}

func (r *cockroachDeviceRepository) UpdateTrustAndRisk(ctx context.Context, deviceID string, trustDelta int, riskDelta int) error {
	const q = `
UPDATE device_fingerprints
SET trust_level = GREATEST(trust_level + $2, 0),
    risk_score = LEAST(GREATEST(risk_score + $3, 0), 100),
    updated_at = now()
WHERE id = $1
`
	_, err := r.db.ExecContext(ctx, q, deviceID, trustDelta, riskDelta)
	return err
}

func (r *cockroachDeviceRepository) SetTrustAndRisk(ctx context.Context, deviceID string, trustLevel int, riskScore int) error {
	const q = `
UPDATE device_fingerprints
SET trust_level = $2,
    risk_score = $3,
    updated_at = now()
WHERE id = $1
`
	_, err := r.db.ExecContext(ctx, q, deviceID, trustLevel, riskScore)
	return err
}

func (r *cockroachDeviceRepository) RecordTrustEvent(ctx context.Context, evt DeviceTrustEvent) error {
	meta := evt.Meta
	if r.encryptMeta != nil && meta != nil {
		if enc, err := r.encryptMeta(ctx, meta); err == nil {
			meta = enc
		}
	}
	const q = `
INSERT INTO device_trust_events (device_id, user_id, event_type, ts, metadata)
VALUES ($1, $2, $3, $4, $5)
`
	_, err := r.db.ExecContext(ctx, q, evt.DeviceID, evt.UserID, evt.Type, evt.TS, meta)
	return err
}

func (r *cockroachDeviceRepository) TouchLastSeen(ctx context.Context, deviceID string, ts time.Time) error {
	const q = `
UPDATE device_fingerprints
SET last_seen = GREATEST(last_seen, $2),
    updated_at = now()
WHERE id = $1
`
	_, err := r.db.ExecContext(ctx, q, deviceID, ts)
	return err
}

// Batch event operations

func (r *cockroachDeviceRepository) StartEventWorker(ctx context.Context) {
	go func() {
		for {
			select {
			case <-r.evTicker.C:
				_ = r.FlushEvents(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (r *cockroachDeviceRepository) QueueEvent(evt DeviceTrustEvent) {
	r.evMu.Lock()
	r.evBuf = append(r.evBuf, evt)
	flush := len(r.evBuf) >= r.evSize
	r.evMu.Unlock()

	if flush {
		_ = r.FlushEvents(context.Background())
	}
}

func (r *cockroachDeviceRepository) FlushEvents(ctx context.Context) error {
	r.evMu.Lock()
	if len(r.evBuf) == 0 {
		r.evMu.Unlock()
		return nil
	}
	batch := make([]DeviceTrustEvent, len(r.evBuf))
	copy(batch, r.evBuf)
	r.evBuf = r.evBuf[:0]
	r.evMu.Unlock()

	// Use multi-row VALUES insert
	const base = `
INSERT INTO device_trust_events (device_id, user_id, event_type, ts, metadata)
VALUES 
`
	args := make([]any, 0, len(batch)*5)
	values := make([]string, 0, len(batch))
	i := 1
	for _, e := range batch {
		meta := e.Meta
		if r.encryptMeta != nil && meta != nil {
			if enc, err := r.encryptMeta(ctx, meta); err == nil {
				meta = enc
			}
		}
		values = append(values, fmt.Sprintf("($%d,$%d,$%d,$%d,$%d)", i, i+1, i+2, i+3, i+4))
		args = append(args, e.DeviceID, e.UserID, e.Type, e.TS, meta)
		i += 5
	}
	q := base + stringsJoin(values, ",")
	_, err := r.db.ExecContext(ctx, q, args...)
	return err
}

func stringsJoin(ss []string, sep string) string {
    switch len(ss) {
    case 0:
        return ""
    case 1:
        return ss[0]
    }

    // Compute total length to preallocate once
    n := len(sep) * (len(ss) - 1)
    for i := 0; i < len(ss); i++ {
        n += len(ss[i])
    }

    // Build into a byte slice
    b := make([]byte, 0, n)
    b = append(b, ss[0]...)           // ✅ append first string's bytes
    for _, s := range ss[1:] {
        b = append(b, sep...)
        b = append(b, s...)
    }
    return string(b)
}
