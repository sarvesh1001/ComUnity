package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type OTPRequest struct {
	ID           string          // UUID
	PhoneHash    string
	DeviceKey    *string
	Channel      string
	Provider     *string
	TemplateID   *string
	SenderID     *string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Status       string
	AttemptCount int
	IPBucket     *string
	UAHash       *string
	Platform     *string
	AppVersion   *string
	Metadata     json.RawMessage
}

type OTPVerification struct {
	ID           string          // UUID
	OTPID        string
	VerifiedAt   time.Time
	Result       string
	Reason       *string
	DeviceKey    *string
	IPBucket     *string
	UAHash       *string
	RiskSnapshot json.RawMessage
}

type OTPRepository interface {
	CreateOTPRequest(ctx context.Context, r OTPRequest) (string, error)
	MarkOTPRequestStatus(ctx context.Context, otpID string, status string, meta map[string]any) error
	IncrementOTPAttempts(ctx context.Context, otpID string) error

	RecordOTPVerification(ctx context.Context, v OTPVerification) (string, error)

	GetRecentRequestsByPhone(ctx context.Context, phoneHash string, since time.Time, limit int) ([]OTPRequest, error)
	GetLastRequestByPhone(ctx context.Context, phoneHash string) (*OTPRequest, error)
}

type cockroachOTPRepository struct {
	db *sql.DB
}

func NewCockroachOTPRepository(db *sql.DB) OTPRepository {
	return &cockroachOTPRepository{db: db}
}

func (r *cockroachOTPRepository) CreateOTPRequest(ctx context.Context, req OTPRequest) (string, error) {
	if req.Metadata == nil {
		req.Metadata = json.RawMessage(`{}`)
	}
	const q = `
INSERT INTO otp_requests (phone_hash, device_key, channel, provider, template_id, sender_id, created_at, expires_at, status, attempt_count, ip_bucket, ua_hash, platform, app_version, metadata)
VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7, now()),$8,$9,$10,$11,$12,$13,$14,$15)
RETURNING id
`
	var id string
	err := r.db.QueryRowContext(ctx, q,
		req.PhoneHash, req.DeviceKey, req.Channel, req.Provider, req.TemplateID, req.SenderID,
		sql.NullTime{Time: req.CreatedAt, Valid: !req.CreatedAt.IsZero()},
		req.ExpiresAt, req.Status, req.AttemptCount, req.IPBucket, req.UAHash, req.Platform, req.AppVersion, req.Metadata,
	).Scan(&id)
	return id, err
}

func (r *cockroachOTPRepository) MarkOTPRequestStatus(ctx context.Context, otpID string, status string, meta map[string]any) error {
	var b json.RawMessage
	if meta != nil {
		bs, _ := json.Marshal(meta)
		b = bs
	} else {
		b = json.RawMessage(`{}`)
	}
	const q = `
UPDATE otp_requests
SET status = $2,
    metadata = COALESCE(metadata, '{}'::jsonb) || $3::jsonb
WHERE id = $1
`
	_, err := r.db.ExecContext(ctx, q, otpID, status, b)
	return err
}

func (r *cockroachOTPRepository) IncrementOTPAttempts(ctx context.Context, otpID string) error {
	const q = `
UPDATE otp_requests
SET attempt_count = attempt_count + 1
WHERE id = $1
`
	_, err := r.db.ExecContext(ctx, q, otpID)
	return err
}

func (r *cockroachOTPRepository) RecordOTPVerification(ctx context.Context, v OTPVerification) (string, error) {
	if v.RiskSnapshot == nil {
		v.RiskSnapshot = json.RawMessage(`{}`)
	}
	const q = `
INSERT INTO otp_verifications (otp_id, verified_at, result, reason, device_key, ip_bucket, ua_hash, risk_snapshot)
VALUES ($1, COALESCE($2, now()), $3, $4, $5, $6, $7, $8)
RETURNING id
`
	var id string
	err := r.db.QueryRowContext(ctx, q,
		v.OTPID,
		sql.NullTime{Time: v.VerifiedAt, Valid: !v.VerifiedAt.IsZero()},
		v.Result, v.Reason, v.DeviceKey, v.IPBucket, v.UAHash, v.RiskSnapshot,
	).Scan(&id)
	return id, err
}

func (r *cockroachOTPRepository) GetRecentRequestsByPhone(ctx context.Context, phoneHash string, since time.Time, limit int) ([]OTPRequest, error) {
	const q = `
SELECT id, phone_hash, device_key, channel, provider, template_id, sender_id, created_at, expires_at, status, attempt_count, ip_bucket, ua_hash, platform, app_version, metadata
FROM otp_requests
WHERE phone_hash = $1 AND created_at >= $2
ORDER BY created_at DESC
LIMIT $3
`
	rows, err := r.db.QueryContext(ctx, q, phoneHash, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]OTPRequest, 0, limit)
	for rows.Next() {
		var rec OTPRequest
		err := rows.Scan(&rec.ID, &rec.PhoneHash, &rec.DeviceKey, &rec.Channel, &rec.Provider, &rec.TemplateID, &rec.SenderID, &rec.CreatedAt, &rec.ExpiresAt, &rec.Status, &rec.AttemptCount, &rec.IPBucket, &rec.UAHash, &rec.Platform, &rec.AppVersion, &rec.Metadata)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (r *cockroachOTPRepository) GetLastRequestByPhone(ctx context.Context, phoneHash string) (*OTPRequest, error) {
	const q = `
SELECT id, phone_hash, device_key, channel, provider, template_id, sender_id, created_at, expires_at, status, attempt_count, ip_bucket, ua_hash, platform, app_version, metadata
FROM otp_requests
WHERE phone_hash = $1
ORDER BY created_at DESC
LIMIT 1
`
	row := r.db.QueryRowContext(ctx, q, phoneHash)
	var rec OTPRequest
	if err := row.Scan(&rec.ID, &rec.PhoneHash, &rec.DeviceKey, &rec.Channel, &rec.Provider, &rec.TemplateID, &rec.SenderID, &rec.CreatedAt, &rec.ExpiresAt, &rec.Status, &rec.AttemptCount, &rec.IPBucket, &rec.UAHash, &rec.Platform, &rec.AppVersion, &rec.Metadata); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &rec, nil
}
