CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- OTP requests (authoritative audit of sends)
CREATE TABLE IF NOT EXISTS otp_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  phone_hash TEXT NOT NULL,                     -- HMAC(phone) with server pepper; never store phone
  device_key TEXT NULL,                         -- from fingerprint middleware (if available)
  channel TEXT NOT NULL,                        -- "sms"|"whatsapp"|"email"
  provider TEXT NULL,                           -- vendor identifier
  template_id TEXT NULL,                        -- TRAI/template traceability
  sender_id TEXT NULL,                          -- sender header used
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL,                         -- "requested"|"delivered"|"failed"|"throttled"|"expired"|"cancelled"
  attempt_count INT NOT NULL DEFAULT 0,
  ip_bucket TEXT NULL,                          -- privacy-preserving from fingerprint middleware
  ua_hash TEXT NULL,                            -- from fingerprint middleware
  platform TEXT NULL,                           -- "ios"|"android"|"web"
  app_version TEXT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_otp_requests_phone_time   ON otp_requests (phone_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_otp_requests_device_time  ON otp_requests (device_key, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_otp_requests_status       ON otp_requests (status);
CREATE INDEX IF NOT EXISTS idx_otp_requests_created_at   ON otp_requests (created_at DESC);

-- OTP verifications (authoritative audit of verify outcomes)
CREATE TABLE IF NOT EXISTS otp_verifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  otp_id UUID NOT NULL REFERENCES otp_requests(id) ON DELETE CASCADE,
  verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  result TEXT NOT NULL,                         -- "success"|"failure"|"expired"|"mismatch"|"max_attempts"|"throttled"
  reason TEXT NULL,                             -- free-text reason or enum string
  device_key TEXT NULL,
  ip_bucket TEXT NULL,
  ua_hash TEXT NULL,
  risk_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_otp_verifications_otp         ON otp_verifications (otp_id);
CREATE INDEX IF NOT EXISTS idx_otp_verifications_result_time ON otp_verifications (result, verified_at DESC);
