-- CockroachDB/PostgreSQL-compatible migrations

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Main device registry
CREATE TABLE IF NOT EXISTS device_fingerprints (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_key STRING NOT NULL UNIQUE,
  platform STRING NOT NULL,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  trust_level INT NOT NULL DEFAULT 0,   -- 0 unknown, 1 low, 2 med, 3 high (or tune as you like)
  risk_score INT NOT NULL DEFAULT 0,    -- 0..100
  signals JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_fingerprints_device_key ON device_fingerprints(device_key);
CREATE INDEX IF NOT EXISTS idx_device_fingerprints_last_seen ON device_fingerprints(last_seen);
CREATE INDEX IF NOT EXISTS idx_device_fingerprints_trust_risk ON device_fingerprints(trust_level, risk_score);

-- Append-only trust/risk events
CREATE TABLE IF NOT EXISTS device_trust_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES device_fingerprints(id) ON DELETE CASCADE,
  user_id UUID NULL,
  event_type STRING NOT NULL,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_device_trust_events_device_time ON device_trust_events(device_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_device_trust_events_type ON device_trust_events(event_type);
