-- 000_core_rbac.sql

-- Enable pgcrypto for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =========================
-- Permissions
-- =========================
CREATE TABLE IF NOT EXISTS permissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  category TEXT,
  scope_type TEXT DEFAULT 'COMMUNITY',
  is_deprecated BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =========================
-- Roles
-- =========================
CREATE TABLE IF NOT EXISTS roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT,
  community_type TEXT,
  is_custom BOOLEAN DEFAULT FALSE,
  is_system_managed BOOLEAN DEFAULT FALSE,
  created_by_id UUID,
  community_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_role_name_community UNIQUE (name, community_type)
);

-- =========================
-- Communities (minimal)
-- =========================
CREATE TABLE IF NOT EXISTS communities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  is_private BOOLEAN DEFAULT FALSE,
  head_user_id UUID NOT NULL,
  verification_status TEXT DEFAULT 'PENDING',
  payment_status TEXT DEFAULT 'UNPAID',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =========================
-- Users (extended with profile + language preferences)
-- =========================
-- Note: device_fingerprints table must exist before this file or in an earlier migration.
-- =========================
-- Users (profile + array-only language preferences)
-- =========================
-- Users (profile + array-only language preferences)
CREATE TABLE IF NOT EXISTS users (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  phone_number         TEXT NOT NULL UNIQUE,
  username             TEXT UNIQUE,
  display_name         TEXT,
  preferred_languages  TEXT[] NOT NULL DEFAULT ARRAY['en']::TEXT[],
  verification_status  TEXT NOT NULL DEFAULT 'NONE',        -- NONE | BLUE_TICK | GREEN_TICK
  phone_verified       BOOLEAN DEFAULT FALSE,
  setup_completed      BOOLEAN NOT NULL DEFAULT FALSE,
  primary_device_id    UUID REFERENCES device_fingerprints(id) ON DELETE SET NULL,
  public_visibility    BOOLEAN DEFAULT FALSE,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT chk_users_languages_valid
    CHECK (preferred_languages <@ ARRAY['hi','en','ta','te','bn','mr','gu','kn','ml','or','pa','as']),
  CONSTRAINT chk_users_languages_size
    CHECK (cardinality(preferred_languages) BETWEEN 1 AND 3),
  CONSTRAINT chk_users_verification
    CHECK (verification_status IN ('NONE','BLUE_TICK','GREEN_TICK')),

  -- Optional hygiene: username must be non-empty if present
  CONSTRAINT chk_users_username_trimmed
    CHECK (username IS NULL OR username = NULLIF(BTRIM(username), '')),

  -- Optional hygiene: simple phone_number sanity (10-15 digits)
  CONSTRAINT chk_users_phone_format
    CHECK (phone_number ~ '^[0-9]{10,15}$')
);

CREATE INDEX IF NOT EXISTS idx_users_primary_device ON users(primary_device_id);
CREATE INDEX IF NOT EXISTS idx_users_display_name ON users(display_name);
CREATE INDEX IF NOT EXISTS idx_users_verification_status ON users(verification_status);
CREATE INDEX IF NOT EXISTS idx_users_pref_langs_gin ON users USING GIN (preferred_languages);

-- =========================
-- User Roles (assign roles to users within a community)
-- =========================
-- User Roles (assign roles to users within a community)
CREATE TABLE IF NOT EXISTS user_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
  role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE ON UPDATE CASCADE,
  community_id UUID REFERENCES communities(id) ON DELETE CASCADE ON UPDATE CASCADE,
  sub_scope_id UUID,
  assigned_by UUID,
  granted_by_role_id UUID REFERENCES roles(id) ON DELETE SET NULL ON UPDATE CASCADE,
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  not_before TIMESTAMPTZ,
  status TEXT DEFAULT 'ACTIVE',
  metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_status ON user_roles(status);

-- Role Permissions (many-to-many)
CREATE TABLE IF NOT EXISTS role_permissions (
  role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE ON UPDATE CASCADE,
  permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE ON UPDATE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);
