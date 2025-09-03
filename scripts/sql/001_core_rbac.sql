-- 000_core_rbac.sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- permissions
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

-- roles
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


-- communities (minimal)
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
-- users (minimal subset to satisfy later FKs; extend as needed)
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  phone_number TEXT NOT NULL UNIQUE,
  username TEXT UNIQUE,
  phone_verified BOOLEAN DEFAULT FALSE,
  setup_completed BOOLEAN NOT NULL DEFAULT FALSE,
  primary_device_id UUID REFERENCES device_fingerprints(id) ON DELETE SET NULL,
  public_visibility BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_users_primary_device ON users(primary_device_id);


-- ✅ user_roles (assigns roles to users within a community)
CREATE TABLE IF NOT EXISTS user_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  community_id UUID REFERENCES communities(id) ON DELETE CASCADE,
  sub_scope_id UUID,
  assigned_by UUID,
  granted_by_role_id UUID REFERENCES roles(id),
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  not_before TIMESTAMPTZ,
  status TEXT DEFAULT 'ACTIVE',
  metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_role ON user_roles(role_id);
CREATE INDEX idx_user_roles_status ON user_roles(status);


-- role_permissions (many-to-many)
CREATE TABLE IF NOT EXISTS role_permissions (
  role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);
