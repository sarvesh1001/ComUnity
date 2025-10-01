-- 006_community_enhancements.sql
-- Enhanced community system with verification, admin controls, and unique names

-- Drop existing communities table and recreate with enhanced structure
DROP TABLE IF EXISTS communities CASCADE;

-- Enhanced Communities table
CREATE TABLE IF NOT EXISTS communities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT,
  type TEXT NOT NULL CHECK (type IN ('SCHOOL', 'COLLEGE', 'GOVERNMENT', 'NGO', 'BUSINESS', 'SOCIAL', 'OTHERS')),
  is_private BOOLEAN DEFAULT FALSE,
  head_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

  -- Verification system (for GOVERNMENT & NGO)
  verification_status TEXT DEFAULT 'PENDING' CHECK (verification_status IN ('PENDING', 'VERIFIED', 'REJECTED', 'NOT_REQUIRED')),
  verification_requested_at TIMESTAMPTZ,
  verified_at TIMESTAMPTZ,
  verified_by_admin_id UUID REFERENCES users(id) ON DELETE SET NULL,
  verification_documents JSONB DEFAULT '{}'::jsonb,
  verification_notes TEXT,

  -- Admin controls
  is_blocked BOOLEAN DEFAULT FALSE,
  blocked_at TIMESTAMPTZ,
  blocked_by_admin_id UUID REFERENCES users(id) ON DELETE SET NULL,
  block_reason TEXT,

  -- Community settings
  member_limit INTEGER,
  auto_approve_members BOOLEAN DEFAULT TRUE, -- FALSE for private communities
  allow_member_posts BOOLEAN DEFAULT TRUE,
  allow_member_invites BOOLEAN DEFAULT FALSE,
  require_approval_to_post BOOLEAN DEFAULT FALSE,

  -- Location (optional)
  location_data JSONB DEFAULT '{}'::jsonb,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for communities
CREATE INDEX IF NOT EXISTS idx_communities_type ON communities(type);
CREATE INDEX IF NOT EXISTS idx_communities_verification_status ON communities(verification_status);
CREATE INDEX IF NOT EXISTS idx_communities_head_user ON communities(head_user_id);
CREATE INDEX IF NOT EXISTS idx_communities_blocked ON communities(is_blocked);
CREATE INDEX IF NOT EXISTS idx_communities_private ON communities(is_private);

-- Enforce unique community names (normalized: trim, collapse spaces, lowercase)
CREATE UNIQUE INDEX IF NOT EXISTS ux_communities_name_norm
ON communities ((lower(regexp_replace(trim(name), '\s+', ' ', 'g'))));

-- If uniqueness should be scoped by city, use this variant instead:
-- CREATE UNIQUE INDEX IF NOT EXISTS ux_communities_name_city_norm
-- ON communities (
--   (lower(regexp_replace(trim(name), '\s+', ' ', 'g'))),
--   coalesce(lower((location_data->>'city')), '')
-- );

-- Platform/admin permissions
-- Do NOT include 'community:create:any'; add NGO creation permission to gate GOVERNMENT/NGO only
INSERT INTO permissions (name, description, category, scope_type, created_at, updated_at)
VALUES
  ('admin:super', 'Super admin access', 'Admin', 'GLOBAL', NOW(), NOW()),
  ('community:verify:government', 'Verify government communities', 'Admin', 'GLOBAL', NOW(), NOW()),
  ('community:verify:ngo', 'Verify NGO communities', 'Admin', 'GLOBAL', NOW(), NOW()),
  ('community:block:any', 'Block any community', 'Admin', 'GLOBAL', NOW(), NOW()),
  ('community:unblock:any', 'Unblock any community', 'Admin', 'GLOBAL', NOW(), NOW()),
  ('community:create:government', 'Create government communities', 'Community', 'GLOBAL', NOW(), NOW()),
  ('community:create:ngo', 'Create NGO communities', 'Community', 'GLOBAL', NOW(), NOW()),
  ('community:moderate:global', 'Moderate all communities globally', 'Admin', 'GLOBAL', NOW(), NOW())
ON CONFLICT (name) DO NOTHING;

-- Create super admin role
INSERT INTO roles (name, description, community_type, is_system_managed, created_at, updated_at)
VALUES ('super_admin', 'Super Administrator with full system access', 'SYSTEM', TRUE, NOW(), NOW())
ON CONFLICT (name, community_type) DO NOTHING;

-- Assign permissions to super_admin
DO $$
DECLARE
  super_admin_role_id UUID;
  perm_record RECORD;
BEGIN
  SELECT id INTO super_admin_role_id FROM roles WHERE name = 'super_admin';

  FOR perm_record IN
    SELECT id FROM permissions
    WHERE category = 'Admin' OR name LIKE 'community:%' OR name = 'admin:super'
  LOOP
    INSERT INTO role_permissions (role_id, permission_id)
    VALUES (super_admin_role_id, perm_record.id)
    ON CONFLICT (role_id, permission_id) DO NOTHING;
  END LOOP;
END $$;

-- Function to automatically set verification status based on community type
CREATE OR REPLACE FUNCTION set_community_verification_status()
RETURNS TRIGGER AS $$
BEGIN
  -- Set verification status based on community type
  IF NEW.type IN ('GOVERNMENT', 'NGO') THEN
    NEW.verification_status := 'PENDING';
    NEW.verification_requested_at := NOW();
  ELSE
    NEW.verification_status := 'NOT_REQUIRED';
  END IF;

  -- Set auto_approve_members to FALSE for private communities
  IF NEW.is_private = TRUE THEN
    NEW.auto_approve_members := FALSE;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for community verification
CREATE TRIGGER trigger_community_verification_status
  BEFORE INSERT OR UPDATE OF type, is_private ON communities
  FOR EACH ROW
  EXECUTE FUNCTION set_community_verification_status();
