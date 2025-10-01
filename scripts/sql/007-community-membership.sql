-- 007_community_membership.sql
-- Community membership system with join requests and roles

-- Community membership table
CREATE TABLE IF NOT EXISTS community_members (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('PENDING', 'ACTIVE', 'SUSPENDED', 'BANNED', 'LEFT')),
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  approved_at TIMESTAMPTZ,
  approved_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,

  role_in_community TEXT DEFAULT 'MEMBER' CHECK (role_in_community IN ('OWNER', 'ADMIN', 'MODERATOR', 'MEMBER')),
  role_assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
  role_assigned_at TIMESTAMPTZ,

  join_requested_at TIMESTAMPTZ,
  join_message TEXT,
  rejection_reason TEXT,

  last_activity_at TIMESTAMPTZ DEFAULT NOW(),
  notification_settings JSONB DEFAULT '{"posts": true, "events": true, "mentions": true}'::jsonb,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE(community_id, user_id)
);

-- Indexes for community members
CREATE INDEX IF NOT EXISTS idx_community_members_community ON community_members(community_id);
CREATE INDEX IF NOT EXISTS idx_community_members_user ON community_members(user_id);
CREATE INDEX IF NOT EXISTS idx_community_members_status ON community_members(status);
CREATE INDEX IF NOT EXISTS idx_community_members_role ON community_members(role_in_community);
CREATE INDEX IF NOT EXISTS idx_community_members_joined ON community_members(joined_at DESC);

-- Community join requests
CREATE TABLE IF NOT EXISTS community_join_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  request_message TEXT,
  status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED')),

  reviewed_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  reviewed_at TIMESTAMPTZ,
  admin_response TEXT,

  auto_approved BOOLEAN DEFAULT FALSE,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE(community_id, user_id)
);

-- Indexes for join requests
CREATE INDEX IF NOT EXISTS idx_join_requests_community ON community_join_requests(community_id);
CREATE INDEX IF NOT EXISTS idx_join_requests_user ON community_join_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_join_requests_status ON community_join_requests(status);
CREATE INDEX IF NOT EXISTS idx_join_requests_pending ON community_join_requests(status, created_at) WHERE status = 'PENDING';

-- Community invitations
CREATE TABLE IF NOT EXISTS community_invitations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  inviter_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  invitee_phone_number TEXT,
  invitee_user_id UUID REFERENCES users(id) ON DELETE SET NULL,

  message TEXT,
  suggested_role TEXT DEFAULT 'MEMBER' CHECK (suggested_role IN ('ADMIN', 'MODERATOR', 'MEMBER')),
  status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACCEPTED', 'DECLINED', 'EXPIRED', 'CANCELLED')),

  expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '7 days'),

  responded_at TIMESTAMPTZ,
  response_message TEXT,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for invitations
CREATE INDEX IF NOT EXISTS idx_community_invitations_community ON community_invitations(community_id);
CREATE INDEX IF NOT EXISTS idx_community_invitations_inviter ON community_invitations(inviter_user_id);
CREATE INDEX IF NOT EXISTS idx_community_invitations_invitee_user ON community_invitations(invitee_user_id);
CREATE INDEX IF NOT EXISTS idx_community_invitations_invitee_phone ON community_invitations(invitee_phone_number);
CREATE INDEX IF NOT EXISTS idx_community_invitations_status ON community_invitations(status);
CREATE INDEX IF NOT EXISTS idx_community_invitations_expires ON community_invitations(expires_at);

-- Add community-specific permissions (idempotent)
INSERT INTO permissions (name, description, category, scope_type, created_at, updated_at) VALUES
('community:join', 'Join public communities', 'Community', 'COMMUNITY', NOW(), NOW()),
('community:request_join', 'Request to join private communities', 'Community', 'COMMUNITY', NOW(), NOW()),
('community:invite', 'Invite users to community', 'Community', 'COMMUNITY', NOW(), NOW()),
('community:approve_members', 'Approve member join requests', 'Community', 'COMMUNITY', NOW(), NOW()),
('community:remove_members', 'Remove members from community', 'Community', 'COMMUNITY', NOW(), NOW()),
('community:promote_members', 'Promote members to higher roles', 'Community', 'COMMUNITY', NOW(), NOW()),
('community:manage_settings', 'Manage community settings', 'Community', 'COMMUNITY', NOW(), NOW()),
('community:view_members', 'View community member list', 'Community', 'COMMUNITY', NOW(), NOW())
ON CONFLICT (name) DO NOTHING;

-- Create default community roles (idempotent)
INSERT INTO roles (name, description, community_type, is_system_managed, created_at, updated_at) VALUES
('community_owner', 'Community Owner - Full Access', 'ALL', TRUE, NOW(), NOW()),
('community_admin', 'Community Administrator', 'ALL', TRUE, NOW(), NOW()),
('community_moderator', 'Community Moderator', 'ALL', TRUE, NOW(), NOW()),
('community_member', 'Community Member', 'ALL', TRUE, NOW(), NOW())
ON CONFLICT (name, community_type) DO NOTHING;

-- Function to auto-approve public community joins
CREATE OR REPLACE FUNCTION handle_community_join_request()
RETURNS TRIGGER AS $$
DECLARE
    community_record RECORD;
BEGIN
    SELECT is_private, auto_approve_members INTO community_record
    FROM communities WHERE id = NEW.community_id;

    IF community_record.is_private = FALSE AND community_record.auto_approve_members = TRUE THEN
        NEW.status := 'APPROVED';
        NEW.auto_approved := TRUE;
        NEW.reviewed_at := NOW();

        INSERT INTO community_members (
            community_id, user_id, status, joined_at, approved_at, role_in_community, join_requested_at
        ) VALUES (
            NEW.community_id, NEW.user_id, 'ACTIVE', NOW(), NOW(), 'MEMBER', NEW.created_at
        ) ON CONFLICT (community_id, user_id) DO NOTHING;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for auto-approval
CREATE TRIGGER trigger_auto_approve_join
    BEFORE INSERT ON community_join_requests
    FOR EACH ROW
    EXECUTE FUNCTION handle_community_join_request();

-- Function to create owner membership when community is created
CREATE OR REPLACE FUNCTION create_community_owner_membership()
RETURNS TRIGGER AS $$
BEGIN
    -- Create OWNER membership for community creator (idempotent via unique key)
    INSERT INTO community_members (
        community_id, user_id, status, joined_at, approved_at, role_in_community, role_assigned_at
    ) VALUES (
        NEW.id, NEW.head_user_id, 'ACTIVE', NOW(), NOW(), 'OWNER', NOW()
    ) ON CONFLICT (community_id, user_id) DO NOTHING;

    -- Assign RBAC owner role in this community
    -- Prefer ON CONFLICT if unique index exists (user_id, community_id, role_id),
    -- else fallback to NOT EXISTS to avoid error on systems lacking the index.
    WITH owner_role AS (
        SELECT id AS role_id FROM roles WHERE name = 'community_owner' LIMIT 1
    )
    INSERT INTO user_roles (user_id, role_id, community_id, status, assigned_by, assigned_at)
    SELECT NEW.head_user_id, o.role_id, NEW.id, 'ACTIVE', NEW.head_user_id, NOW()
    FROM owner_role o
    WHERE NOT EXISTS (
        SELECT 1 FROM user_roles ur
        WHERE ur.user_id = NEW.head_user_id
          AND ur.community_id = NEW.id
          AND ur.role_id = o.role_id
    )
    ON CONFLICT (user_id, community_id, role_id) DO NOTHING;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for owner membership
CREATE TRIGGER trigger_create_owner_membership
    AFTER INSERT ON communities
    FOR EACH ROW
    EXECUTE FUNCTION create_community_owner_membership();
