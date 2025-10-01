-- 010_seed_and_triggers.sql

-- Ensure the unique index exists for ON CONFLICT
CREATE UNIQUE INDEX IF NOT EXISTS ux_user_roles_user_comm_role
ON user_roles (user_id, community_id, role_id);

-- Seed owner/admin permissions (idempotent)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.name IN (
  'community:manage_settings',
  'community:approve_members',
  'community:remove_members',
  'community:promote_members',
  'community:invite',
  'community:view_members',
  'post:moderate'
)
WHERE r.name IN ('community_owner','community_admin')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Recreate owner membership trigger function with safe ON CONFLICT/NOT EXISTS
CREATE OR REPLACE FUNCTION create_community_owner_membership()
RETURNS TRIGGER AS $BODY$
BEGIN
    -- Owner membership (idempotent via unique constraint)
    INSERT INTO community_members (
        community_id, user_id, status, joined_at, approved_at, role_in_community, role_assigned_at
    ) VALUES (
        NEW.id, NEW.head_user_id, 'ACTIVE', NOW(), NOW(), 'OWNER', NOW()
    ) ON CONFLICT (community_id, user_id) DO NOTHING;

    -- Assign RBAC owner role
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
$BODY$ LANGUAGE plpgsql;

-- Recreate trigger to ensure it points to the latest function
DROP TRIGGER IF EXISTS trigger_create_owner_membership ON communities;
CREATE TRIGGER trigger_create_owner_membership
    AFTER INSERT ON communities
    FOR EACH ROW
    EXECUTE FUNCTION create_community_owner_membership();

-- One-time backfill for pre-existing communities

-- 1) Ensure OWNER membership exists for each creator
INSERT INTO community_members (community_id, user_id, status, joined_at, approved_at, role_in_community, role_assigned_at)
SELECT c.id, c.head_user_id, 'ACTIVE', NOW(), NOW(), 'OWNER', NOW()
FROM communities c
LEFT JOIN community_members m
  ON m.community_id = c.id AND m.user_id = c.head_user_id
WHERE m.id IS NULL
ON CONFLICT (community_id, user_id) DO NOTHING;

-- 2) Ensure community_owner role exists for each creator
WITH owner_role AS (
  SELECT id AS role_id FROM roles WHERE name = 'community_owner' LIMIT 1
),
candidates AS (
  SELECT c.id AS community_id, c.head_user_id, owner_role.role_id
  FROM communities c
  CROSS JOIN owner_role
)
INSERT INTO user_roles (user_id, role_id, community_id, status, assigned_by, assigned_at)
SELECT cand.head_user_id, cand.role_id, cand.community_id, 'ACTIVE', cand.head_user_id, NOW()
FROM candidates cand
LEFT JOIN user_roles ur
  ON ur.user_id = cand.head_user_id
 AND ur.community_id = cand.community_id
 AND ur.role_id = cand.role_id
WHERE ur.user_id IS NULL
ON CONFLICT (user_id, community_id, role_id) DO NOTHING;
