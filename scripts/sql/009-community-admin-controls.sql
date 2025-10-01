-- 009_community_admin_controls.sql
-- Admin panel controls for community verification, blocking, and management

-- Community verification requests and documents
CREATE TABLE IF NOT EXISTS community_verification_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  requested_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  
  -- Request details
  request_type TEXT NOT NULL CHECK (request_type IN ('GOVERNMENT', 'NGO')),
  organization_name TEXT NOT NULL,
  registration_number TEXT,
  contact_person_name TEXT NOT NULL,
  contact_person_designation TEXT,
  contact_phone TEXT NOT NULL,
  contact_email TEXT,
  
  -- Address information
  address_line1 TEXT NOT NULL,
  address_line2 TEXT,
  city TEXT NOT NULL,
  state TEXT NOT NULL,
  pincode TEXT NOT NULL,
  
  -- Documents submitted
  documents JSONB NOT NULL DEFAULT '[]'::jsonb, -- Array of document objects
  supporting_info JSONB DEFAULT '{}'::jsonb,
  
  -- Request status
  status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'UNDER_REVIEW', 'APPROVED', 'REJECTED', 'MORE_INFO_REQUIRED')),
  
  -- Admin review
  reviewed_by_admin_id UUID REFERENCES users(id) ON DELETE SET NULL,
  reviewed_at TIMESTAMPTZ,
  admin_notes TEXT,
  rejection_reason TEXT,
  additional_info_requested TEXT,
  
  -- Resubmission tracking
  is_resubmission BOOLEAN DEFAULT FALSE,
  original_request_id UUID REFERENCES community_verification_requests(id) ON DELETE SET NULL,
  resubmission_count INTEGER DEFAULT 0,
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for verification requests
CREATE INDEX IF NOT EXISTS idx_verification_requests_community ON community_verification_requests(community_id);
CREATE INDEX IF NOT EXISTS idx_verification_requests_requested_by ON community_verification_requests(requested_by_user_id);
CREATE INDEX IF NOT EXISTS idx_verification_requests_type ON community_verification_requests(request_type);
CREATE INDEX IF NOT EXISTS idx_verification_requests_status ON community_verification_requests(status);
CREATE INDEX IF NOT EXISTS idx_verification_requests_pending ON community_verification_requests(status, created_at) WHERE status IN ('PENDING', 'UNDER_REVIEW');

-- Community blocks by admin (different from user blocks)
CREATE TABLE IF NOT EXISTS community_admin_actions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  admin_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  
  -- Action details
  action_type TEXT NOT NULL CHECK (action_type IN ('BLOCK', 'UNBLOCK', 'SUSPEND', 'UNSUSPEND', 'DELETE', 'VERIFY', 'REJECT_VERIFICATION')),
  reason TEXT NOT NULL,
  severity TEXT DEFAULT 'MEDIUM' CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  
  -- Duration (for temporary actions)
  duration_days INTEGER,
  expires_at TIMESTAMPTZ,
  
  -- Evidence and notes
  evidence_attachments JSONB DEFAULT '[]'::jsonb,
  internal_notes TEXT,
  public_reason TEXT, -- Shown to community members
  
  -- Impact tracking
  affected_members_count INTEGER DEFAULT 0,
  notification_sent BOOLEAN DEFAULT FALSE,
  
  -- Reversal tracking
  is_reversed BOOLEAN DEFAULT FALSE,
  reversed_by_admin_id UUID REFERENCES users(id) ON DELETE SET NULL,
  reversed_at TIMESTAMPTZ,
  reversal_reason TEXT,
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for admin actions
CREATE INDEX IF NOT EXISTS idx_community_admin_actions_community ON community_admin_actions(community_id);
CREATE INDEX IF NOT EXISTS idx_community_admin_actions_admin ON community_admin_actions(admin_user_id);
CREATE INDEX IF NOT EXISTS idx_community_admin_actions_type ON community_admin_actions(action_type);
CREATE INDEX IF NOT EXISTS idx_community_admin_actions_created ON community_admin_actions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_community_admin_actions_active ON community_admin_actions(community_id, is_reversed, expires_at);

-- Admin audit log for all admin activities
CREATE TABLE IF NOT EXISTS admin_audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  
  -- Action details
  action TEXT NOT NULL, -- e.g., 'VERIFY_COMMUNITY', 'BLOCK_USER', 'VIEW_REPORTS'
  resource_type TEXT NOT NULL, -- COMMUNITY, USER, REPORT, SYSTEM
  resource_id UUID, -- ID of the resource being acted upon
  
  -- Context
  ip_address INET,
  user_agent TEXT,
  session_id TEXT,
  
  -- Action data
  action_data JSONB DEFAULT '{}'::jsonb, -- Additional context about the action
  result TEXT, -- SUCCESS, FAILED, PARTIAL
  error_message TEXT,
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for audit log
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_admin ON admin_audit_log(admin_user_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_action ON admin_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_resource ON admin_audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_created ON admin_audit_log(created_at DESC);

-- System reports for admin dashboard
CREATE TABLE IF NOT EXISTS system_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  report_type TEXT NOT NULL CHECK (report_type IN ('COMMUNITY_ABUSE', 'USER_ABUSE', 'CONTENT_VIOLATION', 'SECURITY_INCIDENT', 'SYSTEM_ISSUE')),
  
  -- Report details
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  severity TEXT DEFAULT 'MEDIUM' CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  status TEXT DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED', 'DISMISSED')),
  
  -- Related entities
  reported_community_id UUID REFERENCES communities(id) ON DELETE SET NULL,
  reported_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  reporter_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  
  -- Evidence
  evidence JSONB DEFAULT '[]'::jsonb,
  tags JSONB DEFAULT '[]'::jsonb,
  
  -- Resolution
  assigned_admin_id UUID REFERENCES users(id) ON DELETE SET NULL,
  resolved_by_admin_id UUID REFERENCES users(id) ON DELETE SET NULL,
  resolved_at TIMESTAMPTZ,
  resolution_notes TEXT,
  action_taken TEXT,
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for system reports
CREATE INDEX IF NOT EXISTS idx_system_reports_type ON system_reports(report_type);
CREATE INDEX IF NOT EXISTS idx_system_reports_status ON system_reports(status);
CREATE INDEX IF NOT EXISTS idx_system_reports_severity ON system_reports(severity);
CREATE INDEX IF NOT EXISTS idx_system_reports_assigned ON system_reports(assigned_admin_id);
CREATE INDEX IF NOT EXISTS idx_system_reports_community ON system_reports(reported_community_id);
CREATE INDEX IF NOT EXISTS idx_system_reports_user ON system_reports(reported_user_id);
CREATE INDEX IF NOT EXISTS idx_system_reports_created ON system_reports(created_at DESC);

-- Admin dashboard statistics view
CREATE OR REPLACE VIEW admin_dashboard_stats AS
SELECT 
  -- Community stats
  (SELECT COUNT(*) FROM communities WHERE verification_status = 'PENDING') as pending_verifications,
  (SELECT COUNT(*) FROM communities WHERE is_blocked = true) as blocked_communities,
  (SELECT COUNT(*) FROM communities WHERE created_at >= CURRENT_DATE - INTERVAL '7 days') as new_communities_week,
  (SELECT COUNT(*) FROM communities WHERE type = 'GOVERNMENT' AND verification_status = 'VERIFIED') as verified_government_communities,
  (SELECT COUNT(*) FROM communities WHERE type = 'NGO' AND verification_status = 'VERIFIED') as verified_ngo_communities,
  
  -- User stats
  (SELECT COUNT(*) FROM users WHERE created_at >= CURRENT_DATE - INTERVAL '7 days') as new_users_week,
  (SELECT COUNT(*) FROM user_blocks WHERE created_at >= CURRENT_DATE - INTERVAL '7 days') as new_blocks_week,
  (SELECT COUNT(*) FROM user_reports WHERE status = 'PENDING') as pending_user_reports,
  
  -- Content stats
  (SELECT COUNT(*) FROM community_posts WHERE created_at >= CURRENT_DATE - INTERVAL '24 hours') as posts_last_24h,
  (SELECT COUNT(*) FROM community_posts WHERE status = 'PENDING') as posts_pending_approval,
  (SELECT COUNT(*) FROM system_reports WHERE status IN ('OPEN', 'IN_PROGRESS')) as open_system_reports,
  
  -- Activity stats
  (SELECT COUNT(*) FROM admin_audit_log WHERE created_at >= CURRENT_DATE - INTERVAL '24 hours') as admin_actions_24h;

-- Function to automatically handle verification status updates
CREATE OR REPLACE FUNCTION handle_verification_decision()
RETURNS TRIGGER AS $$
BEGIN
    -- Update community verification status based on verification request
    IF NEW.status = 'APPROVED' AND OLD.status != 'APPROVED' THEN
        UPDATE communities 
        SET 
            verification_status = 'VERIFIED',
            verified_at = NOW(),
            verified_by_admin_id = NEW.reviewed_by_admin_id
        WHERE id = NEW.community_id;
        
        -- Log admin action
        INSERT INTO community_admin_actions (
            community_id, admin_user_id, action_type, reason, public_reason
        ) VALUES (
            NEW.community_id, NEW.reviewed_by_admin_id, 'VERIFY', 
            'Community verification approved', 'Community has been verified'
        );
        
    ELSIF NEW.status = 'REJECTED' AND OLD.status != 'REJECTED' THEN
        UPDATE communities 
        SET 
            verification_status = 'REJECTED',
            verified_at = NULL,
            verified_by_admin_id = NEW.reviewed_by_admin_id
        WHERE id = NEW.community_id;
        
        -- Log admin action
        INSERT INTO community_admin_actions (
            community_id, admin_user_id, action_type, reason, public_reason
        ) VALUES (
            NEW.community_id, NEW.reviewed_by_admin_id, 'REJECT_VERIFICATION', 
            COALESCE(NEW.rejection_reason, 'Verification rejected'), 
            'Community verification was rejected'
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for verification decisions
CREATE TRIGGER trigger_verification_decision
    AFTER UPDATE OF status ON community_verification_requests
    FOR EACH ROW
    WHEN (NEW.status != OLD.status AND NEW.status IN ('APPROVED', 'REJECTED'))
    EXECUTE FUNCTION handle_verification_decision();

-- Function to handle community blocking/unblocking
CREATE OR REPLACE FUNCTION handle_community_blocking()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.action_type = 'BLOCK' THEN
        UPDATE communities 
        SET 
            is_blocked = true,
            blocked_at = NOW(),
            blocked_by_admin_id = NEW.admin_user_id,
            block_reason = NEW.reason
        WHERE id = NEW.community_id;
        
    ELSIF NEW.action_type = 'UNBLOCK' THEN
        UPDATE communities 
        SET 
            is_blocked = false,
            blocked_at = NULL,
            blocked_by_admin_id = NULL,
            block_reason = NULL
        WHERE id = NEW.community_id;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for community blocking
CREATE TRIGGER trigger_community_blocking
    AFTER INSERT ON community_admin_actions
    FOR EACH ROW
    WHEN (NEW.action_type IN ('BLOCK', 'UNBLOCK'))
    EXECUTE FUNCTION handle_community_blocking();

-- Add admin-specific permissions
INSERT INTO permissions (name, description, category, scope_type, created_at, updated_at) VALUES
('admin:dashboard:view', 'View admin dashboard', 'Admin', 'GLOBAL', NOW(), NOW()),
('admin:communities:verify', 'Verify communities', 'Admin', 'GLOBAL', NOW(), NOW()),
('admin:communities:block', 'Block communities', 'Admin', 'GLOBAL', NOW(), NOW()),
('admin:communities:delete', 'Delete communities', 'Admin', 'GLOBAL', NOW(), NOW()),
('admin:users:block', 'Block users globally', 'Admin', 'GLOBAL', NOW(), NOW()),
('admin:users:manage', 'Manage user accounts', 'Admin', 'GLOBAL', NOW(), NOW()),
('admin:reports:view', 'View all reports', 'Admin', 'GLOBAL', NOW(), NOW()),
('admin:reports:resolve', 'Resolve reports', 'Admin', 'GLOBAL', NOW(), NOW()),
('admin:audit:view', 'View audit logs', 'Admin', 'GLOBAL', NOW(), NOW()),
('admin:system:manage', 'Manage system settings', 'Admin', 'GLOBAL', NOW(), NOW());

-- Create admin role and assign permissions
DO $$
DECLARE
    admin_role_id UUID;
    super_admin_role_id UUID;
    perm_record RECORD;
BEGIN
    -- Create regular admin role
    INSERT INTO roles (name, description, community_type, is_system_managed, created_at, updated_at) 
    VALUES ('platform_admin', 'Platform Administrator', 'SYSTEM', TRUE, NOW(), NOW())
    ON CONFLICT (name, community_type) DO NOTHING;
    
    -- Get role IDs
    SELECT id INTO admin_role_id FROM roles WHERE name = 'platform_admin';
    SELECT id INTO super_admin_role_id FROM roles WHERE name = 'super_admin';
    
    -- Assign admin permissions to both admin roles
    FOR perm_record IN 
        SELECT id FROM permissions WHERE category = 'Admin'
    LOOP
        -- Regular admin
        INSERT INTO role_permissions (role_id, permission_id) 
        VALUES (admin_role_id, perm_record.id)
        ON CONFLICT (role_id, permission_id) DO NOTHING;
        
        -- Super admin
        INSERT INTO role_permissions (role_id, permission_id) 
        VALUES (super_admin_role_id, perm_record.id)
        ON CONFLICT (role_id, permission_id) DO NOTHING;
    END LOOP;
END $$;