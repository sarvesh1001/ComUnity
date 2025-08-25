-- Add user blocking tables
CREATE TABLE user_blocks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    blocker_user_id UUID NOT NULL,
    blocked_user_id UUID NOT NULL,
    community_id UUID,
    reason TEXT,
    block_type VARCHAR(20) DEFAULT 'FULL',
    expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_blocks_blocked_user ON user_blocks(blocked_user_id);
CREATE INDEX idx_user_blocks_community ON user_blocks(community_id);
CREATE INDEX idx_user_blocks_expires ON user_blocks(expires_at);

CREATE TABLE user_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_user_id UUID NOT NULL,
    reported_user_id UUID NOT NULL,
    community_id UUID,
    content_id UUID,
    content_type VARCHAR(50),
    reason TEXT,
    category VARCHAR(50),
    status VARCHAR(20) DEFAULT 'PENDING',
    action_taken VARCHAR(50),
    reviewed_by UUID,
    reviewed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_reports_reported_user ON user_reports(reported_user_id);
CREATE INDEX idx_user_reports_reporter ON user_reports(reporter_user_id);
CREATE INDEX idx_user_reports_community ON user_reports(community_id);
CREATE INDEX idx_user_reports_status ON user_reports(status);

-- Add new permissions for blocking and reporting
INSERT INTO permissions (name, description, category, scope_type, created_at, updated_at) VALUES
('user:block:global', 'Block users globally', 'Moderation', 'GLOBAL', NOW(), NOW()),
('user:block:community', 'Block users in community', 'Moderation', 'COMMUNITY', NOW(), NOW()),
('user:unblock:global', 'Unblock users globally', 'Moderation', 'GLOBAL', NOW(), NOW()),
('user:unblock:community', 'Unblock users in community', 'Moderation', 'COMMUNITY', NOW(), NOW()),
('user:report', 'Report users or content', 'Moderation', 'COMMUNITY', NOW(), NOW()),
('report:moderate:global', 'Moderate reports globally', 'Moderation', 'GLOBAL', NOW(), NOW()),
('report:moderate:community', 'Moderate reports in community', 'Moderation', 'COMMUNITY', NOW(), NOW()),
('content:moderate', 'Moderate content', 'Moderation', 'COMMUNITY', NOW(), NOW());

-- Add these permissions to appropriate roles
-- For example, add moderation permissions to moderator roles