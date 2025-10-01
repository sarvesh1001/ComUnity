-- 008_community_content.sql
-- Community content system - posts, comments, events, alerts

-- Community posts
CREATE TABLE IF NOT EXISTS community_posts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  author_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  
  -- Post content
  title TEXT,
  content TEXT NOT NULL,
  post_type TEXT DEFAULT 'POST' CHECK (post_type IN ('POST', 'ANNOUNCEMENT', 'ALERT', 'EVENT', 'POLL')),
  media_attachments JSONB DEFAULT '[]'::jsonb, -- URLs, file references
  
  -- Post settings
  is_pinned BOOLEAN DEFAULT FALSE,
  is_featured BOOLEAN DEFAULT FALSE,
  allow_comments BOOLEAN DEFAULT TRUE,
  require_approval BOOLEAN DEFAULT FALSE,
  
  -- Moderation
  status TEXT DEFAULT 'PUBLISHED' CHECK (status IN ('DRAFT', 'PENDING', 'PUBLISHED', 'HIDDEN', 'REMOVED')),
  moderated_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  moderated_at TIMESTAMPTZ,
  moderation_reason TEXT,
  
  -- Engagement metrics
  likes_count INTEGER DEFAULT 0,
  comments_count INTEGER DEFAULT 0,
  shares_count INTEGER DEFAULT 0,
  views_count INTEGER DEFAULT 0,
  
  -- Priority for alerts and announcements
  priority TEXT DEFAULT 'NORMAL' CHECK (priority IN ('LOW', 'NORMAL', 'HIGH', 'URGENT')),
  
  -- Event-specific fields (when post_type = 'EVENT')
  event_start_time TIMESTAMPTZ,
  event_end_time TIMESTAMPTZ,
  event_location TEXT,
  max_attendees INTEGER,
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for posts
CREATE INDEX IF NOT EXISTS idx_community_posts_community ON community_posts(community_id);
CREATE INDEX IF NOT EXISTS idx_community_posts_author ON community_posts(author_user_id);
CREATE INDEX IF NOT EXISTS idx_community_posts_type ON community_posts(post_type);
CREATE INDEX IF NOT EXISTS idx_community_posts_status ON community_posts(status);
CREATE INDEX IF NOT EXISTS idx_community_posts_created ON community_posts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_community_posts_pinned ON community_posts(is_pinned, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_community_posts_priority ON community_posts(priority, created_at DESC);

-- Post comments
CREATE TABLE IF NOT EXISTS post_comments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  post_id UUID NOT NULL REFERENCES community_posts(id) ON DELETE CASCADE,
  author_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  parent_comment_id UUID REFERENCES post_comments(id) ON DELETE CASCADE, -- for nested comments
  
  -- Comment content
  content TEXT NOT NULL,
  media_attachments JSONB DEFAULT '[]'::jsonb,
  
  -- Moderation
  status TEXT DEFAULT 'PUBLISHED' CHECK (status IN ('PUBLISHED', 'HIDDEN', 'REMOVED')),
  moderated_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  moderated_at TIMESTAMPTZ,
  moderation_reason TEXT,
  
  -- Engagement
  likes_count INTEGER DEFAULT 0,
  replies_count INTEGER DEFAULT 0,
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for comments
CREATE INDEX IF NOT EXISTS idx_post_comments_post ON post_comments(post_id);
CREATE INDEX IF NOT EXISTS idx_post_comments_author ON post_comments(author_user_id);
CREATE INDEX IF NOT EXISTS idx_post_comments_parent ON post_comments(parent_comment_id);
CREATE INDEX IF NOT EXISTS idx_post_comments_status ON post_comments(status);
CREATE INDEX IF NOT EXISTS idx_post_comments_created ON post_comments(created_at DESC);

-- Post likes/reactions
CREATE TABLE IF NOT EXISTS post_reactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  post_id UUID REFERENCES community_posts(id) ON DELETE CASCADE,
  comment_id UUID REFERENCES post_comments(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  
  -- Reaction type
  reaction_type TEXT DEFAULT 'LIKE' CHECK (reaction_type IN ('LIKE', 'LOVE', 'LAUGH', 'ANGRY', 'SAD')),
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  
  -- Constraints - user can only react once per post/comment
  CONSTRAINT chk_post_reactions_target CHECK (
    (post_id IS NOT NULL AND comment_id IS NULL) OR 
    (post_id IS NULL AND comment_id IS NOT NULL)
  ),
  UNIQUE(post_id, user_id),
  UNIQUE(comment_id, user_id)
);

-- Indexes for reactions
CREATE INDEX IF NOT EXISTS idx_post_reactions_post ON post_reactions(post_id);
CREATE INDEX IF NOT EXISTS idx_post_reactions_comment ON post_reactions(comment_id);
CREATE INDEX IF NOT EXISTS idx_post_reactions_user ON post_reactions(user_id);

-- Event attendees (when post_type = 'EVENT')
CREATE TABLE IF NOT EXISTS event_attendees (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_post_id UUID NOT NULL REFERENCES community_posts(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  
  -- RSVP status
  status TEXT DEFAULT 'INTERESTED' CHECK (status IN ('INTERESTED', 'GOING', 'NOT_GOING', 'MAYBE')),
  response_message TEXT,
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  
  UNIQUE(event_post_id, user_id)
);

-- Indexes for event attendees
CREATE INDEX IF NOT EXISTS idx_event_attendees_event ON event_attendees(event_post_id);
CREATE INDEX IF NOT EXISTS idx_event_attendees_user ON event_attendees(user_id);
CREATE INDEX IF NOT EXISTS idx_event_attendees_status ON event_attendees(status);

-- Community announcements/alerts tracking
CREATE TABLE IF NOT EXISTS community_notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  post_id UUID REFERENCES community_posts(id) ON DELETE CASCADE,
  sender_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  
  -- Notification details
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  notification_type TEXT DEFAULT 'ANNOUNCEMENT' CHECK (notification_type IN ('ANNOUNCEMENT', 'ALERT', 'REMINDER', 'SYSTEM')),
  priority TEXT DEFAULT 'NORMAL' CHECK (priority IN ('LOW', 'NORMAL', 'HIGH', 'URGENT')),
  
  -- Targeting
  target_role TEXT, -- Send to specific role only
  target_users JSONB DEFAULT '[]'::jsonb, -- Specific user IDs
  
  -- Delivery tracking
  total_recipients INTEGER DEFAULT 0,
  delivered_count INTEGER DEFAULT 0,
  read_count INTEGER DEFAULT 0,
  
  -- Schedule
  scheduled_at TIMESTAMPTZ,
  sent_at TIMESTAMPTZ,
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for notifications
CREATE INDEX IF NOT EXISTS idx_community_notifications_community ON community_notifications(community_id);
CREATE INDEX IF NOT EXISTS idx_community_notifications_sender ON community_notifications(sender_user_id);
CREATE INDEX IF NOT EXISTS idx_community_notifications_type ON community_notifications(notification_type);
CREATE INDEX IF NOT EXISTS idx_community_notifications_priority ON community_notifications(priority);
CREATE INDEX IF NOT EXISTS idx_community_notifications_scheduled ON community_notifications(scheduled_at);

-- User notification delivery tracking
CREATE TABLE IF NOT EXISTS user_notification_status (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  notification_id UUID NOT NULL REFERENCES community_notifications(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  
  -- Delivery status
  status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'DELIVERED', 'READ', 'DISMISSED', 'FAILED')),
  delivered_at TIMESTAMPTZ,
  read_at TIMESTAMPTZ,
  dismissed_at TIMESTAMPTZ,
  
  -- Delivery method
  delivery_channels JSONB DEFAULT '["in_app"]'::jsonb, -- in_app, push, sms, email
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  
  UNIQUE(notification_id, user_id)
);

-- Indexes for user notification status
CREATE INDEX IF NOT EXISTS idx_user_notification_status_notification ON user_notification_status(notification_id);
CREATE INDEX IF NOT EXISTS idx_user_notification_status_user ON user_notification_status(user_id);
CREATE INDEX IF NOT EXISTS idx_user_notification_status_status ON user_notification_status(status);
CREATE INDEX IF NOT EXISTS idx_user_notification_status_unread ON user_notification_status(user_id, status) WHERE status IN ('DELIVERED', 'PENDING');

-- Add content-related permissions
INSERT INTO permissions (name, description, category, scope_type, created_at, updated_at) VALUES
('post:create', 'Create posts in community', 'Content', 'COMMUNITY', NOW(), NOW()),
('post:edit:own', 'Edit own posts', 'Content', 'COMMUNITY', NOW(), NOW()),
('post:edit:any', 'Edit any posts in community', 'Content', 'COMMUNITY', NOW(), NOW()),
('post:delete:own', 'Delete own posts', 'Content', 'COMMUNITY', NOW(), NOW()),
('post:delete:any', 'Delete any posts in community', 'Content', 'COMMUNITY', NOW(), NOW()),
('post:pin', 'Pin posts in community', 'Content', 'COMMUNITY', NOW(), NOW()),
('post:feature', 'Feature posts in community', 'Content', 'COMMUNITY', NOW(), NOW()),
('post:moderate', 'Moderate posts in community', 'Content', 'COMMUNITY', NOW(), NOW()),
('comment:create', 'Create comments on posts', 'Content', 'COMMUNITY', NOW(), NOW()),
('comment:moderate', 'Moderate comments in community', 'Content', 'COMMUNITY', NOW(), NOW()),
('event:create', 'Create events in community', 'Content', 'COMMUNITY', NOW(), NOW()),
('event:manage', 'Manage events in community', 'Content', 'COMMUNITY', NOW(), NOW()),
('alert:send:normal', 'Send normal alerts to community', 'Content', 'COMMUNITY', NOW(), NOW()),
('alert:send:urgent', 'Send urgent alerts to community', 'Content', 'COMMUNITY', NOW(), NOW()),
('notification:send', 'Send notifications to community members', 'Content', 'COMMUNITY', NOW(), NOW());

-- Functions to update counters
CREATE OR REPLACE FUNCTION update_post_counters()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Update comments count
        IF TG_TABLE_NAME = 'post_comments' THEN
            UPDATE community_posts 
            SET comments_count = comments_count + 1, updated_at = NOW()
            WHERE id = NEW.post_id;
        END IF;
        
        -- Update likes count
        IF TG_TABLE_NAME = 'post_reactions' THEN
            IF NEW.post_id IS NOT NULL THEN
                UPDATE community_posts 
                SET likes_count = likes_count + 1, updated_at = NOW()
                WHERE id = NEW.post_id;
            ELSIF NEW.comment_id IS NOT NULL THEN
                UPDATE post_comments 
                SET likes_count = likes_count + 1, updated_at = NOW()
                WHERE id = NEW.comment_id;
            END IF;
        END IF;
        
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        -- Update comments count
        IF TG_TABLE_NAME = 'post_comments' THEN
            UPDATE community_posts 
            SET comments_count = GREATEST(0, comments_count - 1), updated_at = NOW()
            WHERE id = OLD.post_id;
        END IF;
        
        -- Update likes count
        IF TG_TABLE_NAME = 'post_reactions' THEN
            IF OLD.post_id IS NOT NULL THEN
                UPDATE community_posts 
                SET likes_count = GREATEST(0, likes_count - 1), updated_at = NOW()
                WHERE id = OLD.post_id;
            ELSIF OLD.comment_id IS NOT NULL THEN
                UPDATE post_comments 
                SET likes_count = GREATEST(0, likes_count - 1), updated_at = NOW()
                WHERE id = OLD.comment_id;
            END IF;
        END IF;
        
        RETURN OLD;
    END IF;
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for counter updates
CREATE TRIGGER trigger_update_comment_count
    AFTER INSERT OR DELETE ON post_comments
    FOR EACH ROW
    EXECUTE FUNCTION update_post_counters();

CREATE TRIGGER trigger_update_reaction_count
    AFTER INSERT OR DELETE ON post_reactions
    FOR EACH ROW
    EXECUTE FUNCTION update_post_counters();