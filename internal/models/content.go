package models

import (
    "time"

    "github.com/google/uuid"
)

// post_type: POST, ANNOUNCEMENT, ALERT, EVENT, POLL
// status: DRAFT, PENDING, PUBLISHED, HIDDEN, REMOVED
// priority: LOW, NORMAL, HIGH, URGENT
type CommunityPost struct {
    ID               uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    CommunityID      uuid.UUID  `gorm:"type:uuid;index;not null"`
    AuthorUserID     uuid.UUID  `gorm:"type:uuid;index;not null"`
    Title            *string    `gorm:"type:text"`
    Content          string     `gorm:"type:text;not null"`
    PostType         string     `gorm:"size:20;default:'POST';index"`
    MediaAttachments JSONMap    `gorm:"type:jsonb"` // JSON array of attachments

    IsPinned        bool    `gorm:"default:false;index"`
    IsFeatured      bool    `gorm:"default:false;index"`
    AllowComments   bool    `gorm:"default:true"`
    RequireApproval bool    `gorm:"default:false"`
    Status          string  `gorm:"size:20;default:'PUBLISHED';index"`
    ModerationReason *string    `gorm:"type:text"`
    ModeratedByUserID *uuid.UUID `gorm:"type:uuid;index"`
    ModeratedAt       *time.Time

    LikesCount    int `gorm:"default:0;index"`
    CommentsCount int `gorm:"default:0;index"`
    SharesCount   int `gorm:"default:0;index"`
    ViewsCount    int `gorm:"default:0;index"`

    Priority string `gorm:"size:10;default:'NORMAL';index"`

    // Event-specific
    EventStartTime *time.Time `gorm:"index"`
    EventEndTime   *time.Time `gorm:"index"`
    EventLocation  *string    `gorm:"type:text"`
    MaxAttendees   *int

    CreatedAt time.Time `gorm:"not null"`
    UpdatedAt time.Time `gorm:"not null"`
}

// status: PUBLISHED, HIDDEN, REMOVED
type PostComment struct {
    ID               uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    PostID           uuid.UUID  `gorm:"type:uuid;index;not null"`
    AuthorUserID     uuid.UUID  `gorm:"type:uuid;index;not null"`
    ParentCommentID  *uuid.UUID `gorm:"type:uuid;index"`
    Content          string     `gorm:"type:text;not null"`
    MediaAttachments JSONMap    `gorm:"type:jsonb"`

    Status            string     `gorm:"size:20;default:'PUBLISHED';index"`
    ModeratedByUserID *uuid.UUID `gorm:"type:uuid;index"`
    ModeratedAt       *time.Time
    ModerationReason  *string `gorm:"type:text"`

    LikesCount   int `gorm:"default:0;index"`
    RepliesCount int `gorm:"default:0;index"`

    CreatedAt time.Time `gorm:"not null"`
    UpdatedAt time.Time `gorm:"not null"`
}

// One of PostID or CommentID must be set
type PostReaction struct {
    ID        uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    PostID    *uuid.UUID `gorm:"type:uuid;index"`
    CommentID *uuid.UUID `gorm:"type:uuid;index"`
    UserID    uuid.UUID  `gorm:"type:uuid;index;not null"`
    Reaction  string     `gorm:"size:10;default:'LIKE';index"` // LIKE, LOVE, LAUGH, ANGRY, SAD
    CreatedAt time.Time  `gorm:"not null"`
}

// RSVP for EVENT posts
// status: INTERESTED, GOING, NOT_GOING, MAYBE
type EventAttendee struct {
    ID          uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    EventPostID uuid.UUID `gorm:"type:uuid;index;not null"`
    UserID      uuid.UUID `gorm:"type:uuid;index;not null"`
    Status      string    `gorm:"size:20;default:'INTERESTED';index"`
    Message     *string   `gorm:"type:text"`

    CreatedAt time.Time `gorm:"not null"`
    UpdatedAt time.Time `gorm:"not null"`
}

// notification_type: ANNOUNCEMENT, ALERT, REMINDER, SYSTEM
// priority: LOW, NORMAL, HIGH, URGENT
type CommunityNotification struct {
    ID           uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    CommunityID  uuid.UUID  `gorm:"type:uuid;index;not null"`
    PostID       *uuid.UUID `gorm:"type:uuid;index"`
    SenderUserID uuid.UUID  `gorm:"type:uuid;index;not null"`
    Title        string     `gorm:"type:text;not null"`
    Message      string     `gorm:"type:text;not null"`
    Type         string     `gorm:"column:notification_type;size:20;default:'ANNOUNCEMENT';index"`
    Priority     string     `gorm:"size:10;default:'NORMAL';index"`

    TargetRole  *string `gorm:"size:20;index"`
    TargetUsers JSONMap `gorm:"type:jsonb"` // JSON array of user IDs

    TotalRecipients int `gorm:"default:0"`
    DeliveredCount  int `gorm:"default:0"`
    ReadCount       int `gorm:"default:0"`

    ScheduledAt *time.Time `gorm:"index"`
    SentAt      *time.Time `gorm:"index"`

    CreatedAt time.Time `gorm:"not null"`
    UpdatedAt time.Time `gorm:"not null"`
}

// Per-user delivery status for notifications
// status: PENDING, DELIVERED, READ, DISMISSED, FAILED
type UserNotificationStatus struct {
    ID               uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    NotificationID   uuid.UUID `gorm:"type:uuid;index;not null"`
    UserID           uuid.UUID `gorm:"type:uuid;index;not null"`
    Status           string    `gorm:"size:20;default:'PENDING';index"`
    DeliveredAt      *time.Time
    ReadAt           *time.Time
    DismissedAt      *time.Time
    DeliveryChannels JSONMap `gorm:"type:jsonb"` // ["in_app","push","sms","email"]

    CreatedAt time.Time `gorm:"not null"`
    UpdatedAt time.Time `gorm:"not null"`
}
