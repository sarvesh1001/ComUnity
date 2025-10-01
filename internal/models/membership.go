package models

import (
    "time"

    "github.com/google/uuid"
)

// role_in_community: OWNER, ADMIN, MODERATOR, MEMBER
// status: PENDING, ACTIVE, SUSPENDED, BANNED, LEFT
type CommunityMember struct {
    ID               uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    CommunityID      uuid.UUID  `gorm:"type:uuid;index;not null"`
    UserID           uuid.UUID  `gorm:"type:uuid;index;not null"`
    Status           string     `gorm:"size:20;default:'ACTIVE';index"`
    JoinedAt         time.Time  `gorm:"not null;index"`
    ApprovedAt       *time.Time
    ApprovedByUserID *uuid.UUID `gorm:"type:uuid;index"`

    RoleInCommunity string     `gorm:"size:20;default:'MEMBER';index"`
    RoleAssignedBy  *uuid.UUID `gorm:"type:uuid;index"`
    RoleAssignedAt  *time.Time

    JoinRequestedAt *time.Time
    JoinMessage     *string    `gorm:"type:text"`
    RejectionReason *string    `gorm:"type:text"`

    LastActivityAt     *time.Time `gorm:"index"`
    NotificationConfig JSONMap    `gorm:"type:jsonb"` // posts/events/mentions prefs

    CreatedAt time.Time `gorm:"not null"`
    UpdatedAt time.Time `gorm:"not null"`
}

// status: PENDING, APPROVED, REJECTED, CANCELLED
type CommunityJoinRequest struct {
    ID               uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    CommunityID      uuid.UUID  `gorm:"type:uuid;index;not null"`
    UserID           uuid.UUID  `gorm:"type:uuid;index;not null"`
    RequestMessage   *string    `gorm:"type:text"`
    Status           string     `gorm:"size:20;default:'PENDING';index"`
    ReviewedByUserID *uuid.UUID `gorm:"type:uuid;index"`
    ReviewedAt       *time.Time
    AdminResponse    *string `gorm:"type:text"`
    AutoApproved     bool    `gorm:"default:false;index"`

    CreatedAt time.Time `gorm:"not null"`
    UpdatedAt time.Time `gorm:"not null"`
}

// Invitations by phone or existing user
// status: PENDING, ACCEPTED, DECLINED, EXPIRED, CANCELLED
type CommunityInvitation struct {
    ID              uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    CommunityID     uuid.UUID  `gorm:"type:uuid;index;not null"`
    InviterUserID   uuid.UUID  `gorm:"type:uuid;index;not null"`
    InviteePhone    *string    `gorm:"size:20;index"`
    InviteeUserID   *uuid.UUID `gorm:"type:uuid;index"`
    Message         *string    `gorm:"type:text"`
    SuggestedRole   string     `gorm:"size:20;default:'MEMBER';index"` // ADMIN, MODERATOR, MEMBER
    Status          string     `gorm:"size:20;default:'PENDING';index"`
    ExpiresAt       time.Time  `gorm:"index"`
    RespondedAt     *time.Time
    ResponseMessage *string `gorm:"type:text"`

    CreatedAt time.Time `gorm:"not null"`
    UpdatedAt time.Time `gorm:"not null"`
}
