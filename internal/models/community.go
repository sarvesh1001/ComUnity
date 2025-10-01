package models

import (
    "time"

    "github.com/google/uuid"
)

type Community struct {
    ID          uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    Name        string    `gorm:"size:100;not null"`
    Description *string   `gorm:"type:text"`
    // Allowed: SCHOOL, COLLEGE, GOVERNMENT, NGO, BUSINESS, SOCIAL, OTHERS
    Type       string     `gorm:"size:20;not null;index"`
    IsPrivate  bool       `gorm:"default:false;index"`
    HeadUserID uuid.UUID  `gorm:"type:uuid;not null;index"`

    // Verification workflow
    VerificationStatus      string     `gorm:"size:20;default:'PENDING';index"` // PENDING, VERIFIED, REJECTED, NOT_REQUIRED
    VerificationRequestedAt *time.Time
    VerifiedAt              *time.Time
    VerifiedByAdminID       *uuid.UUID `gorm:"type:uuid;index"`
    VerificationDocuments   JSONMap    `gorm:"type:jsonb"`
    VerificationNotes       *string    `gorm:"type:text"`

    // Admin controls
    IsBlocked        bool       `gorm:"default:false;index"`
    BlockedAt        *time.Time
    BlockedByAdminID *uuid.UUID `gorm:"type:uuid;index"`
    BlockReason      *string    `gorm:"type:text"`

    // Community settings
    MemberLimit           *int
    AutoApproveMembers    bool `gorm:"default:true"`
    AllowMemberPosts      bool `gorm:"default:true"`
    AllowMemberInvites    bool `gorm:"default:false"`
    RequireApprovalToPost bool `gorm:"default:false"`

    // Optional location data
    LocationData JSONMap `gorm:"type:jsonb"`

    CreatedAt time.Time `gorm:"not null"`
    UpdatedAt time.Time `gorm:"not null"`
}
