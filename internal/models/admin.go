package models

import (
    "time"

    "github.com/google/uuid"
)

// request_type: GOVERNMENT, NGO
// status: PENDING, UNDER_REVIEW, APPROVED, REJECTED, MORE_INFO_REQUIRED
type CommunityVerificationRequest struct {
    ID                        uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    CommunityID               uuid.UUID  `gorm:"type:uuid;index;not null"`
    RequestedByUserID         uuid.UUID  `gorm:"type:uuid;index;not null"`
    RequestType               string     `gorm:"size:20;not null;index"`
    OrganizationName          string     `gorm:"type:text;not null"`
    RegistrationNumber        *string    `gorm:"type:text"`
    ContactPersonName         string     `gorm:"type:text;not null"`
    ContactPersonDesignation  *string    `gorm:"type:text"`
    ContactPhone              string     `gorm:"type:text;not null"`
    ContactEmail              *string    `gorm:"type:text"`
    AddressLine1              string     `gorm:"type:text;not null"`
    AddressLine2              *string    `gorm:"type:text"`
    City                      string     `gorm:"type:text;not null"`
    State                     string     `gorm:"type:text;not null"`
    Pincode                   string     `gorm:"type:text;not null"`
    Documents                 JSONMap    `gorm:"type:jsonb"` // array of doc objects
    SupportingInfo            JSONMap    `gorm:"type:jsonb"`
    Status                    string     `gorm:"size:30;default:'PENDING';index"`
    ReviewedByAdminID         *uuid.UUID `gorm:"type:uuid;index"`
    ReviewedAt                *time.Time
    AdminNotes                *string `gorm:"type:text"`
    RejectionReason           *string `gorm:"type:text"`
    AdditionalInfoRequested   *string `gorm:"type:text"`
    IsResubmission            bool    `gorm:"default:false;index"`
    OriginalRequestID         *uuid.UUID `gorm:"type:uuid;index"`
    ResubmissionCount         int        `gorm:"default:0"`

    CreatedAt time.Time `gorm:"not null"`
    UpdatedAt time.Time `gorm:"not null"`
}

// action_type: BLOCK, UNBLOCK, SUSPEND, UNSUSPEND, DELETE, VERIFY, REJECT_VERIFICATION
// severity: LOW, MEDIUM, HIGH, CRITICAL
type CommunityAdminAction struct {
    ID                  uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    CommunityID         uuid.UUID  `gorm:"type:uuid;index;not null"`
    AdminUserID         uuid.UUID  `gorm:"type:uuid;index;not null"`
    ActionType          string     `gorm:"size:30;not null;index"`
    Reason              string     `gorm:"type:text;not null"`
    Severity            string     `gorm:"size:10;default:'MEDIUM';index"`
    DurationDays        *int
    ExpiresAt           *time.Time `gorm:"index"`
    EvidenceAttachments JSONMap    `gorm:"type:jsonb"`
    InternalNotes       *string    `gorm:"type:text"`
    PublicReason        *string    `gorm:"type:text"`
    AffectedMembersCount int       `gorm:"default:0"`
    NotificationSent    bool       `gorm:"default:false"`
    IsReversed          bool       `gorm:"default:false;index"`
    ReversedByAdminID   *uuid.UUID `gorm:"type:uuid;index"`
    ReversedAt          *time.Time
    ReversalReason      *string    `gorm:"type:text"`

    CreatedAt time.Time `gorm:"not null"`
    UpdatedAt time.Time `gorm:"not null"`
}

// Generic admin audit log
type AdminAuditLog struct {
    ID           uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    AdminUserID  uuid.UUID  `gorm:"type:uuid;index;not null"`
    Action       string     `gorm:"type:text;not null"` // VERIFY_COMMUNITY, BLOCK_USER, etc.
    ResourceType string     `gorm:"type:text;not null"` // COMMUNITY, USER, REPORT, SYSTEM
    ResourceID   *uuid.UUID `gorm:"type:uuid;index"`
    IPAddress    *string    `gorm:"type:text"`
    UserAgent    *string    `gorm:"type:text"`
    SessionID    *string    `gorm:"type:text"`
    ActionData   JSONMap    `gorm:"type:jsonb"`
    Result       *string    `gorm:"type:text"` // SUCCESS, FAILED, PARTIAL
    ErrorMessage *string    `gorm:"type:text"`
    CreatedAt    time.Time  `gorm:"not null"`
}

// report_type: COMMUNITY_ABUSE, USER_ABUSE, CONTENT_VIOLATION, SECURITY_INCIDENT, SYSTEM_ISSUE
// status: OPEN, IN_PROGRESS, RESOLVED, CLOSED, DISMISSED
// severity: LOW, MEDIUM, HIGH, CRITICAL
type SystemReport struct {
    ID                  uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    ReportType          string     `gorm:"size:30;not null;index"`
    Title               string     `gorm:"type:text;not null"`
    Description         string     `gorm:"type:text;not null"`
    Severity            string     `gorm:"size:10;default:'MEDIUM';index"`
    Status              string     `gorm:"size:20;default:'OPEN';index"`
    ReportedCommunityID *uuid.UUID `gorm:"type:uuid;index"`
    ReportedUserID      *uuid.UUID `gorm:"type:uuid;index"`
    ReporterUserID      *uuid.UUID `gorm:"type:uuid;index"`
    Evidence            JSONMap    `gorm:"type:jsonb"`
    Tags                JSONMap    `gorm:"type:jsonb"`
    AssignedAdminID     *uuid.UUID `gorm:"type:uuid;index"`
    ResolvedByAdminID   *uuid.UUID `gorm:"type:uuid;index"`
    ResolvedAt          *time.Time
    ResolutionNotes     *string    `gorm:"type:text"`
    ActionTaken         *string    `gorm:"type:text"`

    CreatedAt time.Time `gorm:"not null"`
    UpdatedAt time.Time `gorm:"not null"`
}
