package models

import (
	"time"
	
	"github.com/google/uuid"
)

// Permission represents a single action that can be performed
type Permission struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name        string    `gorm:"size:100;uniqueIndex;not null"`
	Description string    `gorm:"size:255"`
	Category    string    `gorm:"size:50;index"`
	ScopeType   string    `gorm:"size:20;default:'COMMUNITY'"` // GLOBAL, COMMUNITY, SUB_SCOPE, OBJECT_OWNER
	IsDeprecated bool     `gorm:"default:false"`
	CreatedAt   time.Time `gorm:"not null"`
	UpdatedAt   time.Time `gorm:"not null"`
}

// Role represents a collection of permissions
type Role struct {
	ID            uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name          string     `gorm:"size:100;index:idx_role_name_community,unique;not null"`
	Description   string     `gorm:"size:255"`
	CommunityType string     `gorm:"size:50;index:idx_role_name_community,unique"` // SCHOOL, SOCIETY, GOVERNMENT, PUBLIC, BUSINESS
	IsCustom      bool       `gorm:"default:false"`
	IsSystemManaged bool     `gorm:"default:false"`
	CreatedByID   uuid.UUID  `gorm:"type:uuid"`
	CommunityID   *uuid.UUID `gorm:"type:uuid;index"`
	Permissions   []Permission `gorm:"many2many:role_permissions;"`
	CreatedAt     time.Time  `gorm:"not null"`
	UpdatedAt     time.Time  `gorm:"not null"`
}

// UserRole represents a role assigned to a user in a specific context
type UserRole struct {
	ID          uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID      uuid.UUID  `gorm:"type:uuid;index:idx_user_community_role,unique"`
	RoleID      uuid.UUID  `gorm:"type:uuid;index"`
	CommunityID uuid.UUID  `gorm:"type:uuid;index:idx_user_community_role,unique"`
	SubScopeID  *uuid.UUID `gorm:"type:uuid;index"` // class_id, beat_id, block_id
	AssignedBy  uuid.UUID  `gorm:"type:uuid"`
	GrantedByRoleID *uuid.UUID `gorm:"type:uuid"` // Role that granted this assignment
	AssignedAt  time.Time  `gorm:"not null"`
	ExpiresAt   *time.Time `gorm:"index"`
	NotBefore   *time.Time `gorm:"index"`
	Status      string     `gorm:"size:20;default:'ACTIVE'"` // ACTIVE, EXPIRED, REVOKED, PENDING
	Metadata    JSONMap    `gorm:"type:jsonb"`
}

// DelegationRule defines which roles can grant which other roles
type DelegationRule struct {
	ID              uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	GranterRoleID   uuid.UUID `gorm:"type:uuid;index"`
	GranteeRoleID   uuid.UUID `gorm:"type:uuid;index"`
	ScopeConstraint string    `gorm:"size:50;default:'SAME_COMMUNITY'"` // SAME_COMMUNITY, SAME_SUBSCOPE, ANY
	MaxDuration     *time.Duration
	CreatedAt       time.Time `gorm:"not null"`
	UpdatedAt       time.Time `gorm:"not null"`
}

// UserBlock represents a block of a user either globally or in a specific community
type UserBlock struct {
	ID             uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	BlockerUserID  uuid.UUID  `gorm:"type:uuid;not null"` // who performed the block
	BlockedUserID  uuid.UUID  `gorm:"type:uuid;not null;index:idx_blocked_user"`
	CommunityID    *uuid.UUID `gorm:"type:uuid;index:idx_community_block"` // null for global block
	Reason         string     `gorm:"type:text"`
	BlockType      string     `gorm:"size:20;default:'FULL'"` // FULL, POST, MESSAGE, etc.
	ExpiresAt      *time.Time `gorm:"index"` // null for permanent block
	CreatedAt      time.Time  `gorm:"not null"`
	UpdatedAt      time.Time  `gorm:"not null"`
}

// UserReport represents a report against a user or content
type UserReport struct {
	ID             uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	ReporterUserID uuid.UUID  `gorm:"type:uuid;not null"`
	ReportedUserID uuid.UUID  `gorm:"type:uuid;not null;index"`
	CommunityID    *uuid.UUID `gorm:"type:uuid;index"` // null for platform-level reports
	ContentID      *uuid.UUID `gorm:"type:uuid;index"` // post, message, etc.
	ContentType    string     `gorm:"size:50"` // POST, MESSAGE, COMMENT, PROFILE
	Reason         string     `gorm:"type:text"`
	Category       string     `gorm:"size:50"` // SPAM, HARASSMENT, INAPPROPRIATE, etc.
	Status         string     `gorm:"size:20;default:'PENDING'"` // PENDING, REVIEWING, RESOLVED, DISMISSED
	ActionTaken    string     `gorm:"size:50"` // BLOCKED, WARNED, CONTENT_REMOVED, etc.
	ReviewedBy     *uuid.UUID `gorm:"type:uuid"`
	ReviewedAt     *time.Time
	CreatedAt      time.Time  `gorm:"not null"`
	UpdatedAt      time.Time  `gorm:"not null"`
}

// JSONMap is a simple type for JSON data
type JSONMap map[string]interface{}

// AuthzContext contains all authorization context information
type AuthzContext struct {
	CommunityID    uuid.UUID
	SubScopeID     *uuid.UUID
	ResourceID     *uuid.UUID
	ResourceOwnerID *uuid.UUID
	Attributes     map[string]interface{}
}

// Consent table: links a child and parent approval
type Consent struct {
	ID           uuid.UUID `db:"id"`
	ChildUserID  uuid.UUID `db:"child_user_id"`
	ParentUserID uuid.UUID `db:"parent_user_id"`
	Status       string    `db:"status"` // PENDING, APPROVED, REJECTED
	CreatedAt    time.Time `db:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"`
}

// School table
type School struct {
	ID        uuid.UUID `db:"id"`
	Name      string    `db:"name"`
	Paid      bool      `db:"paid"`
	Validated bool      `db:"validated"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

// User model
type User struct {
	ID                uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	PhoneNumber       string    `gorm:"size:15;uniqueIndex;not null"`
	Username          *string   `gorm:"size:50;uniqueIndex"`
	PhoneVerified     bool      `gorm:"default:false"`
	LastLoginAt       *time.Time `gorm:"index"` // Add this field

	SetupCompleted    bool      `gorm:"default:false"`
	FingerprintData   []byte    `gorm:"type:bytea"`
	PublicVisibility  bool      `gorm:"default:false"`
	CreatedAt         time.Time `gorm:"not null"`
	UpdatedAt         time.Time `gorm:"not null"`
}

// Community model
type Community struct {
	ID                 uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name               string    `gorm:"size:100;not null"`
	Type               string    `gorm:"size:50;not null"` // SCHOOL, SOCIETY, GOVERNMENT, PUBLIC, BUSINESS
	IsPrivate          bool      `gorm:"default:false"`
	HeadUserID         uuid.UUID `gorm:"type:uuid;not null"`
	VerificationStatus string    `gorm:"size:20;default:'PENDING'"` // PENDING, VERIFIED, REJECTED
	PaymentStatus      string    `gorm:"size:20;default:'UNPAID'"` // PAID, UNPAID, TRIAL
	CreatedAt          time.Time `gorm:"not null"`
	UpdatedAt          time.Time `gorm:"not null"`
}
