package repository

import (
	"context"
	"time"

	"github.com/ComUnity/auth-service/internal/models"

	"github.com/google/uuid"
)

// RoleRepository handles all RBAC-related database operations
type RoleRepository interface {
	// Basic CRUD operations
	GetPermissionByName(ctx context.Context, name string) (*models.Permission, error)
	GetRoleByID(ctx context.Context, id uuid.UUID) (*models.Role, error)
	CreateRole(ctx context.Context, role *models.Role, permissionIDs []uuid.UUID) error
	UpdateRole(ctx context.Context, role *models.Role) error
	DeleteRole(ctx context.Context, id uuid.UUID) error
	
	// User role assignments
	AssignRoleToUser(ctx context.Context, userID, roleID, communityID, assignedBy uuid.UUID, 
		subScopeID *uuid.UUID, expiresAt, notBefore *time.Time) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID, communityID uuid.UUID) error
	GetUserRoles(ctx context.Context, userID, communityID uuid.UUID) ([]models.Role, error)
	GetUserRolesWithExpiry(ctx context.Context, userID, communityID uuid.UUID, 
		now time.Time) ([]models.Role, error)
	
	// Permission queries
	GetUserPermissions(ctx context.Context, userID, communityID uuid.UUID) ([]string, error)
	GetUserPermissionsWithContext(ctx context.Context, userID uuid.UUID, 
		authzCtx *models.AuthzContext) ([]string, error)
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]string, error)
	GetAllPermissionsForCommunityType(ctx context.Context, communityType string) ([]string, error)
	
	// Community roles
	GetCommunityRoles(ctx context.Context, communityID uuid.UUID) ([]models.Role, error)
	GetAllUserRoles(ctx context.Context, userID uuid.UUID) ([]models.UserRole, error)
    GetRoleWithPermissions(ctx context.Context, roleID uuid.UUID) (*models.Role, error)
    
	// Delegation rules
	GetDelegationRules(ctx context.Context, granterRoleID uuid.UUID) ([]models.DelegationRule, error)
	CreateDelegationRule(ctx context.Context, rule *models.DelegationRule) error
	
	// User blocking
	CreateUserBlock(ctx context.Context, block *models.UserBlock) error
	RemoveUserBlock(ctx context.Context, blockID uuid.UUID) error
	GetUserBlock(ctx context.Context, blockID uuid.UUID) (*models.UserBlock, error)
	GetGlobalUserBlock(ctx context.Context, userID uuid.UUID) (*models.UserBlock, error)
	GetCommunityUserBlock(ctx context.Context, userID, communityID uuid.UUID) (*models.UserBlock, error)
	GetUserBlocks(ctx context.Context, userID uuid.UUID) ([]models.UserBlock, error)
	GetBlocksByBlocker(ctx context.Context, blockerUserID uuid.UUID) ([]models.UserBlock, error)
	
	// User reports
	CreateUserReport(ctx context.Context, report *models.UserReport) error
	UpdateUserReport(ctx context.Context, reportID uuid.UUID, updates map[string]interface{}) error
	GetUserReport(ctx context.Context, reportID uuid.UUID) (*models.UserReport, error)
	GetUserReports(ctx context.Context, reportedUserID uuid.UUID) ([]models.UserReport, error)
	GetReportsByReporter(ctx context.Context, reporterUserID uuid.UUID) ([]models.UserReport, error)
	GetPendingReports(ctx context.Context, limit int) ([]models.UserReport, error)
	
	// Audit logging
	LogRoleAssignment(ctx context.Context, assignment *models.UserRole) error
	LogPermissionDecision(ctx context.Context, decision *PermissionDecision) error
}

// UserRepository handles user-related database operations
type UserRepository interface {
	GetByID(ctx context.Context, userID uuid.UUID) (*models.User, error)
	GetByPhone(ctx context.Context, phoneNumber string) (*models.User, error)
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	CreateUser(ctx context.Context, user *models.User) error
    UpdateUser(ctx context.Context, userID uuid.UUID, updates map[string]interface{}) error
}

// CommunityRepository handles community-related database operations
type CommunityRepository interface {
	GetByID(ctx context.Context, communityID uuid.UUID) (*models.Community, error)
	CreateCommunity(ctx context.Context, community *models.Community) error
	UpdateCommunity(ctx context.Context, community *models.Community) error
	GetCommunitiesByType(ctx context.Context, communityType string) ([]models.Community, error)
	GetUserCommunities(ctx context.Context, userID uuid.UUID) ([]models.Community, error)
}

// ConsentRepository handles child consent operations
type ConsentRepository interface {
	CreateConsent(ctx context.Context, consent *models.Consent) error
	GetConsentByChild(ctx context.Context, childID uuid.UUID) (*models.Consent, error)
	GetConsentByID(ctx context.Context, consentID uuid.UUID) (*models.Consent, error)
	UpdateConsentStatus(ctx context.Context, consentID uuid.UUID, status string) error
}

// SchoolRepository handles school operations
type SchoolRepository interface {
	RegisterSchool(ctx context.Context, s *models.School) error
	ValidateSchool(ctx context.Context, schoolID uuid.UUID) error
	GetSchoolByID(ctx context.Context, schoolID uuid.UUID) (*models.School, error)
}

// CacheRepository handles caching operations
type CacheRepository interface {
	Get(ctx context.Context, key string) (interface{}, bool)
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration)
	Delete(ctx context.Context, key string)
}

// PermissionDecision represents a permission check decision for audit logging
type PermissionDecision struct {
	DecisionID    uuid.UUID
	Timestamp     time.Time
	UserID        uuid.UUID
	Permission    string
	CommunityID   uuid.UUID
	SubScopeID    *uuid.UUID
	ResourceID    *uuid.UUID
	Decision      bool
	Reason        string
	ProcessingTime time.Duration
	PolicyVersion string
	RequestID     string
}
