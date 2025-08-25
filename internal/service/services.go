package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ComUnity/auth-service/internal/models"
	"github.com/ComUnity/auth-service/internal/repository"

	"github.com/google/uuid"
)

// RoleService handles all RBAC business logic
type RoleService interface {
	HasPermission(ctx context.Context, userID uuid.UUID, permission string, 
		authzCtx *models.AuthzContext) (bool, error)
	AssignRole(ctx context.Context, userID, roleID uuid.UUID, authzCtx *models.AuthzContext, 
		assignedBy uuid.UUID, expiresAt, notBefore *time.Time) error
	CreateRole(ctx context.Context, role *models.Role, permissionNames []string, 
		createdBy uuid.UUID) error
	GetUserPermissions(ctx context.Context, userID uuid.UUID, 
		authzCtx *models.AuthzContext) ([]string, error)
	GetUserRoles(ctx context.Context, userID uuid.UUID, 
		authzCtx *models.AuthzContext) ([]models.Role, error)
	GetCommunityRoles(ctx context.Context, communityID uuid.UUID) ([]models.Role, error)
	RemoveRole(ctx context.Context, userID, roleID uuid.UUID, 
		authzCtx *models.AuthzContext, removedBy uuid.UUID) error
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]string, error)
	
	// User blocking methods
	BlockUser(ctx context.Context, blockerID, blockedID uuid.UUID, authzCtx *models.AuthzContext, 
		blockType, reason string, expiresAt *time.Time) error
	UnblockUser(ctx context.Context, unblockerID, blockID uuid.UUID) error
	GetUserBlocks(ctx context.Context, userID uuid.UUID) ([]models.UserBlock, error)
	IsUserBlocked(ctx context.Context, userID uuid.UUID, authzCtx *models.AuthzContext) (bool, error)
	
	// User report methods
	ReportUser(ctx context.Context, reporterID, reportedID uuid.UUID, authzCtx *models.AuthzContext, 
		contentID *uuid.UUID, contentType, reason, category string) error
	UpdateReportStatus(ctx context.Context, reportID uuid.UUID, updaterID uuid.UUID, 
		status, actionTaken string) error
	GetUserReports(ctx context.Context, userID uuid.UUID) ([]models.UserReport, error)
}

// EntitlementChecker handles license and verification checks
type EntitlementChecker interface {
	CheckLicense(ctx context.Context, communityID uuid.UUID, feature string) (bool, error)
	CheckVerification(ctx context.Context, userID uuid.UUID, level string) (bool, error)
}

// ConsentManager handles child consent workflow
type ConsentManager interface {
	RequestChildConsent(ctx context.Context, childID, parentID uuid.UUID) error
	ApproveConsent(ctx context.Context, parentID, consentID uuid.UUID) error
	CheckConsent(ctx context.Context, childID uuid.UUID) (bool, error)
}

// SchoolValidator handles school validation
type SchoolValidator interface {
	RegisterSchool(ctx context.Context, name string, paid bool) (*models.School, error)
	ValidateSchool(ctx context.Context, schoolID uuid.UUID) error
	IsSchoolValid(ctx context.Context, schoolID uuid.UUID) (bool, error)
}

// roleService implements RoleService
type roleService struct {
	roleRepo           repository.RoleRepository
	userRepo           repository.UserRepository
	communityRepo      repository.CommunityRepository
	cache              repository.CacheRepository
	entitlementChecker EntitlementChecker
	policyVersion      string
}

func NewRoleService(
	roleRepo repository.RoleRepository,
	userRepo repository.UserRepository,
	communityRepo repository.CommunityRepository,
	cache repository.CacheRepository,
	entitlementChecker EntitlementChecker,
	policyVersion string,
) RoleService {
	return &roleService{
		roleRepo:           roleRepo,
		userRepo:           userRepo,
		communityRepo:      communityRepo,
		cache:              cache,
		entitlementChecker: entitlementChecker,
		policyVersion:      policyVersion,
	}
}

func (s *roleService) HasPermission(ctx context.Context, userID uuid.UUID, 
	permission string, authzCtx *models.AuthzContext) (bool, error) {
	
	start := time.Now()
	decision := false
	reason := ""
	
	defer func() {
		s.logPermissionDecision(ctx, &repository.PermissionDecision{
			Timestamp:     start,
			UserID:        userID,
			Permission:    permission,
			CommunityID:   authzCtx.CommunityID,
			SubScopeID:    authzCtx.SubScopeID,
			ResourceID:    authzCtx.ResourceID,
			Decision:      decision,
			Reason:        reason,
			ProcessingTime: time.Since(start),
			PolicyVersion: s.policyVersion,
		})
	}()
	
	// Check if user is blocked
	isBlocked, err := s.IsUserBlocked(ctx, userID, authzCtx)
	if err != nil {
		reason = fmt.Sprintf("block check error: %v", err)
		return false, err
	}
	if isBlocked {
		reason = "user is blocked"
		return false, nil
	}
	
	// Check if user is community head (has all permissions)
	community, err := s.communityRepo.GetByID(ctx, authzCtx.CommunityID)
	if err != nil {
		reason = "community not found"
		return false, err
	}
	
	if community.HeadUserID == userID {
		decision = true
		reason = "user is community head"
		return true, nil
	}
	
	// Check cache first
	cacheKey := s.getPermissionCacheKey(userID, authzCtx)
	if cachedPerms, found := s.cache.Get(ctx, cacheKey); found {
		if perms, ok := cachedPerms.([]string); ok {
			for _, p := range perms {
				if p == permission {
					decision = true
					reason = "cached permission found"
					return true, nil
				}
			}
		}
		reason = "cached permission not found"
		return false, nil
	}
	
	// Get all user permissions for this context
	permissions, err := s.GetUserPermissions(ctx, userID, authzCtx)
	if err != nil {
		reason = fmt.Sprintf("error getting permissions: %v", err)
		return false, err
	}
	
	// Cache the permissions
	s.cache.Set(ctx, cacheKey, permissions, 5*time.Minute)
	
	// Check if permission exists
	for _, p := range permissions {
		if p == permission {
			// Check entitlements based on permission type
			entitled, err := s.checkEntitlements(ctx, userID, permission, authzCtx)
			if err != nil {
				reason = fmt.Sprintf("entitlement check failed: %v", err)
				return false, err
			}
			
			if entitled {
				decision = true
				reason = "permission granted with entitlements"
				return true, nil
			}
			
			reason = "entitlement check failed"
			return false, nil
		}
	}
	
	reason = "permission not found in user's roles"
	return false, nil
}

func (s *roleService) checkEntitlements(ctx context.Context, userID uuid.UUID, 
	permission string, authzCtx *models.AuthzContext) (bool, error) {
	
	// Check license for billing-related permissions
	if strings.HasPrefix(permission, "billing:") {
		hasLicense, err := s.entitlementChecker.CheckLicense(ctx, authzCtx.CommunityID, "billing_access")
		if err != nil || !hasLicense {
			return false, err
		}
	}
	
	// Check verification level for broadcast permissions
	if strings.HasPrefix(permission, "alert:broadcast:") {
		if strings.Contains(permission, "government") {
			isVerified, err := s.entitlementChecker.CheckVerification(ctx, userID, "government")
			if err != nil || !isVerified {
				return false, err
			}
		}
		if strings.Contains(permission, "school") {
			isVerified, err := s.entitlementChecker.CheckVerification(ctx, userID, "school")
			if err != nil || !isVerified {
				return false, err
			}
		}
	}
	
	return true, nil
}

func (s *roleService) AssignRole(ctx context.Context, userID, roleID uuid.UUID, 
	authzCtx *models.AuthzContext, assignedBy uuid.UUID, expiresAt, notBefore *time.Time) error {
	
	canAssign, err := s.HasPermission(ctx, assignedBy, "role:assign", authzCtx)
	if err != nil {
		return err
	}
	
	if !canAssign {
		return errors.New("user doesn't have permission to assign roles")
	}
	
	// Check delegation rules
	canGrant, err := s.checkDelegationRules(ctx, assignedBy, roleID, authzCtx)
	if err != nil {
		return err
	}
	
	if !canGrant {
		return errors.New("user cannot assign this role due to delegation rules")
	}
	
	// Check if user already has this role
	existingRoles, err := s.roleRepo.GetUserRoles(ctx, userID, authzCtx.CommunityID)
	if err != nil {
		return err
	}

	for _, existingRole := range existingRoles {
		if existingRole.ID == roleID {
			return errors.New("user already has this role in this context")
		}
	}
	
	// Assign the role
	err = s.roleRepo.AssignRoleToUser(ctx, userID, roleID, authzCtx.CommunityID, 
		assignedBy, authzCtx.SubScopeID, expiresAt, notBefore)
	if err != nil {
		return err
	}
	
	// Invalidate permission cache
	s.cache.Delete(ctx, s.getPermissionCacheKey(userID, authzCtx))
	
	return nil
}

func (s *roleService) checkDelegationRules(ctx context.Context, assignerID, 
	targetRoleID uuid.UUID, authzCtx *models.AuthzContext) (bool, error) {
	
	assignerRoles, err := s.roleRepo.GetUserRoles(ctx, assignerID, authzCtx.CommunityID)
	if err != nil {
		return false, err
	}
	
	for _, assignerRole := range assignerRoles {
		rules, err := s.roleRepo.GetDelegationRules(ctx, assignerRole.ID)
		if err != nil {
			continue
		}
		
		for _, rule := range rules {
			if rule.GranteeRoleID == targetRoleID {
				if s.checkScopeConstraint(rule.ScopeConstraint, assignerRole, authzCtx) {
					return true, nil
				}
			}
		}
	}
	
	return false, nil
}

func (s *roleService) checkScopeConstraint(constraint string, assignerRole models.Role, 
	authzCtx *models.AuthzContext) bool {
	
	switch constraint {
	case "SAME_COMMUNITY":
		return true
	case "SAME_SUBSCOPE":
		return true
	case "ANY":
		return true
	default:
		return false
	}
}

func (s *roleService) CreateRole(ctx context.Context, role *models.Role, 
	permissionNames []string, createdBy uuid.UUID) error {
	
	if role.CommunityID != nil {
		authzCtx := &models.AuthzContext{
			CommunityID: *role.CommunityID,
		}
		canCreate, err := s.HasPermission(ctx, createdBy, "role:create", authzCtx)
		if err != nil {
			return err
		}
		if !canCreate {
			return errors.New("user doesn't have permission to create roles")
		}
	}
	
	validPermissions, err := s.validatePermissionNames(ctx, permissionNames)
	if err != nil {
		return err
	}
	
	role.CreatedByID = createdBy
	err = s.roleRepo.CreateRole(ctx, role, validPermissions)
	if err != nil {
		return err
	}
	
	return nil
}

func (s *roleService) validatePermissionNames(ctx context.Context, permissionNames []string) ([]uuid.UUID, error) {
	var permissionIDs []uuid.UUID
	for _, name := range permissionNames {
		permission, err := s.roleRepo.GetPermissionByName(ctx, name)
		if err != nil {
			return nil, errors.New("invalid permission: " + name)
		}
		permissionIDs = append(permissionIDs, permission.ID)
	}
	return permissionIDs, nil
}

func (s *roleService) GetUserPermissions(ctx context.Context, userID uuid.UUID, 
	authzCtx *models.AuthzContext) ([]string, error) {
	
	return s.roleRepo.GetUserPermissionsWithContext(ctx, userID, authzCtx)
}

func (s *roleService) GetUserRoles(ctx context.Context, userID uuid.UUID, 
	authzCtx *models.AuthzContext) ([]models.Role, error) {
	
	now := time.Now()
	return s.roleRepo.GetUserRolesWithExpiry(ctx, userID, authzCtx.CommunityID, now)
}

func (s *roleService) GetCommunityRoles(ctx context.Context, communityID uuid.UUID) ([]models.Role, error) {
	return s.roleRepo.GetCommunityRoles(ctx, communityID)
}

func (s *roleService) RemoveRole(ctx context.Context, userID, roleID uuid.UUID, 
	authzCtx *models.AuthzContext, removedBy uuid.UUID) error {
	
	canRemove, err := s.HasPermission(ctx, removedBy, "role:remove", authzCtx)
	if err != nil {
		return err
	}
	
	if !canRemove {
		return errors.New("user doesn't have permission to remove roles")
	}
	
	err = s.roleRepo.RemoveRoleFromUser(ctx, userID, roleID, authzCtx.CommunityID)
	if err != nil {
		return err
	}
	
	s.cache.Delete(ctx, s.getPermissionCacheKey(userID, authzCtx))
	
	return nil
}

func (s *roleService) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]string, error) {
	return s.roleRepo.GetRolePermissions(ctx, roleID)
}

// User blocking methods
func (s *roleService) BlockUser(ctx context.Context, blockerID, blockedID uuid.UUID, 
	authzCtx *models.AuthzContext, blockType, reason string, expiresAt *time.Time) error {
	
	var permission string
	if authzCtx.CommunityID == uuid.Nil {
		permission = "user:block:global"
	} else {
		permission = "user:block:community"
	}
	
	canBlock, err := s.HasPermission(ctx, blockerID, permission, authzCtx)
	if err != nil {
		return err
	}
	
	if !canBlock {
		return errors.New("user doesn't have permission to block users")
	}
	
	if blockerID == blockedID {
		return errors.New("users cannot block themselves")
	}
	
	isBlocked, err := s.IsUserBlocked(ctx, blockedID, authzCtx)
	if err != nil {
		return err
	}
	
	if isBlocked {
		return errors.New("user is already blocked")
	}
	
	block := &models.UserBlock{
		BlockerUserID: blockerID,
		BlockedUserID: blockedID,
		CommunityID:   &authzCtx.CommunityID,
		Reason:        reason,
		BlockType:     blockType,
		ExpiresAt:     expiresAt,
	}
	
	if authzCtx.CommunityID == uuid.Nil {
		block.CommunityID = nil
	}
	
	err = s.roleRepo.CreateUserBlock(ctx, block)
	if err != nil {
		return err
	}
	
	s.cache.Delete(ctx, s.getPermissionCacheKey(blockedID, authzCtx))
	
	return nil
}

func (s *roleService) UnblockUser(ctx context.Context, unblockerID, blockID uuid.UUID) error {
	block, err := s.roleRepo.GetUserBlock(ctx, blockID)
	if err != nil {
		return err
	}
	
	var permission string
	authzCtx := &models.AuthzContext{}
	
	if block.CommunityID == nil {
		permission = "user:unblock:global"
	} else {
		permission = "user:unblock:community"
		authzCtx.CommunityID = *block.CommunityID
	}
	
	canUnblock, err := s.HasPermission(ctx, unblockerID, permission, authzCtx)
	if err != nil {
		return err
	}
	
	if !canUnblock {
		return errors.New("user doesn't have permission to unblock users")
	}
	
	err = s.roleRepo.RemoveUserBlock(ctx, blockID)
	if err != nil {
		return err
	}
	
	s.cache.Delete(ctx, s.getPermissionCacheKey(block.BlockedUserID, authzCtx))
	
	return nil
}

func (s *roleService) GetUserBlocks(ctx context.Context, userID uuid.UUID) ([]models.UserBlock, error) {
	return s.roleRepo.GetUserBlocks(ctx, userID)
}

func (s *roleService) IsUserBlocked(ctx context.Context, userID uuid.UUID, 
	authzCtx *models.AuthzContext) (bool, error) {
	
	// Check global blocks first
	globalBlock, err := s.roleRepo.GetGlobalUserBlock(ctx, userID)
	if err != nil {
		return false, err
	}
	
	if globalBlock != nil {
		if globalBlock.ExpiresAt != nil && globalBlock.ExpiresAt.Before(time.Now()) {
			err = s.roleRepo.RemoveUserBlock(ctx, globalBlock.ID)
			if err != nil {
				return false, err
			}
			return false, nil
		}
		return true, nil
	}
	
	// Check community blocks if community context is provided
	if authzCtx.CommunityID != uuid.Nil {
		communityBlock, err := s.roleRepo.GetCommunityUserBlock(ctx, userID, authzCtx.CommunityID)
		if err != nil {
			return false, err
		}
		
		if communityBlock != nil {
			if communityBlock.ExpiresAt != nil && communityBlock.ExpiresAt.Before(time.Now()) {
				err = s.roleRepo.RemoveUserBlock(ctx, communityBlock.ID)
				if err != nil {
					return false, err
				}
				return false, nil
			}
			return true, nil
		}
	}
	
	return false, nil
}

// User report methods
func (s *roleService) ReportUser(ctx context.Context, reporterID, reportedID uuid.UUID, 
	authzCtx *models.AuthzContext, contentID *uuid.UUID, contentType, reason, category string) error {
	
	canReport, err := s.HasPermission(ctx, reporterID, "user:report", authzCtx)
	if err != nil {
		return err
	}
	
	if !canReport {
		return errors.New("user doesn't have permission to report")
	}
	
	if reporterID == reportedID {
		return errors.New("users cannot report themselves")
	}
	
	report := &models.UserReport{
		ReporterUserID: reporterID,
		ReportedUserID: reportedID,
		CommunityID:    &authzCtx.CommunityID,
		ContentID:      contentID,
		ContentType:    contentType,
		Reason:         reason,
		Category:       category,
		Status:         "PENDING",
	}
	
	if authzCtx.CommunityID == uuid.Nil {
		report.CommunityID = nil
	}
	
	err = s.roleRepo.CreateUserReport(ctx, report)
	if err != nil {
		return err
	}
	
	return nil
}

func (s *roleService) UpdateReportStatus(ctx context.Context, reportID uuid.UUID, 
	updaterID uuid.UUID, status, actionTaken string) error {
	
	report, err := s.roleRepo.GetUserReport(ctx, reportID)
	if err != nil {
		return err
	}
	
	var permission string
	authzCtx := &models.AuthzContext{}
	
	if report.CommunityID == nil {
		permission = "report:moderate:global"
	} else {
		permission = "report:moderate:community"
		authzCtx.CommunityID = *report.CommunityID
	}
	
	canModerate, err := s.HasPermission(ctx, updaterID, permission, authzCtx)
	if err != nil {
		return err
	}
	
	if !canModerate {
		return errors.New("user doesn't have permission to moderate reports")
	}
	
	updates := map[string]interface{}{
		"status":       status,
		"action_taken": actionTaken,
		"reviewed_by":  updaterID,
		"reviewed_at":  time.Now(),
	}
	
	err = s.roleRepo.UpdateUserReport(ctx, reportID, updates)
	if err != nil {
		return err
	}
	
	return nil
}

func (s *roleService) GetUserReports(ctx context.Context, userID uuid.UUID) ([]models.UserReport, error) {
	return s.roleRepo.GetUserReports(ctx, userID)
}

func (s *roleService) getPermissionCacheKey(userID uuid.UUID, authzCtx *models.AuthzContext) string {
	key := "user_perms:" + userID.String() + ":" + authzCtx.CommunityID.String()
	
	if authzCtx.SubScopeID != nil {
		key += ":" + authzCtx.SubScopeID.String()
	}
	
	if authzCtx.ResourceID != nil {
		key += ":" + authzCtx.ResourceID.String()
	}
	
	key += ":v" + s.policyVersion
	
	return key
}

func (s *roleService) logPermissionDecision(ctx context.Context, decision *repository.PermissionDecision) {
	go s.roleRepo.LogPermissionDecision(ctx, decision)
}