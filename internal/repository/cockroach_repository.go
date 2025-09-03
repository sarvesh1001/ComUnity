package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
	"strings"
	"github.com/ComUnity/auth-service/internal/client"
	"github.com/ComUnity/auth-service/internal/util/logger"
	"errors"
	"github.com/ComUnity/auth-service/internal/models"
	"github.com/google/uuid"
)

// CockroachRoleRepository implements RoleRepository for CockroachDB
type CockroachRoleRepository struct {
	db *sql.DB
}

// NewCockroachRoleRepository returns the RoleRepository interface
func NewCockroachRoleRepository(db *sql.DB) RoleRepository {
	return &CockroachRoleRepository{db: db}
}

func (r *CockroachRoleRepository) GetPermissionByName(ctx context.Context, name string) (*models.Permission, error) {
	var permission models.Permission
	query := `SELECT id, name, description, category, scope_type, is_deprecated, created_at, updated_at FROM permissions WHERE name = $1`
	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&permission.ID, &permission.Name, &permission.Description, &permission.Category,
		&permission.ScopeType, &permission.IsDeprecated, &permission.CreatedAt, &permission.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &permission, nil
}

func (r *CockroachRoleRepository) GetRoleByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	var role models.Role
	query := `SELECT id, name, description, community_type, is_custom, is_system_managed, created_by_id, community_id, created_at, updated_at FROM roles WHERE id = $1`
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&role.ID, &role.Name, &role.Description, &role.CommunityType, &role.IsCustom,
		&role.IsSystemManaged, &role.CreatedByID, &role.CommunityID, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (r *CockroachRoleRepository) CreateRole(ctx context.Context, role *models.Role, permissionIDs []uuid.UUID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	query := `INSERT INTO roles (name, description, community_type, is_custom, is_system_managed, created_by_id, community_id)
	          VALUES ($1, $2, $3, $4, $5, $6, $7) 
	          RETURNING id, created_at, updated_at`
	err = tx.QueryRowContext(ctx, query,
		role.Name, role.Description, role.CommunityType, role.IsCustom, role.IsSystemManaged,
		role.CreatedByID, role.CommunityID,
	).Scan(&role.ID, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		return err
	}

	for _, pid := range permissionIDs {
		_, err = tx.ExecContext(ctx,
			"INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
			role.ID, pid,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *CockroachRoleRepository) UpdateRole(ctx context.Context, role *models.Role) error {
	query := `UPDATE roles SET name = $1, description = $2, community_type = $3, is_custom = $4, is_system_managed = $5, updated_at = NOW() WHERE id = $6`
	_, err := r.db.ExecContext(ctx, query,
		role.Name, role.Description, role.CommunityType, role.IsCustom,
		role.IsSystemManaged, role.ID,
	)
	return err
}

func (r *CockroachRoleRepository) DeleteRole(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM roles WHERE id = $1", id)
	return err
}

func (r *CockroachRoleRepository) AssignRoleToUser(
	ctx context.Context,
	userID, roleID, communityID, assignedBy uuid.UUID,
	subScopeID *uuid.UUID,
	expiresAt, notBefore *time.Time,
) error {
	query := `INSERT INTO user_roles (user_id, role_id, community_id, sub_scope_id, assigned_by, expires_at, not_before, status, assigned_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`
	_, err := r.db.ExecContext(ctx, query,
		userID, roleID, communityID, subScopeID, assignedBy, expiresAt, notBefore, "ACTIVE",
	)
	return err
}

func (r *CockroachRoleRepository) RemoveRoleFromUser(ctx context.Context, userID, roleID, communityID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2 AND community_id = $3",
		userID, roleID, communityID,
	)
	return err
}

func (r *CockroachRoleRepository) GetUserRoles(ctx context.Context, userID, communityID uuid.UUID) ([]models.Role, error) {
	query := `SELECT r.id, r.name, r.description, r.community_type, r.is_custom, r.is_system_managed, r.created_by_id, r.community_id, r.created_at, r.updated_at 
	          FROM roles r JOIN user_roles ur ON r.id = ur.role_id 
	          WHERE ur.user_id = $1 AND ur.community_id = $2 
	          AND ur.status = 'ACTIVE' 
	          AND (ur.expires_at IS NULL OR ur.expires_at > NOW()) 
	          AND (ur.not_before IS NULL OR ur.not_before <= NOW())`

	rows, err := r.db.QueryContext(ctx, query, userID, communityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []models.Role
	for rows.Next() {
		var role models.Role
		err := rows.Scan(
			&role.ID, &role.Name, &role.Description, &role.CommunityType, &role.IsCustom,
			&role.IsSystemManaged, &role.CreatedByID, &role.CommunityID, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

func (r *CockroachRoleRepository) GetUserRolesWithExpiry(ctx context.Context, userID, communityID uuid.UUID, now time.Time) ([]models.Role, error) {
	query := `SELECT r.id, r.name, r.description, r.community_type, r.is_custom, r.is_system_managed, r.created_by_id, r.community_id, r.created_at, r.updated_at 
	          FROM roles r JOIN user_roles ur ON r.id = ur.role_id 
	          WHERE ur.user_id = $1 AND ur.community_id = $2 
	          AND ur.status = 'ACTIVE' 
	          AND (ur.expires_at IS NULL OR ur.expires_at > $3) 
	          AND (ur.not_before IS NULL OR ur.not_before <= $3)`

	rows, err := r.db.QueryContext(ctx, query, userID, communityID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []models.Role
	for rows.Next() {
		var role models.Role
		err := rows.Scan(
			&role.ID, &role.Name, &role.Description, &role.CommunityType, &role.IsCustom,
			&role.IsSystemManaged, &role.CreatedByID, &role.CommunityID, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
		return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

func (r *CockroachRoleRepository) GetUserPermissions(ctx context.Context, userID, communityID uuid.UUID) ([]string, error) {
	query := `SELECT DISTINCT p.name 
	          FROM permissions p 
	          JOIN role_permissions rp ON p.id = rp.permission_id 
	          JOIN user_roles ur ON rp.role_id = ur.role_id 
	          WHERE ur.user_id = $1 AND ur.community_id = $2 
	          AND ur.status = 'ACTIVE' 
	          AND (ur.expires_at IS NULL OR ur.expires_at > NOW()) 
	          AND (ur.not_before IS NULL OR ur.not_before <= NOW())`

	rows, err := r.db.QueryContext(ctx, query, userID, communityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var permission string
		err := rows.Scan(&permission)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

func (r *CockroachRoleRepository) GetUserPermissionsWithContext(ctx context.Context, userID uuid.UUID, authzCtx *models.AuthzContext) ([]string, error) {
	permissions, err := r.GetUserPermissions(ctx, userID, authzCtx.CommunityID)
	if err != nil {
		return nil, err
	}
	return permissions, nil
}

func (r *CockroachRoleRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]string, error) {
	query := `SELECT p.name 
	          FROM permissions p 
	          JOIN role_permissions rp ON p.id = rp.permission_id 
	          WHERE rp.role_id = $1`

	rows, err := r.db.QueryContext(ctx, query, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var permission string
		err := rows.Scan(&permission)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

func (r *CockroachRoleRepository) GetAllPermissionsForCommunityType(ctx context.Context, communityType string) ([]string, error) {
	query := `SELECT DISTINCT p.name 
	          FROM permissions p 
	          JOIN role_permissions rp ON p.id = rp.permission_id 
	          JOIN roles r ON rp.role_id = r.id 
	          WHERE r.community_type = $1`

	rows, err := r.db.QueryContext(ctx, query, communityType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var permission string
		err := rows.Scan(&permission)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

func (r *CockroachRoleRepository) GetCommunityRoles(ctx context.Context, communityID uuid.UUID) ([]models.Role, error) {
	query := `SELECT id, name, description, community_type, is_custom, is_system_managed, created_by_id, community_id, created_at, updated_at 
	          FROM roles 
	          WHERE community_id = $1 OR community_id IS NULL`

	rows, err := r.db.QueryContext(ctx, query, communityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []models.Role
	for rows.Next() {
		var role models.Role
		err := rows.Scan(
			&role.ID, &role.Name, &role.Description, &role.CommunityType, &role.IsCustom,
			&role.IsSystemManaged, &role.CreatedByID, &role.CommunityID, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

func (r *CockroachRoleRepository) GetDelegationRules(ctx context.Context, granterRoleID uuid.UUID) ([]models.DelegationRule, error) {
	query := `SELECT id, granter_role_id, grantee_role_id, scope_constraint, max_duration, created_at, updated_at 
	          FROM delegation_rules 
	          WHERE granter_role_id = $1`

	rows, err := r.db.QueryContext(ctx, query, granterRoleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []models.DelegationRule
	for rows.Next() {
		var rule models.DelegationRule
		err := rows.Scan(
			&rule.ID, &rule.GranterRoleID, &rule.GranteeRoleID, &rule.ScopeConstraint,
			&rule.MaxDuration, &rule.CreatedAt, &rule.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

func (r *CockroachRoleRepository) CreateDelegationRule(ctx context.Context, rule *models.DelegationRule) error {
	query := `INSERT INTO delegation_rules (granter_role_id, grantee_role_id, scope_constraint, max_duration) 
	          VALUES ($1, $2, $3, $4) 
	          RETURNING id, created_at, updated_at`

	err := r.db.QueryRowContext(ctx, query,
		rule.GranterRoleID, rule.GranteeRoleID, rule.ScopeConstraint, rule.MaxDuration,
	).Scan(&rule.ID, &rule.CreatedAt, &rule.UpdatedAt)

	return err
}

// User blocking methods

func (r *CockroachRoleRepository) CreateUserBlock(ctx context.Context, block *models.UserBlock) error {
	query := `INSERT INTO user_blocks (blocker_user_id, blocked_user_id, community_id, reason, block_type, expires_at) 
	          VALUES ($1, $2, $3, $4, $5, $6) 
	          RETURNING id, created_at, updated_at`

	err := r.db.QueryRowContext(ctx, query,
		block.BlockerUserID, block.BlockedUserID, block.CommunityID, block.Reason,
		block.BlockType, block.ExpiresAt,
	).Scan(&block.ID, &block.CreatedAt, &block.UpdatedAt)

	return err
}

func (r *CockroachRoleRepository) RemoveUserBlock(ctx context.Context, blockID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM user_blocks WHERE id = $1", blockID)
	return err
}

func (r *CockroachRoleRepository) GetUserBlock(ctx context.Context, blockID uuid.UUID) (*models.UserBlock, error) {
	var block models.UserBlock
	query := `SELECT id, blocker_user_id, blocked_user_id, community_id, reason, block_type, expires_at, created_at, updated_at 
	          FROM user_blocks 
	          WHERE id = $1`

	err := r.db.QueryRowContext(ctx, query, blockID).Scan(
		&block.ID, &block.BlockerUserID, &block.BlockedUserID, &block.CommunityID,
		&block.Reason, &block.BlockType, &block.ExpiresAt, &block.CreatedAt, &block.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &block, nil
}

func (r *CockroachRoleRepository) GetGlobalUserBlock(ctx context.Context, userID uuid.UUID) (*models.UserBlock, error) {
	var block models.UserBlock
	query := `SELECT id, blocker_user_id, blocked_user_id, community_id, reason, block_type, expires_at, created_at, updated_at 
	          FROM user_blocks 
	          WHERE blocked_user_id = $1 
	          AND community_id IS NULL 
	          AND (expires_at IS NULL OR expires_at > NOW()) 
	          ORDER by created_at DESC 
	          LIMIT 1`

	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&block.ID, &block.BlockerUserID, &block.BlockedUserID, &block.CommunityID,
		&block.Reason, &block.BlockType, &block.ExpiresAt, &block.CreatedAt, &block.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &block, nil
}

func (r *CockroachRoleRepository) GetCommunityUserBlock(ctx context.Context, userID, communityID uuid.UUID) (*models.UserBlock, error) {
	var block models.UserBlock
	query := `SELECT id, blocker_user_id, blocked_user_id, community_id, reason, block_type, expires_at, created_at, updated_at 
	          FROM user_blocks 
	          WHERE blocked_user_id = $1 
	          AND community_id = $2 
	          AND (expires_at IS NULL OR expires_at > NOW()) 
	          ORDER by created_at DESC 
	          LIMIT 1`

	err := r.db.QueryRowContext(ctx, query, userID, communityID).Scan(
		&block.ID, &block.BlockerUserID, &block.BlockedUserID, &block.CommunityID,
		&block.Reason, &block.BlockType, &block.ExpiresAt, &block.CreatedAt, &block.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &block, nil
}

func (r *CockroachRoleRepository) GetUserBlocks(ctx context.Context, userID uuid.UUID) ([]models.UserBlock, error) {
	query := `SELECT id, blocker_user_id, blocked_user_id, community_id, reason, block_type, expires_at, created_at, updated_at 
	          FROM user_blocks 
	          WHERE blocked_user_id = $1 
	          ORDER by created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var blocks []models.UserBlock
	for rows.Next() {
		var block models.UserBlock
		err := rows.Scan(
			&block.ID, &block.BlockerUserID, &block.BlockedUserID, &block.CommunityID,
			&block.Reason, &block.BlockType, &block.ExpiresAt, &block.CreatedAt, &block.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}

	return blocks, nil
}

func (r *CockroachRoleRepository) GetBlocksByBlocker(ctx context.Context, blockerUserID uuid.UUID) ([]models.UserBlock, error) {
	query := `SELECT id, blocker_user_id, blocked_user_id, community_id, reason, block_type, expires_at, created_at, updated_at 
	          FROM user_blocks 
	          WHERE blocker_user_id = $1 
	          ORDER by created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, blockerUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var blocks []models.UserBlock
	for rows.Next() {
		var block models.UserBlock
		err := rows.Scan(
			&block.ID, &block.BlockerUserID, &block.BlockedUserID, &block.CommunityID,
			&block.Reason, &block.BlockType, &block.ExpiresAt, &block.CreatedAt, &block.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}

	return blocks, nil
}

// User reporting methods

func (r *CockroachRoleRepository) CreateUserReport(ctx context.Context, report *models.UserReport) error {
	query := `INSERT INTO user_reports (reporter_user_id, reported_user_id, community_id, content_id, content_type, reason, category, status) 
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
	          RETURNING id, created_at, updated_at`

	err := r.db.QueryRowContext(ctx, query,
		report.ReporterUserID, report.ReportedUserID, report.CommunityID, report.ContentID,
		report.ContentType, report.Reason, report.Category, report.Status,
	).Scan(&report.ID, &report.CreatedAt, &report.UpdatedAt)

	return err
}

func (r *CockroachRoleRepository) UpdateUserReport(ctx context.Context, reportID uuid.UUID, updates map[string]interface{}) error {
	query := "UPDATE user_reports SET "
	params := []interface{}{}
	i := 1

	for key, value := range updates {
		query += fmt.Sprintf("%s = $%d, ", key, i)
		params = append(params, value)
		i++
	}

	query += "updated_at = NOW() WHERE id = $" + fmt.Sprintf("%d", i)
	params = append(params, reportID)

	_, err := r.db.ExecContext(ctx, query, params...)
	return err
}

func (r *CockroachRoleRepository) GetUserReport(ctx context.Context, reportID uuid.UUID) (*models.UserReport, error) {
	var report models.UserReport
	query := `SELECT id, reporter_user_id, reported_user_id, community_id, content_id, content_type, reason, category, status, action_taken, reviewed_by, reviewed_at, created_at, updated_at 
	          FROM user_reports 
	          WHERE id = $1`

	err := r.db.QueryRowContext(ctx, query, reportID).Scan(
		&report.ID, &report.ReporterUserID, &report.ReportedUserID, &report.CommunityID, &report.ContentID,
		&report.ContentType, &report.Reason, &report.Category, &report.Status, &report.ActionTaken,
		&report.ReviewedBy, &report.ReviewedAt, &report.CreatedAt, &report.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &report, nil
}

func (r *CockroachRoleRepository) GetUserReports(ctx context.Context, reportedUserID uuid.UUID) ([]models.UserReport, error) {
	query := `SELECT id, reporter_user_id, reported_user_id, community_id, content_id, content_type, reason, category, status, action_taken, reviewed_by, reviewed_at, created_at, updated_at 
	          FROM user_reports 
	          WHERE reported_user_id = $1 
	          ORDER by created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, reportedUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []models.UserReport
	for rows.Next() {
		var report models.UserReport
		err := rows.Scan(
			&report.ID, &report.ReporterUserID, &report.ReportedUserID, &report.CommunityID, &report.ContentID,
			&report.ContentType, &report.Reason, &report.Category, &report.Status, &report.ActionTaken,
			&report.ReviewedBy, &report.ReviewedAt, &report.CreatedAt, &report.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}

	return reports, nil
}

func (r *CockroachRoleRepository) GetReportsByReporter(ctx context.Context, reporterUserID uuid.UUID) ([]models.UserReport, error) {
	query := `SELECT id, reporter_user_id, reported_user_id, community_id, content_id, content_type, reason, category, status, action_taken, reviewed_by, reviewed_at, created_at, updated_at 
	          FROM user_reports 
	          WHERE reporter_user_id = $1 
	          ORDER by created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, reporterUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []models.UserReport
	for rows.Next() {
		var report models.UserReport
		err := rows.Scan(
			&report.ID, &report.ReporterUserID, &report.ReportedUserID, &report.CommunityID, &report.ContentID,
			&report.ContentType, &report.Reason, &report.Category, &report.Status, &report.ActionTaken,
			&report.ReviewedBy, &report.ReviewedAt, &report.CreatedAt, &report.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}

	return reports, nil
}

func (r *CockroachRoleRepository) GetPendingReports(ctx context.Context, limit int) ([]models.UserReport, error) {
	query := `SELECT id, reporter_user_id, reported_user_id, community_id, content_id, content_type, reason, category, status, action_taken, reviewed_by, reviewed_at, created_at, updated_at 
	          FROM user_reports 
	          WHERE status = 'PENDING' 
	          ORDER by created_at DESC 
	          LIMIT $1`

	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

var reports []models.UserReport
	for rows.Next() {
		var report models.UserReport
		err := rows.Scan(
			&report.ID, &report.ReporterUserID, &report.ReportedUserID, &report.CommunityID, &report.ContentID,
			&report.ContentType, &report.Reason, &report.Category, &report.Status, &report.ActionTaken,
			&report.ReviewedBy, &report.ReviewedAt, &report.CreatedAt, &report.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}

	return reports, nil
}

func (r *CockroachRoleRepository) LogRoleAssignment(ctx context.Context, assignment *models.UserRole) error {
	// Implementation for audit logging (no-op placeholder to preserve behavior)
	return nil
}

func (r *CockroachRoleRepository) LogPermissionDecision(ctx context.Context, decision *PermissionDecision) error {
	// Implementation for audit logging (no-op placeholder to preserve behavior)
	return nil
}

// CockroachUserRepository implements UserRepository for CockroachDB
type CockroachUserRepository struct {
	db *sql.DB
}

func NewCockroachUserRepository(db *sql.DB) UserRepository {
	return &CockroachUserRepository{db: db}
}

func (r *CockroachUserRepository) GetByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	var user models.User
	query := `SELECT id, phone_number, username, phone_verified, setup_completed, public_visibility, primary_device_id, last_login_at, created_at, updated_at 
	          FROM users 
	          WHERE id = $1`

	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID, &user.PhoneNumber, &user.Username, &user.PhoneVerified, &user.SetupCompleted,
		&user.PublicVisibility, &user.PrimaryDeviceID, &user.LastLoginAt,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *CockroachUserRepository) GetByPhone(ctx context.Context, phoneNumber string) (*models.User, error) {
	var user models.User
	query := `SELECT id, phone_number, username, phone_verified, setup_completed, public_visibility, primary_device_id, last_login_at, created_at, updated_at 
	          FROM users 
	          WHERE phone_number = $1`

	err := r.db.QueryRowContext(ctx, query, phoneNumber).Scan(
		&user.ID, &user.PhoneNumber, &user.Username, &user.PhoneVerified, &user.SetupCompleted,
		&user.PublicVisibility, &user.PrimaryDeviceID, &user.LastLoginAt,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		logger.Errorf("GetByPhone DB error: %v, phone=%s", err, phoneNumber)
		return nil, err
	}
	return &user, nil
}		
		

func (r *CockroachUserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	query := `SELECT id, phone_number, username, phone_verified, setup_completed, public_visibility, primary_device_id, last_login_at, created_at, updated_at 
	          FROM users 
	          WHERE username = $1 AND public_visibility = true`

	err := r.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID, &user.PhoneNumber, &user.Username, &user.PhoneVerified, &user.SetupCompleted,
		&user.PublicVisibility, &user.PrimaryDeviceID, &user.LastLoginAt,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *CockroachUserRepository) CreateUser(ctx context.Context, user *models.User) error {
	query := `INSERT INTO users (phone_number, username, phone_verified, setup_completed, public_visibility, primary_device_id) 
	          VALUES ($1, $2, $3, $4, $5, $6) 
	          RETURNING id, created_at, updated_at`

	err := r.db.QueryRowContext(ctx, query,
		user.PhoneNumber, user.Username, user.PhoneVerified,
		user.SetupCompleted, user.PublicVisibility, user.PrimaryDeviceID,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	return err
}

func (r *CockroachUserRepository) UpdateUser(ctx context.Context, id uuid.UUID, updates map[string]interface{}) error {
	query := `UPDATE users SET phone_number = $1, username = $2, phone_verified = $3, setup_completed = $4, 
              public_visibility = $5, last_login_at = $6, primary_device_id = $7, updated_at = NOW() 
              WHERE id = $8`

	_, err := r.db.ExecContext(ctx, query,
		updates["phone_number"],     // $1
		updates["username"],         // $2
		updates["phone_verified"],   // $3
		updates["setup_completed"],  // $4
		updates["public_visibility"],// $5
		updates["last_login_at"],    // $6
		updates["primary_device_id"],// $7
		id,                          // $8
	)

	return err
}

// UpdateUserFields updates specific fields of a user
func (r *CockroachUserRepository) UpdateUserFields(ctx context.Context, userID uuid.UUID, updates map[string]interface{}) error {
    if len(updates) == 0 {
        return nil
    }

    // Start building the query
    query := "UPDATE users SET "
    setClauses := []string{}
    args := []interface{}{}
    argPos := 1

    // Add each field from the updates map
    for field, value := range updates {
        setClauses = append(setClauses, fmt.Sprintf("%s = $%d", field, argPos))
        args = append(args, value)
        argPos++
    }

    query += strings.Join(setClauses, ", ")
    query += fmt.Sprintf(" WHERE id = $%d", argPos)
    args = append(args, userID)

    _, err := r.db.ExecContext(ctx, query, args...)
    return err
}
// CockroachCommunityRepository implements CommunityRepository for CockroachDB
type CockroachCommunityRepository struct {
	db *sql.DB
}

func NewCockroachCommunityRepository(db *sql.DB) CommunityRepository {
	return &CockroachCommunityRepository{db: db}
}

func (r *CockroachCommunityRepository) GetByID(ctx context.Context, communityID uuid.UUID) (*models.Community, error) {
	var community models.Community
	query := `SELECT id, name, type, is_private, head_user_id, verification_status, payment_status, created_at, updated_at 
	          FROM communities 
	          WHERE id = $1`

	err := r.db.QueryRowContext(ctx, query, communityID).Scan(
		&community.ID, &community.Name, &community.Type, &community.IsPrivate, &community.HeadUserID,
		&community.VerificationStatus, &community.PaymentStatus, &community.CreatedAt, &community.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &community, nil
}

func (r *CockroachCommunityRepository) CreateCommunity(ctx context.Context, community *models.Community) error {
	query := `INSERT INTO communities (name, type, is_private, head_user_id, verification_status, payment_status) 
	          VALUES ($1, $2, $3, $4, $5, $6) 
	          RETURNING id, created_at, updated_at`

	err := r.db.QueryRowContext(ctx, query,
		community.Name, community.Type, community.IsPrivate, community.HeadUserID,
		community.VerificationStatus, community.PaymentStatus,
	).Scan(&community.ID, &community.CreatedAt, &community.UpdatedAt)

	return err
}

func (r *CockroachCommunityRepository) UpdateCommunity(ctx context.Context, community *models.Community) error {
	query := `UPDATE communities SET name = $1, type = $2, is_private = $3, head_user_id = $4, verification_status = $5, payment_status = $6, updated_at = NOW() 
	          WHERE id = $7`

	_, err := r.db.ExecContext(ctx, query,
		community.Name, community.Type, community.IsPrivate, community.HeadUserID,
		community.VerificationStatus, community.PaymentStatus, community.ID,
	)

	return err
}

func (r *CockroachCommunityRepository) GetCommunitiesByType(ctx context.Context, communityType string) ([]models.Community, error) {
	query := `SELECT id, name, type, is_private, head_user_id, verification_status, payment_status, created_at, updated_at 
	          FROM communities 
	          WHERE type = $1`

	rows, err := r.db.QueryContext(ctx, query, communityType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var communities []models.Community
	for rows.Next() {
		var community models.Community
		err := rows.Scan(
			&community.ID, &community.Name, &community.Type, &community.IsPrivate, &community.HeadUserID,
			&community.VerificationStatus, &community.PaymentStatus, &community.CreatedAt, &community.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		communities = append(communities, community)
	}

	return communities, nil
}

func (r *CockroachCommunityRepository) GetUserCommunities(ctx context.Context, userID uuid.UUID) ([]models.Community, error) {
	query := `SELECT c.id, c.name, c.type, c.is_private, c.head_user_id, c.verification_status, c.payment_status, c.created_at, c.updated_at 
	          FROM communities c 
	          JOIN user_roles ur ON c.id = ur.community_id 
	          WHERE ur.user_id = $1 AND ur.status = 'ACTIVE' 
	          GROUP BY c.id, c.name, c.type, c.is_private, c.head_user_id, c.verification_status, c.payment_status, c.created_at, c.updated_at`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var communities []models.Community
	for rows.Next() {
		var community models.Community
		err := rows.Scan(
			&community.ID, &community.Name, &community.Type, &community.IsPrivate, &community.HeadUserID,
			&community.VerificationStatus, &community.PaymentStatus, &community.CreatedAt, &community.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		communities = append(communities, community)
	}

	return communities, nil
}

// CockroachConsentRepository implements ConsentRepository for CockroachDB
type CockroachConsentRepository struct {
	db *sql.DB
}

func NewCockroachConsentRepository(db *sql.DB) ConsentRepository {
	return &CockroachConsentRepository{db: db}
}

func (r *CockroachConsentRepository) CreateConsent(ctx context.Context, consent *models.Consent) error {
	consent.ID = uuid.New()
	consent.CreatedAt = time.Now()
	consent.UpdatedAt = time.Now()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO consents (id, child_user_id, parent_user_id, status, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		consent.ID, consent.ChildUserID, consent.ParentUserID,
		consent.Status, consent.CreatedAt, consent.UpdatedAt,
	)
	return err
}

func (r *CockroachConsentRepository) GetConsentByChild(ctx context.Context, childID uuid.UUID) (*models.Consent, error) {
	var c models.Consent
	err := r.db.QueryRowContext(ctx,
		`SELECT id, child_user_id, parent_user_id, status, created_at, updated_at FROM consents WHERE child_user_id = $1`,
		childID,
	).Scan(&c.ID, &c.ChildUserID, &c.ParentUserID, &c.Status, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *CockroachConsentRepository) GetConsentByID(ctx context.Context, consentID uuid.UUID) (*models.Consent, error) {
	var c models.Consent
	err := r.db.QueryRowContext(ctx,
		`SELECT id, child_user_id, parent_user_id, status, created_at, updated_at FROM consents WHERE id = $1`,
		consentID,
	).Scan(&c.ID, &c.ChildUserID, &c.ParentUserID, &c.Status, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *CockroachConsentRepository) UpdateConsentStatus(ctx context.Context, consentID uuid.UUID, status string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE consents SET status=$1, updated_at=NOW() WHERE id = $2`,
		status, consentID,
	)
	return err
}

// CockroachSchoolRepository implements SchoolRepository for CockroachDB
type CockroachSchoolRepository struct {
	db *sql.DB
}

func NewCockroachSchoolRepository(db *sql.DB) SchoolRepository {
	return &CockroachSchoolRepository{db: db}
}

func (r *CockroachSchoolRepository) RegisterSchool(ctx context.Context, s *models.School) error {
	s.ID = uuid.New()
	s.CreatedAt = time.Now()
	s.UpdatedAt = time.Now()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO schools (id, name, paid, validated, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		s.ID, s.Name, s.Paid, s.Validated, s.CreatedAt, s.UpdatedAt,
	)
	return err
}

func (r *CockroachSchoolRepository) ValidateSchool(ctx context.Context, schoolID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `UPDATE schools SET validated=true, updated_at=NOW() WHERE id=$1`, schoolID)
	return err
}

func (r *CockroachSchoolRepository) GetSchoolByID(ctx context.Context, schoolID uuid.UUID) (*models.School, error) {
	var s models.School
	err := r.db.QueryRowContext(ctx,
		`SELECT id, name, paid, validated, created_at, updated_at FROM schools WHERE id = $1`,
		schoolID,
	).Scan(&s.ID, &s.Name, &s.Paid, &s.Validated, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// RedisCacheRepository uses your wrapped Redis client
type RedisCacheRepository struct {
	client *client.RedisClient
}

func NewRedisCacheRepository(cli *client.RedisClient) CacheRepository {
	return &RedisCacheRepository{client: cli}
}

func (r *RedisCacheRepository) Get(ctx context.Context, key string) (interface{}, bool) {
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		return nil, false
	}

	var result interface{}
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return nil, false
	}

	return result, true
}

func (r *RedisCacheRepository) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) {
	// Use the custom client's SetJSON method
	_ = r.client.SetJSON(ctx, key, value, ttl)
}

func (r *RedisCacheRepository) Delete(ctx context.Context, key string) {
	_ = r.client.Del(ctx, key).Err()
}

// GetAllUserRoles gets all active roles for a user across all communities
func (r *CockroachRoleRepository) GetAllUserRoles(ctx context.Context, userID uuid.UUID) ([]models.UserRole, error) {
	query := `SELECT id, user_id, role_id, community_id, sub_scope_id, assigned_by, granted_by_role_id, assigned_at, expires_at, not_before, status, metadata 
	          FROM user_roles 
	          WHERE user_id = $1 
	          AND status = 'ACTIVE' 
	          AND (expires_at IS NULL OR expires_at > NOW()) 
	          AND (not_before IS NULL OR not_before <= NOW()) 
	          ORDER BY assigned_at DESC`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user roles: %w", err)
	}
	defer rows.Close()

	var userRoles []models.UserRole
	for rows.Next() {
		var ur models.UserRole
		var metadataJSON sql.NullString

		err := rows.Scan(
			&ur.ID, &ur.UserID, &ur.RoleID, &ur.CommunityID, &ur.SubScopeID,
			&ur.AssignedBy, &ur.GrantedByRoleID, &ur.AssignedAt, &ur.ExpiresAt,
			&ur.NotBefore, &ur.Status, &metadataJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user role: %w", err)
		}

		if metadataJSON.Valid {
			var metadata models.JSONMap
			if err := json.Unmarshal([]byte(metadataJSON.String), &metadata); err == nil {
				ur.Metadata = metadata
			}
		}

		userRoles = append(userRoles, ur)
	}

	return userRoles, nil
}

// GetRoleWithPermissions gets a role with all its permissions (for JWT building)
func (r *CockroachRoleRepository) GetRoleWithPermissions(ctx context.Context, roleID uuid.UUID) (*models.Role, error) {
	query := `SELECT r.id, r.name, r.description, r.community_type, r.is_custom, r.is_system_managed, r.created_by_id, r.community_id, r.created_at, r.updated_at, 
	          p.id, p.name, p.description, p.category, p.scope_type, p.is_deprecated 
	          FROM roles r 
	          LEFT JOIN role_permissions rp ON r.id = rp.role_id 
	          LEFT JOIN permissions p ON rp.permission_id = p.id 
	          WHERE r.id = $1`

	rows, err := r.db.QueryContext(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to query role with permissions: %w", err)
	}
	defer rows.Close()

	var role *models.Role
	permissions := make(map[uuid.UUID]models.Permission)

	for rows.Next() {
		if role == nil {
			role = &models.Role{}
			var permID sql.NullString
			var permName, permDesc, permCat, permScope sql.NullString
			var permDeprecated sql.NullBool

			err := rows.Scan(
				&role.ID, &role.Name, &role.Description, &role.CommunityType,
				&role.IsCustom, &role.IsSystemManaged, &role.CreatedByID, &role.CommunityID,
				&role.CreatedAt, &role.UpdatedAt,
				&permID, &permName, &permDesc, &permCat, &permScope, &permDeprecated,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to scan role: %w", err)
			}

			if permID.Valid {
				pid, _ := uuid.Parse(permID.String)
				permissions[pid] = models.Permission{
					ID:           pid,
					Name:         permName.String,
					Description:  permDesc.String,
					Category:     permCat.String,
					ScopeType:    permScope.String,
					IsDeprecated: permDeprecated.Bool,
				}
			}
		} else {
			var permID sql.NullString
			var permName, permDesc, permCat, permScope sql.NullString
			var permDeprecated sql.NullBool

			var dummy1, dummy2, dummy3, dummy4, dummy5, dummy6, dummy7, dummy8, dummy9, dummy10 interface{}
			err := rows.Scan(
				&dummy1, &dummy2, &dummy3, &dummy4, &dummy5, &dummy6, &dummy7, &dummy8, &dummy9, &dummy10,
				&permID, &permName, &permDesc, &permCat, &permScope, &permDeprecated,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to scan permission: %w", err)
			}

			if permID.Valid {
				pid, _ := uuid.Parse(permID.String)
				permissions[pid] = models.Permission{
					ID:           pid,
					Name:         permName.String,
					Description:  permDesc.String,
					Category:     permCat.String,
					ScopeType:    permScope.String,
					IsDeprecated: permDeprecated.Bool,
				}
			}
		}
	}

	if role == nil {
		return nil, fmt.Errorf("role not found")
	}

	role.Permissions = make([]models.Permission, 0, len(permissions))
	for _, perm := range permissions {
		role.Permissions = append(role.Permissions, perm)
	}

	return role, nil
}