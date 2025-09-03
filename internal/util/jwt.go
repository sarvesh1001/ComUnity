package util

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"

	"github.com/ComUnity/auth-service/internal/models"
	"github.com/ComUnity/auth-service/internal/repository"
	"github.com/ComUnity/auth-service/internal/util/logger"
)

// KMSKeyProvider is a minimal interface to obtain a signing key without importing security,
// preventing an import cycle. The concrete security.Helper passed from main must satisfy this.
type KMSKeyProvider interface {
	// GenerateDataKey should return a structure whose Plaintext field contains the raw key bytes.
	// The concrete type is not referenced here to avoid importing the security package.
	GenerateDataKey(ctx context.Context, keySpec string) (interface{ GetPlaintext() []byte }, error)
}

// TokenType represents different types of tokens
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
	IDToken      TokenType = "id"
)

// CommunityRole represents a role within a specific community
type CommunityRole struct {
	CommunityID   uuid.UUID  `json:"community_id"`
	CommunityType string     `json:"community_type"`
	RoleID        uuid.UUID  `json:"role_id"`
	RoleName      string     `json:"role_name"`
	SubScopeID    *uuid.UUID `json:"sub_scope_id,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Permissions   []string   `json:"permissions"`
}

// UserContext represents the user's complete authorization context
type UserContext struct {
	UserID            uuid.UUID       `json:"user_id"`
	PhoneNumber       string          `json:"phone_number"`
	Username          *string         `json:"username,omitempty"`
	PhoneVerified     bool            `json:"phone_verified"`
	SetupCompleted    bool            `json:"setup_completed"`
	PublicVisibility  bool            `json:"public_visibility"`
	CommunityRoles    []CommunityRole `json:"community_roles"`
	GlobalPermissions []string        `json:"global_permissions"`
}

// AuthzClaims represents JWT claims with RBAC information
type AuthzClaims struct {
	UserContext       UserContext `json:"user_context"`
	TokenType         TokenType   `json:"token_type"`
	TokenID           string      `json:"jti"`
	DeviceFingerprint string      `json:"device_fingerprint,omitempty"`
	SessionID         string      `json:"session_id,omitempty"`

	jwt.RegisteredClaims
}

// JWTConfig holds JWT configuration optimized for RBAC
type JWTConfig struct {
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	IDTokenDuration      time.Duration
	Issuer               string
	Audience             []string
	KMSKeyID             string
	MaxCommunityRoles    int
}

// JWTManager handles JWT operations with RBAC support
type JWTManager struct {
	config    JWTConfig
	kms       KMSKeyProvider
	userRepo  repository.UserRepository
	roleRepo  repository.RoleRepository
	cacheRepo repository.CacheRepository
}

// NewJWTManager creates a new JWT manager with RBAC support
func NewJWTManager(
	config JWTConfig,
	kms KMSKeyProvider,
	userRepo repository.UserRepository,
	roleRepo repository.RoleRepository,
	cacheRepo repository.CacheRepository,
) *JWTManager {
	if config.AccessTokenDuration == 0 {
		config.AccessTokenDuration = 15 * time.Minute
	}
	if config.RefreshTokenDuration == 0 {
		config.RefreshTokenDuration = 7 * 24 * time.Hour
	}
	if config.IDTokenDuration == 0 {
		config.IDTokenDuration = 1 * time.Hour
	}
	if config.MaxCommunityRoles == 0 {
		config.MaxCommunityRoles = 50
	}

	return &JWTManager{
		config:    config,
		kms:       kms,
		userRepo:  userRepo,
		roleRepo:  roleRepo,
		cacheRepo: cacheRepo,
	}
}

// CreateAccessToken creates an access token with user's complete RBAC context
func (j *JWTManager) CreateAccessToken(ctx context.Context, user *models.User, userRoles []models.UserRole, deviceFingerprint, sessionID string) (string, error) {
	now := time.Now()

	userContext, err := j.buildUserContext(ctx, user, userRoles)
	if err != nil {
		return "", fmt.Errorf("failed to build user context: %w", err)
	}

	tokenID, err := generateSecureTokenID()
	if err != nil {
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	expiresAt := now.Add(j.config.AccessTokenDuration)

	claims := AuthzClaims{
		UserContext:       *userContext,
		TokenType:         AccessToken,
		TokenID:           tokenID,
		DeviceFingerprint: deviceFingerprint,
		SessionID:         sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			Subject:   user.ID.String(),
			Audience:  jwt.ClaimStrings(j.config.Audience),
			Issuer:    j.config.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signingKey, err := j.getSigningKey(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	logger.Debug("Access token created",
		"user_id", user.ID,
		"community_roles", len(userContext.CommunityRoles),
		"expires_at", expiresAt)

	return tokenString, nil
}

// CreateRefreshToken creates a refresh token (simplified without full RBAC context)
func (j *JWTManager) CreateRefreshToken(ctx context.Context, userID uuid.UUID, deviceFingerprint string) (string, error) {
	now := time.Now()

	tokenID, err := generateSecureTokenID()
	if err != nil {
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	expiresAt := now.Add(j.config.RefreshTokenDuration)

	claims := AuthzClaims{
		UserContext: UserContext{
			UserID: userID,
		},
		TokenType:         RefreshToken,
		TokenID:           tokenID,
		DeviceFingerprint: deviceFingerprint,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings(j.config.Audience),
			Issuer:    j.config.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signingKey, err := j.getSigningKey(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	logger.Debug("Refresh token created", "user_id", userID, "expires_at", expiresAt)
	return tokenString, nil
}

// ValidateToken validates and parses a JWT token
func (j *JWTManager) ValidateToken(tokenString string) (*AuthzClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AuthzClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		signingKey, err := j.getSigningKey(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to get signing key: %w", err)
		}
		return signingKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := token.Claims.(*AuthzClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}
	if claims.TokenType == "" {
		return nil, errors.New("missing token type")
	}
	if time.Now().After(claims.ExpiresAt.Time) {
		return nil, errors.New("token expired")
	}
	return claims, nil
}

// buildUserContext constructs the complete user context with roles and permissions
func (j *JWTManager) buildUserContext(ctx context.Context, user *models.User, userRoles []models.UserRole) (*UserContext, error) {
	userContext := &UserContext{
		UserID:            user.ID,
		PhoneNumber:       user.PhoneNumber,
		Username:          user.Username,
		PhoneVerified:     user.PhoneVerified,
		SetupCompleted:    user.SetupCompleted,
		PublicVisibility:  user.PublicVisibility,
		CommunityRoles:    make([]CommunityRole, 0, len(userRoles)),
		GlobalPermissions: make([]string, 0),
	}

	processedRoles := 0
	for _, userRole := range userRoles {
		if processedRoles >= j.config.MaxCommunityRoles {
			logger.Warn("User has too many roles, truncating JWT",
				"user_id", user.ID,
				"total_roles", len(userRoles),
				"max_roles", j.config.MaxCommunityRoles)
			break
		}
		if userRole.ExpiresAt != nil && time.Now().After(*userRole.ExpiresAt) {
			continue
		}
		if userRole.Status != "ACTIVE" {
			continue
		}

		roleInfo, err := j.getRoleWithPermissions(ctx, userRole.RoleID)
		if err != nil {
			logger.Error("Failed to get role permissions", "role_id", userRole.RoleID, "error", err)
			continue
		}

		communityRole := CommunityRole{
			CommunityID:   userRole.CommunityID,
			CommunityType: roleInfo.CommunityType,
			RoleID:        userRole.RoleID,
			RoleName:      roleInfo.Name,
			SubScopeID:    userRole.SubScopeID,
			ExpiresAt:     userRole.ExpiresAt,
			Permissions:   make([]string, len(roleInfo.Permissions)),
		}

		for i, perm := range roleInfo.Permissions {
			communityRole.Permissions[i] = perm.Name
			if perm.ScopeType == "GLOBAL" {
				userContext.GlobalPermissions = append(userContext.GlobalPermissions, perm.Name)
			}
		}

		userContext.CommunityRoles = append(userContext.CommunityRoles, communityRole)
		processedRoles++
	}

	userContext.GlobalPermissions = removeDuplicateStrings(userContext.GlobalPermissions)
	return userContext, nil
}

func (j *JWTManager) getRoleWithPermissions(ctx context.Context, roleID uuid.UUID) (*models.Role, error) {
	cacheKey := fmt.Sprintf("role_with_perms:%s", roleID.String())
	if cached, found := j.cacheRepo.Get(ctx, cacheKey); found {
		if role, ok := cached.(*models.Role); ok {
			return role, nil
		}
	}
	role, err := j.roleRepo.GetRoleWithPermissions(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role with permissions: %w", err)
	}
	j.cacheRepo.Set(ctx, cacheKey, role, 10*time.Minute)
	return role, nil
}

// getSigningKey returns the JWT signing key using KMS (via the injected interface)
func (j *JWTManager) getSigningKey(ctx context.Context) ([]byte, error) {
	cacheKey := "jwt_signing_key"
	if cached, found := j.cacheRepo.Get(ctx, cacheKey); found {
		if key, ok := cached.([]byte); ok {
			return key, nil
		}
	}

	dk, err := j.kms.GenerateDataKey(ctx, "AES_256")
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}
	signingKey := dk.GetPlaintext()

	j.cacheRepo.Set(ctx, cacheKey, signingKey, 1*time.Hour)
	return signingKey, nil
}

// getUserByID - now implemented with your repository
func (j *JWTManager) getUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	return j.userRepo.GetByID(ctx, userID)
}

func (j *JWTManager) getUserRoles(ctx context.Context, userID uuid.UUID) ([]models.UserRole, error) {
	cacheKey := fmt.Sprintf("user_all_roles:%s", userID.String())
	if cached, found := j.cacheRepo.Get(ctx, cacheKey); found {
		if roles, ok := cached.([]models.UserRole); ok {
			return roles, nil
		}
	}
	roles, err := j.roleRepo.GetAllUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	j.cacheRepo.Set(ctx, cacheKey, roles, 5*time.Minute)
	return roles, nil
}

// RefreshAccessToken creates a new access token from a valid refresh token
func (j *JWTManager) RefreshAccessToken(ctx context.Context, refreshTokenString, deviceFingerprint string) (string, error) {
	claims, err := j.ValidateToken(refreshTokenString)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}
	if claims.TokenType != RefreshToken {
		return "", errors.New("not a refresh token")
	}
	if claims.DeviceFingerprint != deviceFingerprint {
		logger.Warn("Token refresh attempted with mismatched fingerprint",
			"user_id", claims.UserContext.UserID)
		return "", errors.New("invalid device fingerprint")
	}

	user, err := j.getUserByID(ctx, claims.UserContext.UserID)
	if err != nil {
		return "", fmt.Errorf("failed to get user: %w", err)
	}
	userRoles, err := j.getUserRoles(ctx, claims.UserContext.UserID)
	if err != nil {
		return "", fmt.Errorf("failed to get user roles: %w", err)
	}
	return j.CreateAccessToken(ctx, user, userRoles, deviceFingerprint, claims.SessionID)
}

// Helpers

func generateSecureTokenID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func removeDuplicateStrings(slice []string) []string {
	keys := make(map[string]bool)
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}

type TokenInfo struct {
	UserID          uuid.UUID `json:"user_id"`
	TokenType       TokenType `json:"token_type"`
	CommunityCount  int       `json:"community_count"`
	PermissionCount int       `json:"permission_count"`
	ExpiresAt       time.Time `json:"expires_at"`
	IssuedAt        time.Time `json:"issued_at"`
}

func (claims *AuthzClaims) GetTokenInfo() TokenInfo {
	totalPermissions := len(claims.UserContext.GlobalPermissions)
	for _, role := range claims.UserContext.CommunityRoles {
		totalPermissions += len(role.Permissions)
	}
	return TokenInfo{
		UserID:          claims.UserContext.UserID,
		TokenType:       claims.TokenType,
		CommunityCount:  len(claims.GetUserCommunities()),
		PermissionCount: totalPermissions,
		ExpiresAt:       claims.ExpiresAt.Time,
		IssuedAt:        claims.IssuedAt.Time,
	}
}

func (claims *AuthzClaims) HasPermission(permission string, authzContext *models.AuthzContext) bool {
	for _, perm := range claims.UserContext.GlobalPermissions {
		if perm == permission {
			return true
		}
	}
	if authzContext != nil && authzContext.CommunityID != uuid.Nil {
		for _, role := range claims.UserContext.CommunityRoles {
			if role.CommunityID == authzContext.CommunityID {
				if role.ExpiresAt != nil && time.Now().After(*role.ExpiresAt) {
					continue
				}
				if authzContext.SubScopeID != nil && role.SubScopeID != nil && *role.SubScopeID != *authzContext.SubScopeID {
					continue
				}
				for _, perm := range role.Permissions {
					if perm == permission {
						return true
					}
				}
			}
		}
	}
	return false
}

func (claims *AuthzClaims) HasRole(roleName string, communityID uuid.UUID) bool {
	for _, role := range claims.UserContext.CommunityRoles {
		if role.CommunityID == communityID && role.RoleName == roleName {
			if role.ExpiresAt != nil && time.Now().After(*role.ExpiresAt) {
				return false
			}
			return true
		}
	}
	return false
}

func (claims *AuthzClaims) GetUserCommunities() []uuid.UUID {
	communities := make([]uuid.UUID, 0, len(claims.UserContext.CommunityRoles))
	seen := make(map[uuid.UUID]bool)
	for _, role := range claims.UserContext.CommunityRoles {
		if !seen[role.CommunityID] {
			communities = append(communities, role.CommunityID)
			seen[role.CommunityID] = true
		}
	}
	return communities
}

// IssueTokens issues both access and refresh tokens + a sessionID
func (j *JWTManager) IssueTokens(
	ctx context.Context,
	authz *models.AuthzContext,
	deviceFingerprint string,
) (string, string, string, error) {
	// Get user from AuthzContext
	userID, ok := authz.Attributes["user_id"].(uuid.UUID)
	if !ok {
		return "", "", "", fmt.Errorf("invalid user_id type in authz context")
	}

	user, err := j.getUserByID(ctx, userID)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to load user: %w", err)
	}

	// Get roles
	userRoles, err := j.getUserRoles(ctx, user.ID)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to load roles: %w", err)
	}

	// Generate a new session ID
	sessionID := uuid.NewString()

	// Create access token
	accessToken, err := j.CreateAccessToken(ctx, user, userRoles, deviceFingerprint, sessionID)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create access token: %w", err)
	}

	// Create refresh token
	refreshToken, err := j.CreateRefreshToken(ctx, user.ID, deviceFingerprint)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create refresh token: %w", err)
	}

	return accessToken, refreshToken, sessionID, nil
}
