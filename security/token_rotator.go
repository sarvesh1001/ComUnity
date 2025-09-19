package security

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "sync"
    "time"

    "github.com/google/uuid"
    "github.com/redis/go-redis/v9"

    "github.com/ComUnity/auth-service/internal/client"
    "github.com/ComUnity/auth-service/internal/models"
    "github.com/ComUnity/auth-service/internal/repository"
    "github.com/ComUnity/auth-service/internal/util"
    "github.com/ComUnity/auth-service/internal/util/logger"
    "github.com/ComUnity/auth-service/internal/middleware"
)

var (
    ErrRotationInProgress = errors.New("token rotation already in progress")
    ErrTokenNotFound      = errors.New("token not found for rotation")
    ErrRotationDisabled   = errors.New("token rotation is disabled")
)

// TokenRotationConfig holds configuration for automatic token rotation
type TokenRotationConfig struct {
    Enabled             bool          `yaml:"enabled"`
    RotationInterval    time.Duration `yaml:"rotation_interval"`
    GracePeriod        time.Duration `yaml:"grace_period"`
    MaxActiveTokens    int           `yaml:"max_active_tokens"`
    NotificationWebhook string        `yaml:"notification_webhook"`
    BatchSize          int           `yaml:"batch_size"`
    WorkerCount        int           `yaml:"worker_count"`
}

// ActiveTokenInfo represents metadata about an active token
type ActiveTokenInfo struct {
    TokenID         string               `json:"token_id"`
    UserID          uuid.UUID           `json:"user_id"`
    TokenType       util.TokenType      `json:"token_type"`
    DeviceKey       string              `json:"device_key"`
    SessionID       string              `json:"session_id"`
    IssuedAt        time.Time           `json:"issued_at"`
    ExpiresAt       time.Time           `json:"expires_at"`
    NextRotation    time.Time           `json:"next_rotation"`
    RotationCount   int                 `json:"rotation_count"`
    LastAccess      time.Time           `json:"last_access"`
    CommunityCount  int                 `json:"community_count"`
    IsRotated       bool                `json:"is_rotated"`
    Metadata        models.JSONMap      `json:"metadata"`
}

// TokenRotator handles automatic JWT token rotation for enhanced security
type TokenRotator struct {
    redis      *client.RedisClient
    jwtManager *util.JWTManager
    userRepo   repository.UserRepository
    roleRepo   repository.RoleRepository
    config     TokenRotationConfig
    
    // Rotation state
    mu           sync.RWMutex
    isRotating   bool
    rotationChan chan struct{}
    stopChan     chan struct{}
    
    // Statistics
    stats TokenRotationStats
}

// TokenRotationStats tracks rotation statistics
type TokenRotationStats struct {
    TotalRotations      uint64        `json:"total_rotations"`
    SuccessfulRotations uint64        `json:"successful_rotations"`
    FailedRotations     uint64        `json:"failed_rotations"`
    ActiveTokens        int           `json:"active_tokens"`
    LastRotation        *time.Time    `json:"last_rotation,omitempty"`
    AverageRotationTime time.Duration `json:"average_rotation_time"`
}

// NewTokenRotator creates a new token rotator with your Redis client and repositories
func NewTokenRotator(
    redis *client.RedisClient, 
    jwtManager *util.JWTManager, 
    userRepo repository.UserRepository,
    roleRepo repository.RoleRepository,
    config TokenRotationConfig) *TokenRotator {
    
    // Set defaults following your pattern
    if config.RotationInterval == 0 {
        config.RotationInterval = 6 * time.Hour // Rotate every 6 hours
    }
    if config.GracePeriod == 0 {
        config.GracePeriod = 30 * time.Minute // 30 minute grace period
    }
    if config.MaxActiveTokens == 0 {
        config.MaxActiveTokens = 1000 // Reasonable limit for memory
    }
    if config.BatchSize == 0 {
        config.BatchSize = 100 // Process 100 tokens per batch
    }
    if config.WorkerCount == 0 {
        config.WorkerCount = 5 // 5 concurrent workers
    }
    
    return &TokenRotator{
        redis:        redis,
        jwtManager:   jwtManager,
        userRepo:     userRepo,
        roleRepo:     roleRepo,
        config:       config,
        rotationChan: make(chan struct{}, 1),
        stopChan:     make(chan struct{}),
    }
}

// Start begins the token rotation service
func (tr *TokenRotator) Start(ctx context.Context) error {
    if !tr.config.Enabled {
        logger.Info("Token rotation is disabled")
        return nil
    }
    
    logger.Info("Starting token rotation service", 
        "interval", tr.config.RotationInterval,
        "grace_period", tr.config.GracePeriod,
        "batch_size", tr.config.BatchSize)
    
    ticker := time.NewTicker(tr.config.RotationInterval)
    defer ticker.Stop()
    
    // Initial cleanup of expired tokens
    go tr.cleanupExpiredTokens(ctx)
    
    for {
        select {
        case <-ctx.Done():
            logger.Info("Token rotation service stopped")
            return ctx.Err()
            
        case <-tr.stopChan:
            logger.Info("Token rotation service stopped via stop channel")
            return nil
            
        case <-ticker.C:
            if err := tr.performRotationCycle(ctx); err != nil {
                logger.Error("Token rotation cycle failed", "error", err)
            }
            
        case <-tr.rotationChan:
            if err := tr.performRotationCycle(ctx); err != nil {
                logger.Error("Manual token rotation failed", "error", err)
            }
        }
    }
}

// Stop stops the token rotation service
func (tr *TokenRotator) Stop() {
    close(tr.stopChan)
}

// TriggerRotation manually triggers token rotation
func (tr *TokenRotator) TriggerRotation() {
    select {
    case tr.rotationChan <- struct{}{}:
        logger.Info("Manual token rotation triggered")
    default:
        logger.Warn("Token rotation already in progress")
    }
}

// RegisterToken registers a new active token for rotation tracking
func (tr *TokenRotator) RegisterToken(ctx context.Context, tokenID string, userID uuid.UUID, tokenType util.TokenType, deviceKey, sessionID string, expiresAt time.Time, communityCount int) error {
    now := time.Now()
    
    // Extract device fingerprint for additional security context
    var metadata models.JSONMap
    if fp, ok := middleware.FromContext(ctx); ok {
        metadata = models.JSONMap{
            "platform":     fp.Platform,
            "app_version":  fp.AppVersion,
            "ip_bucket":    fp.IPBucket,
            "observed_at":  fp.ObservedAt,
        }
    }
    
    tokenInfo := ActiveTokenInfo{
        TokenID:        tokenID,
        UserID:         userID,
        TokenType:      tokenType,
        DeviceKey:      deviceKey,
        SessionID:      sessionID,
        IssuedAt:       now,
        ExpiresAt:      expiresAt,
        NextRotation:   now.Add(tr.config.RotationInterval),
        RotationCount:  0,
        LastAccess:     now,
        CommunityCount: communityCount,
        IsRotated:      false,
        Metadata:       metadata,
    }
    
    // Store in Redis using your custom SetJSON
    key := fmt.Sprintf("token:active:%s", tokenID)
    if err := tr.redis.SetJSON(ctx, key, tokenInfo, expiresAt.Sub(now)+tr.config.GracePeriod); err != nil {
        return fmt.Errorf("failed to register token: %w", err)
    }
    
    // Add to user's token set for quick lookup
    userTokensKey := fmt.Sprintf("tokens:user:%s", userID.String())
    if err := tr.redis.SAdd(ctx, userTokensKey, tokenID).Err(); err != nil {
        logger.Warn("Failed to add token to user set", "user_id", userID, "error", err)
    }
    
    // Set expiry on user tokens set
    tr.redis.Expire(ctx, userTokensKey, 7*24*time.Hour) // 7 days
    
    logger.Debug("Token registered for rotation", 
        "token_id", tokenID,
        "user_id", userID,
        "token_type", tokenType,
        "next_rotation", tokenInfo.NextRotation)
    
    return nil
}

// UnregisterToken removes a token from rotation tracking
func (tr *TokenRotator) UnregisterToken(ctx context.Context, tokenID string, userID uuid.UUID) error {
    // Remove from active tokens
    key := fmt.Sprintf("token:active:%s", tokenID)
    if err := tr.redis.Del(ctx, key).Err(); err != nil {
        logger.Warn("Failed to unregister token", "token_id", tokenID, "error", err)
    }
    
    // Remove from user's token set
    userTokensKey := fmt.Sprintf("tokens:user:%s", userID.String())
    if err := tr.redis.SRem(ctx, userTokensKey, tokenID).Err(); err != nil {
        logger.Warn("Failed to remove token from user set", "user_id", userID, "error", err)
    }
    
    logger.Debug("Token unregistered from rotation", "token_id", tokenID, "user_id", userID)
    return nil
}

// UpdateTokenAccess updates the last access time for a token
func (tr *TokenRotator) UpdateTokenAccess(ctx context.Context, tokenID string) error {
    key := fmt.Sprintf("token:active:%s", tokenID)
    
    // Use Lua script for atomic update
    script := client.NewScript(`
        local key = KEYS[1]
        local now = ARGV[1]
        local token_data = redis.call('GET', key)
        if not token_data then
            return nil
        end
        local token = cjson.decode(token_data)
        token.last_access = now
        redis.call('SET', key, cjson.encode(token), 'KEEPTTL')
        return 'OK'
    `)
    
    return script.Run(ctx, tr.redis.Client, []string{key}, time.Now().Format(time.RFC3339)).Err()
}

// performRotationCycle executes a complete rotation cycle
func (tr *TokenRotator) performRotationCycle(ctx context.Context) error {
    tr.mu.Lock()
    if tr.isRotating {
        tr.mu.Unlock()
        return ErrRotationInProgress
    }
    tr.isRotating = true
    tr.mu.Unlock()
    
    defer func() {
        tr.mu.Lock()
        tr.isRotating = false
        now := time.Now()
        tr.stats.LastRotation = &now
        tr.mu.Unlock()
    }()
    
    logger.Info("Starting token rotation cycle")
    start := time.Now()
    
    // Get tokens due for rotation
    tokensDue, err := tr.getTokensDueForRotation(ctx)
    if err != nil {
        return fmt.Errorf("failed to get tokens for rotation: %w", err)
    }
    
    if len(tokensDue) == 0 {
        logger.Debug("No tokens due for rotation")
        return nil
    }
    
    logger.Info("Found tokens due for rotation", "count", len(tokensDue))
    
    // Process tokens in batches using workers
    results := tr.processTokensBatch(ctx, tokensDue)
    
    // Update statistics
    tr.updateRotationStats(results, time.Since(start))
    
    logger.Info("Token rotation cycle completed", 
        "duration", time.Since(start),
        "total", len(tokensDue),
        "successful", results.Successful,
        "failed", results.Failed)
    
    return nil
}

// BatchResult tracks batch processing results
type BatchResult struct {
    Successful int
    Failed     int
    Errors     []error
}

// processTokensBatch processes tokens in parallel batches
func (tr *TokenRotator) processTokensBatch(ctx context.Context, tokens []ActiveTokenInfo) BatchResult {
    results := BatchResult{
        Errors: make([]error, 0),
    }
    
    // Create worker pool
    tokenChan := make(chan ActiveTokenInfo, len(tokens))
    resultChan := make(chan error, len(tokens))
    
    // Start workers
    for i := 0; i < tr.config.WorkerCount; i++ {
        go tr.rotationWorker(ctx, tokenChan, resultChan)
    }
    
    // Send tokens to workers
    for _, token := range tokens {
        tokenChan <- token
    }
    close(tokenChan)
    
    // Collect results
    for i := 0; i < len(tokens); i++ {
        if err := <-resultChan; err != nil {
            results.Failed++
            results.Errors = append(results.Errors, err)
        } else {
            results.Successful++
        }
    }
    
    return results
}

// rotationWorker processes token rotation in parallel
func (tr *TokenRotator) rotationWorker(ctx context.Context, tokenChan <-chan ActiveTokenInfo, resultChan chan<- error) {
    for token := range tokenChan {
        err := tr.rotateToken(ctx, token)
        resultChan <- err
    }
}

// rotateToken rotates a specific token
func (tr *TokenRotator) rotateToken(ctx context.Context, tokenInfo ActiveTokenInfo) error {
    logger.Debug("Rotating token", 
        "token_id", tokenInfo.TokenID,
        "user_id", tokenInfo.UserID,
        "rotation_count", tokenInfo.RotationCount)
    
    // Skip refresh tokens - only rotate access tokens
    if tokenInfo.TokenType != util.AccessToken {
        return nil
    }
    
    // Get fresh user data and roles for new token using repositories
    user, err := tr.getUserByID(ctx, tokenInfo.UserID)
    if err != nil {
        return fmt.Errorf("failed to get user for rotation: %w", err)
    }
    
    userRoles, err := tr.getUserRoles(ctx, tokenInfo.UserID)
    if err != nil {
        return fmt.Errorf("failed to get user roles for rotation: %w", err)
    }
    
    // Create new access token
    newAccessToken, err := tr.jwtManager.CreateAccessToken(
        ctx, user, userRoles, tokenInfo.DeviceKey, tokenInfo.SessionID)
    if err != nil {
        return fmt.Errorf("failed to create new access token: %w", err)
    }
    
    // Parse new token to get its ID and expiry
    newClaims, err := tr.jwtManager.ValidateToken(newAccessToken)
    if err != nil {
        return fmt.Errorf("failed to validate new token: %w", err)
    }
    
    // Register the new token
    if err := tr.RegisterToken(ctx, newClaims.TokenID, tokenInfo.UserID, 
        util.AccessToken, tokenInfo.DeviceKey, tokenInfo.SessionID,
        newClaims.ExpiresAt.Time, len(newClaims.UserContext.CommunityRoles)); err != nil {
        return fmt.Errorf("failed to register new token: %w", err)
    }
    
    // Schedule old token revocation after grace period
    if err := tr.scheduleTokenRevocation(ctx, tokenInfo.TokenID, tokenInfo.UserID); err != nil {
        logger.Warn("Failed to schedule token revocation", 
            "token_id", tokenInfo.TokenID, "error", err)
    }
    
    // Store rotation notification for client
    if err := tr.storeRotationNotification(ctx, tokenInfo.UserID, tokenInfo.TokenID, newAccessToken); err != nil {
        logger.Warn("Failed to store rotation notification", 
            "user_id", tokenInfo.UserID, "error", err)
    }
    
    logger.Info("Token rotated successfully", 
        "old_token_id", tokenInfo.TokenID,
        "new_token_id", newClaims.TokenID,
        "user_id", tokenInfo.UserID)
    
    return nil
}

// getTokensDueForRotation finds tokens that need rotation
func (tr *TokenRotator) getTokensDueForRotation(ctx context.Context) ([]ActiveTokenInfo, error) {
    pattern := "token:active:*"
    keys, err := tr.redis.Keys(ctx, pattern).Result()
    if err != nil {
        return nil, fmt.Errorf("failed to get active token keys: %w", err)
    }
    
    now := time.Now()
    var tokensDue []ActiveTokenInfo
    
    // Process in batches to avoid memory issues
    for i := 0; i < len(keys); i += tr.config.BatchSize {
        end := i + tr.config.BatchSize
        if end > len(keys) {
            end = len(keys)
        }
        
        batch := keys[i:end]
        batchTokens, err := tr.processBatchForRotation(ctx, batch, now)
        if err != nil {
            logger.Error("Failed to process batch for rotation", "error", err)
            continue
        }
        
        tokensDue = append(tokensDue, batchTokens...)
        
        if len(tokensDue) >= tr.config.MaxActiveTokens {
            logger.Warn("Reached max active tokens limit, truncating rotation batch",
                "limit", tr.config.MaxActiveTokens)
            tokensDue = tokensDue[:tr.config.MaxActiveTokens]
            break
        }
    }
    
    return tokensDue, nil
}

// processBatchForRotation processes a batch of token keys (corrected implementation)
func (tr *TokenRotator) processBatchForRotation(ctx context.Context, keys []string, now time.Time) ([]ActiveTokenInfo, error) {
    if len(keys) == 0 {
        return nil, nil
    }
    
    var tokenInfos []ActiveTokenInfo
    
    // Use your Redis client's pipeline pattern for batch operations
    err := tr.redis.Pipeline(ctx, func(pipe redis.Pipeliner) error {
        // Get all tokens in one pipeline
        cmds := make([]*redis.StringCmd, len(keys))
        for i, key := range keys {
            cmds[i] = pipe.Get(ctx, key)
        }
        
        // Process results after pipeline execution
        _, err := pipe.Exec(ctx)
        if err != nil {
            return err
        }
        
        // Process each result
        for i, cmd := range cmds {
            val, err := cmd.Result()
            if err != nil {
                logger.Debug("Failed to get token info", "key", keys[i], "error", err)
                continue
            }
            
            var tokenInfo ActiveTokenInfo
            if err := json.Unmarshal([]byte(val), &tokenInfo); err != nil {
                logger.Debug("Failed to unmarshal token info", "key", keys[i], "error", err)
                continue
            }
            
            // Check if token is due for rotation
            if now.After(tokenInfo.NextRotation) && !tokenInfo.IsRotated {
                // Check if token hasn't expired
                if now.Before(tokenInfo.ExpiresAt) {
                    tokenInfos = append(tokenInfos, tokenInfo)
                }
            }
        }
        
        return nil
    })
    
    if err != nil {
        // Fallback to individual calls if pipeline fails
        logger.Warn("Pipeline failed, falling back to individual calls", "error", err)
        return tr.processBatchForRotationFallback(ctx, keys, now)
    }
    
    return tokenInfos, nil
}

// processBatchForRotationFallback processes tokens individually as fallback
func (tr *TokenRotator) processBatchForRotationFallback(ctx context.Context, keys []string, now time.Time) ([]ActiveTokenInfo, error) {
    var tokenInfos []ActiveTokenInfo
    
    for _, key := range keys {
        var tokenInfo ActiveTokenInfo
        if err := tr.redis.GetJSON(ctx, key, &tokenInfo); err != nil {
            logger.Debug("Failed to get token info", "key", key, "error", err)
            continue
        }
        
        // Check if token is due for rotation
        if now.After(tokenInfo.NextRotation) && !tokenInfo.IsRotated {
            // Check if token hasn't expired
            if now.Before(tokenInfo.ExpiresAt) {
                tokenInfos = append(tokenInfos, tokenInfo)
            }
        }
    }
    
    return tokenInfos, nil
}

// scheduleTokenRevocation schedules a token for revocation after grace period
func (tr *TokenRotator) scheduleTokenRevocation(ctx context.Context, tokenID string, userID uuid.UUID) error {
    revocationKey := fmt.Sprintf("token:revoke:%s", tokenID)
    revocationData := models.JSONMap{
        "token_id":    tokenID,
        "user_id":     userID.String(),
        "revoked_at":  time.Now().Add(tr.config.GracePeriod),
        "reason":      "rotation",
    }
    
    // Store revocation notice with grace period TTL
    return tr.redis.SetJSON(ctx, revocationKey, revocationData, tr.config.GracePeriod)
}

// storeRotationNotification stores notification for client about token rotation
func (tr *TokenRotator) storeRotationNotification(ctx context.Context, userID uuid.UUID, oldTokenID, newToken string) error {
    notificationKey := fmt.Sprintf("token:rotated:%s:%s", userID.String(), oldTokenID)
    notification := models.JSONMap{
        "old_token_id": oldTokenID,
        "new_token":    newToken,
        "rotated_at":   time.Now(),
        "expires_in":   int(tr.config.GracePeriod.Seconds()),
    }
    
    // Store notification with grace period + buffer for client to retrieve
    return tr.redis.SetJSON(ctx, notificationKey, notification, tr.config.GracePeriod+time.Hour)
}

// GetRotationNotification retrieves rotation notification for a token
func (tr *TokenRotator) GetRotationNotification(ctx context.Context, userID uuid.UUID, tokenID string) (models.JSONMap, error) {
    notificationKey := fmt.Sprintf("token:rotated:%s:%s", userID.String(), tokenID)
    
    var notification models.JSONMap
    if err := tr.redis.GetJSON(ctx, notificationKey, &notification); err != nil {
        return nil, fmt.Errorf("rotation notification not found: %w", err)
    }
    
    // Delete notification after retrieval
    tr.redis.Del(ctx, notificationKey)
    
    return notification, nil
}

// cleanupExpiredTokens removes expired tokens from tracking
func (tr *TokenRotator) cleanupExpiredTokens(ctx context.Context) {
    ticker := time.NewTicker(1 * time.Hour) // Cleanup every hour
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            if err := tr.performCleanup(ctx); err != nil {
                logger.Error("Token cleanup failed", "error", err)
            }
        }
    }
}

// performCleanup removes expired tokens and updates statistics
func (tr *TokenRotator) performCleanup(ctx context.Context) error {
    pattern := "token:active:*"
    keys, err := tr.redis.Keys(ctx, pattern).Result()
    if err != nil {
        return fmt.Errorf("failed to get keys for cleanup: %w", err)
    }
    
    now := time.Now()
    cleanedCount := 0
    
    for _, key := range keys {
        var tokenInfo ActiveTokenInfo
        if err := tr.redis.GetJSON(ctx, key, &tokenInfo); err != nil {
            continue
        }
        
        // Remove expired tokens
        if now.After(tokenInfo.ExpiresAt.Add(tr.config.GracePeriod)) {
            if err := tr.redis.Del(ctx, key).Err(); err == nil {
                cleanedCount++
                
                // Also remove from user's token set
                userTokensKey := fmt.Sprintf("tokens:user:%s", tokenInfo.UserID.String())
                tr.redis.SRem(ctx, userTokensKey, tokenInfo.TokenID)
            }
        }
    }
    
    if cleanedCount > 0 {
        logger.Info("Cleaned up expired tokens", "count", cleanedCount)
    }
    
    return nil
}

// updateRotationStats updates rotation statistics
func (tr *TokenRotator) updateRotationStats(results BatchResult, duration time.Duration) {
    tr.mu.Lock()
    defer tr.mu.Unlock()
    
    tr.stats.TotalRotations++
    tr.stats.SuccessfulRotations += uint64(results.Successful)
    tr.stats.FailedRotations += uint64(results.Failed)
    
    // Update average rotation time (simple moving average)
    if tr.stats.TotalRotations == 1 {
        tr.stats.AverageRotationTime = duration
    } else {
        tr.stats.AverageRotationTime = (tr.stats.AverageRotationTime + duration) / 2
    }
}

// GetStats returns current rotation statistics
func (tr *TokenRotator) GetStats(ctx context.Context) TokenRotationStats {
    tr.mu.RLock()
    stats := tr.stats
    tr.mu.RUnlock()
    
    // Get current active token count
    pattern := "token:active:*"
    keys, _ := tr.redis.Keys(ctx, pattern).Result()
    stats.ActiveTokens = len(keys)
    
    return stats
}

// IsRotating returns whether rotation is currently in progress
func (tr *TokenRotator) IsRotating() bool {
    tr.mu.RLock()
    defer tr.mu.RUnlock()
    return tr.isRotating
}

// Repository integration methods
func (tr *TokenRotator) getUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
    user, err := tr.userRepo.GetByID(ctx, userID)
    if err != nil {
        return nil, fmt.Errorf("failed to get user by ID: %w", err)
    }
    return user, nil
}

func (tr *TokenRotator) getUserRoles(ctx context.Context, userID uuid.UUID) ([]models.UserRole, error) {
    userRoles, err := tr.roleRepo.GetAllUserRoles(ctx, userID)
    if err != nil {
        return nil, fmt.Errorf("failed to get user roles: %w", err)
    }
    return userRoles, nil
}

// IsTokenRevoked checks if a token has been revoked
func (tr *TokenRotator) IsTokenRevoked(ctx context.Context, tokenID string) bool {
    revocationKey := fmt.Sprintf("token:revoke:%s", tokenID)
    exists, err := tr.redis.Exists(ctx, revocationKey).Result()
    if err != nil {
        logger.Error("Failed to check token revocation", "token_id", tokenID, "error", err)
        return false
    }
    return exists > 0
}

// GetTokenInfo retrieves information about an active token
func (tr *TokenRotator) GetTokenInfo(ctx context.Context, tokenID string) (*ActiveTokenInfo, error) {
    key := fmt.Sprintf("token:active:%s", tokenID)
    var tokenInfo ActiveTokenInfo
    if err := tr.redis.GetJSON(ctx, key, &tokenInfo); err != nil {
        return nil, fmt.Errorf("token not found: %w", err)
    }
    return &tokenInfo, nil
}

// GetUserTokens returns all active tokens for a user
func (tr *TokenRotator) GetUserTokens(ctx context.Context, userID uuid.UUID) ([]string, error) {
    userTokensKey := fmt.Sprintf("tokens:user:%s", userID.String())
    tokenIDs, err := tr.redis.SMembers(ctx, userTokensKey).Result()
    if err != nil {
        return nil, fmt.Errorf("failed to get user tokens: %w", err)
    }
    return tokenIDs, nil
}

// RevokeUserToken immediately revokes a specific user token
func (tr *TokenRotator) RevokeUserToken(ctx context.Context, userID uuid.UUID, tokenID string) error {
    // Mark token as revoked immediately
    revocationKey := fmt.Sprintf("token:revoke:%s", tokenID)
    revocationData := models.JSONMap{
        "token_id":    tokenID,
        "user_id":     userID.String(),
        "revoked_at":  time.Now(),
        "reason":      "manual_revocation",
    }
    
    if err := tr.redis.SetJSON(ctx, revocationKey, revocationData, 24*time.Hour); err != nil {
        return fmt.Errorf("failed to revoke token: %w", err)
    }
    
    // Remove from active tokens
    return tr.UnregisterToken(ctx, tokenID, userID)
}
// RevokeToken immediately revokes a JWT token and associated session
func (tr *TokenRotator) RevokeToken(ctx context.Context, tokenID string) error {
    // Mark token as revoked immediately
    revocationKey := fmt.Sprintf("token:revoke:%s", tokenID)
    revocationData := models.JSONMap{
        "token_id":    tokenID,
        "revoked_at":  time.Now(),
        "reason":      "manual_revocation",
    }
    
    if err := tr.redis.SetJSON(ctx, revocationKey, revocationData, 24*time.Hour); err != nil {
        return fmt.Errorf("failed to revoke token: %w", err)
    }
    
    // Remove hybrid mapping
    hybridKey := fmt.Sprintf("hybrid_session:%s", tokenID)
    _ = tr.redis.Del(ctx, hybridKey).Err()
    
    // Remove from active tokens
    tokenKey := fmt.Sprintf("token:active:%s", tokenID)
    _ = tr.redis.Del(ctx, tokenKey).Err()
    
    logger.Info("Token revoked", "token_id", tokenID)
    return nil
}
