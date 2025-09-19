package security

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	
	"crypto/aes"
    "crypto/cipher"
    "time"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/ComUnity/auth-service/internal/client"
	"github.com/ComUnity/auth-service/internal/middleware"
	"github.com/ComUnity/auth-service/internal/models"
	"github.com/ComUnity/auth-service/internal/util/logger"
	"github.com/ComUnity/auth-service/internal/util"
)

// SessionData represents encrypted session information
type SessionData struct {
	SessionID     string         `json:"session_id"`
	UserID        uuid.UUID      `json:"user_id"`
	DeviceKey     string         `json:"device_key"`
	IPBucket      string         `json:"ip_bucket"`
	Platform      string         `json:"platform"`
	AppVersion    string         `json:"app_version"`
	CreatedAt     time.Time      `json:"created_at"`
	LastActivity  time.Time      `json:"last_activity"`
	ExpiresAt     time.Time      `json:"expires_at"`
	Data          models.JSONMap `json:"data"`
	SecurityLevel string         `json:"security_level"` // LOW, MEDIUM, HIGH
	TrustScore    int            `json:"trust_score"`    // 0-100
}

// EncryptedSession represents a session encrypted with KMS envelope encryption
type EncryptedSession struct {
	SessionID     string    `json:"session_id"`
	EncryptedData string    `json:"encrypted_data"` // Base64 encoded
	DataKeyB64    string    `json:"data_key"`       // KMS encrypted data key
	DeviceKey     string    `json:"device_key"`     // For validation
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Version       int       `json:"version"` // For schema evolution
}

// SessionEncryptorConfig holds encryption configuration
type SessionEncryptorConfig struct {
	Enabled            bool          `yaml:"enabled"`
	SessionDuration    time.Duration `yaml:"session_duration"`
	IdleTimeout        time.Duration `yaml:"idle_timeout"`
	ExtendOnActivity   bool          `yaml:"extend_on_activity"`
	MaxSessions        int           `yaml:"max_sessions_per_user"`
	RequireDeviceMatch bool          `yaml:"require_device_match"`
	CookieName         string        `yaml:"cookie_name"`
	CookieDomain       string        `yaml:"cookie_domain"`
	CookieSecure       bool          `yaml:"cookie_secure"`
	CookieHTTPOnly     bool          `yaml:"cookie_http_only"`
	CookieSameSite     string        `yaml:"cookie_same_site"`
	EncryptionVersion  int           `yaml:"encryption_version"`
	UseLocalKey        bool          `yaml:"use_local_key"`        // ← add this

}

// SessionEncryptor handles session encryption using your existing patterns
type SessionEncryptor struct {
	redis     *client.RedisClient
	kmsHelper Helper
	config    SessionEncryptorConfig
	envelope  cipher.AEAD   // ← add this field

}

// NewSessionEncryptor creates a new session encryptor following your service pattern
// In production, replace with real KMS envelope logic.
func newKmsEnvelope(_ Helper) cipher.AEAD {
    // Generate random AES-256 key
    key := make([]byte, 32)
    _, _ = rand.Read(key)
    block, _ := aes.NewCipher(key)
    aead, _ := cipher.NewGCM(block)
    return aead
}

func NewSessionEncryptor(
    redis *client.RedisClient,
    kmsHelper Helper,
    config SessionEncryptorConfig,
) *SessionEncryptor {
    // Set defaults
    if config.SessionDuration == 0 {
        config.SessionDuration = 24 * time.Hour
    }
    if config.IdleTimeout == 0 {
        config.IdleTimeout = 2 * time.Hour
    }
    if config.MaxSessions == 0 {
        config.MaxSessions = 10
    }
    if config.CookieName == "" {
        config.CookieName = "auth_session_encrypted"
    }
    if config.EncryptionVersion == 0 {
        config.EncryptionVersion = 1
    }

    // Select encryption envelope
    var envelope cipher.AEAD
    if config.UseLocalKey {
        // Local AES-GCM key for development
        key := make([]byte, 32)
        _, _ = rand.Read(key)
        block, _ := aes.NewCipher(key)
        envelope, _ = cipher.NewGCM(block)
    } else {
        // KMS-based envelope (existing implementation)
        envelope = newKmsEnvelope(kmsHelper)
    }

    return &SessionEncryptor{
        redis:     redis,
        kmsHelper: kmsHelper,
        config:    config,
        envelope:  envelope,   // ← assign envelope
    }
}
// CreateSession creates a new encrypted session with device fingerprinting
func (se *SessionEncryptor) CreateSession(ctx context.Context, userID uuid.UUID, additionalData models.JSONMap) (*EncryptedSession, error) {
	if !se.config.Enabled {
		return nil, fmt.Errorf("session encryption is disabled")
	}

	now := time.Now()
	sessionID := se.generateSessionID()

	// Extract device fingerprint from context (your middleware pattern)
	deviceKey := ""
	ipBucket := ""
	platform := ""
	appVersion := ""
	securityLevel := "LOW"
	trustScore := 50 // Default medium trust

	if fp, ok := middleware.FromContext(ctx); ok {
		deviceKey = fp.DeviceKey
		ipBucket = fp.IPBucket
		platform = fp.Platform
		appVersion = fp.AppVersion

		// Calculate security level based on device info
		securityLevel = se.calculateSecurityLevel(fp)
		trustScore = se.calculateTrustScore(fp)
	}

	// Create session data
	sessionData := SessionData{
		SessionID:     sessionID,
		UserID:        userID,
		DeviceKey:     deviceKey,
		IPBucket:      ipBucket,
		Platform:      platform,
		AppVersion:    appVersion,
		CreatedAt:     now,
		LastActivity:  now,
		ExpiresAt:     now.Add(se.config.SessionDuration),
		Data:          additionalData,
		SecurityLevel: securityLevel,
		TrustScore:    trustScore,
	}

	// Serialize session data
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Generate data key for envelope encryption (your KMS pattern)
	dataKey, err := se.kmsHelper.GenerateDataKey(ctx, "AES_256")
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}
	defer Wipe(dataKey.Plaintext) // Wipe plaintext key from memory

	// Encrypt session data with data key
	encryptedData, err := dataKey.Encrypt(sessionBytes, []byte("session_v"+fmt.Sprint(se.config.EncryptionVersion)))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt session data: %w", err)
	}

	encryptedSession := &EncryptedSession{
		SessionID:     sessionID,
		EncryptedData: base64.StdEncoding.EncodeToString(encryptedData),
		DataKeyB64:    dataKey.CiphertextB64,
		DeviceKey:     deviceKey,
		CreatedAt:     now,
		ExpiresAt:     sessionData.ExpiresAt,
		Version:       se.config.EncryptionVersion,
	}

	// Store encrypted session in Redis with your SetJSON pattern
	sessionKey := fmt.Sprintf("session:encrypted:%s", sessionID)
	if err := se.redis.SetJSON(ctx, sessionKey, encryptedSession, se.config.SessionDuration); err != nil {
		return nil, fmt.Errorf("failed to store encrypted session: %w", err)
	}

	// Manage user session limits
	if err := se.manageUserSessions(ctx, userID, sessionID); err != nil {
		logger.Warn("Failed to manage user sessions", "user_id", userID, "error", err)
	}

	logger.Info("Encrypted session created",
		"session_id", sessionID,
		"user_id", userID,
		"device_key", deviceKey,
		"security_level", securityLevel,
		"trust_score", trustScore)

	return encryptedSession, nil
}

// ValidateAndDecryptSession validates and decrypts a session
func (se *SessionEncryptor) ValidateAndDecryptSession(ctx context.Context, sessionID string, requireDeviceMatch bool) (*SessionData, error) {
	if !se.config.Enabled {
		return nil, fmt.Errorf("session encryption is disabled")
	}

	// Get encrypted session from Redis (revocation check → if not found, session revoked)
	sessionKey := fmt.Sprintf("session:encrypted:%s", sessionID)
	var encryptedSession EncryptedSession
	if err := se.redis.GetJSON(ctx, sessionKey, &encryptedSession); err != nil {
		return nil, fmt.Errorf("session not found or revoked: %w", err)
	}

	// Check hard expiry
	if time.Now().After(encryptedSession.ExpiresAt) {
		se.deleteSession(ctx, sessionID)
		return nil, fmt.Errorf("session expired")
	}

	// Decrypt data key using KMS
	plaintextKey, err := se.kmsHelper.DecryptDataKey(ctx, encryptedSession.DataKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %w", err)
	}
	defer Wipe(plaintextKey)

	dataKey := &DataKey{
		Plaintext:     plaintextKey,
		CiphertextB64: encryptedSession.DataKeyB64,
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedSession.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %w", err)
	}

	sessionBytes, err := dataKey.Decrypt(encryptedBytes, []byte("session_v"+fmt.Sprint(encryptedSession.Version)))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session data: %w", err)
	}

	var sessionData SessionData
	if err := json.Unmarshal(sessionBytes, &sessionData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	// 🔒 Device fingerprint enforcement
	if requireDeviceMatch || se.config.RequireDeviceMatch {
		if fp, ok := middleware.FromContext(ctx); ok {
			if fp.DeviceKey != sessionData.DeviceKey {
				logger.Warn("Session device mismatch",
					"session_id", sessionID,
					"expected_device", sessionData.DeviceKey,
					"actual_device", fp.DeviceKey)
				return nil, fmt.Errorf("device fingerprint mismatch")
			}
		}
	}

	// 🔒 Idle timeout
	if time.Since(sessionData.LastActivity) > se.config.IdleTimeout {
		logger.Info("Session idle timeout",
			"session_id", sessionID,
			"user_id", sessionData.UserID,
			"idle_duration", time.Since(sessionData.LastActivity))
		se.deleteSession(ctx, sessionID)
		return nil, fmt.Errorf("session idle timeout")
	}

	// 🔒 Platform binding
	if platform, ok := ctx.Value("request_platform").(string); ok && platform != "" {
		if !strings.EqualFold(sessionData.Platform, platform) {
			logger.Warn("Session platform mismatch",
				"session_id", sessionID,
				"expected_platform", sessionData.Platform,
				"actual_platform", platform)
			return nil, fmt.Errorf("platform mismatch")
		}
	}

	// Update last activity if enabled
	if se.config.ExtendOnActivity {
		sessionData.LastActivity = time.Now()
		if err := se.updateSessionActivity(ctx, sessionID, &sessionData); err != nil {
			logger.Warn("Failed to update session activity", "session_id", sessionID, "error", err)
		}
	}

	logger.Debug("Session validated successfully",
		"session_id", sessionID,
		"user_id", sessionData.UserID,
		"security_level", sessionData.SecurityLevel)

	return &sessionData, nil
}

// RefreshSession extends session expiry and updates activity
func (se *SessionEncryptor) RefreshSession(ctx context.Context, sessionID string) (*EncryptedSession, error) {
	sessionData, err := se.ValidateAndDecryptSession(ctx, sessionID, false)
	if err != nil {
		return nil, fmt.Errorf("failed to validate session for refresh: %w", err)
	}

	// Update timestamps
	now := time.Now()
	sessionData.LastActivity = now
	sessionData.ExpiresAt = now.Add(se.config.SessionDuration)

	// Re-encrypt with updated timestamps
	return se.reEncryptSession(ctx, sessionData)
}

// UpdateSessionData updates session data and re-encrypts
func (se *SessionEncryptor) UpdateSessionData(ctx context.Context, sessionID string, updates models.JSONMap) (*EncryptedSession, error) {
	sessionData, err := se.ValidateAndDecryptSession(ctx, sessionID, true)
	if err != nil {
		return nil, fmt.Errorf("failed to validate session for update: %w", err)
	}

	// Update session data
	if sessionData.Data == nil {
		sessionData.Data = make(models.JSONMap)
	}
	for key, value := range updates {
		sessionData.Data[key] = value
	}

	sessionData.LastActivity = time.Now()

	return se.reEncryptSession(ctx, sessionData)
}

// InvalidateSession invalidates and deletes a session
func (se *SessionEncryptor) InvalidateSession(ctx context.Context, sessionID string, userID uuid.UUID) error {
	logger.Info("Invalidating session", "session_id", sessionID, "user_id", userID)

	// Delete from Redis
	if err := se.deleteSession(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	// Remove from user's session set
	userSessionsKey := fmt.Sprintf("sessions:user:%s", userID.String())
	if err := se.redis.SRem(ctx, userSessionsKey, sessionID).Err(); err != nil {
		logger.Warn("Failed to remove session from user set", "user_id", userID, "error", err)
	}

	return nil
}

// InvalidateAllUserSessions invalidates all sessions for a user
func (se *SessionEncryptor) InvalidateAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	userSessionsKey := fmt.Sprintf("sessions:user:%s", userID.String())

	// Get all user sessions
	sessionIDs, err := se.redis.SMembers(ctx, userSessionsKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	// Delete all sessions
	for _, sessionID := range sessionIDs {
		if err := se.deleteSession(ctx, sessionID); err != nil {
			logger.Warn("Failed to delete session", "session_id", sessionID, "error", err)
		}
	}

	// Clear user session set
	se.redis.Del(ctx, userSessionsKey)

	logger.Info("All user sessions invalidated", "user_id", userID, "count", len(sessionIDs))
	return nil
}

// CreateSessionCookie creates a secure HTTP cookie with the encrypted session
func (se *SessionEncryptor) CreateSessionCookie(encryptedSession *EncryptedSession) *http.Cookie {
	// Create minimal cookie data (just session ID)
	cookieValue := encryptedSession.SessionID

	sameSite := http.SameSiteStrictMode
	switch se.config.CookieSameSite {
	case "lax":
		sameSite = http.SameSiteLaxMode
	case "none":
		sameSite = http.SameSiteNoneMode
	}

	return &http.Cookie{
		Name:     se.config.CookieName,
		Value:    cookieValue,
		Domain:   se.config.CookieDomain,
		Path:     "/",
		Expires:  encryptedSession.ExpiresAt,
		MaxAge:   int(time.Until(encryptedSession.ExpiresAt).Seconds()),
		Secure:   se.config.CookieSecure,
		HttpOnly: se.config.CookieHTTPOnly,
		SameSite: sameSite,
	}
}

// SessionMiddleware creates middleware for encrypted session handling
// Helper methods
// SessionMiddleware creates middleware for encrypted session handling
// SessionMiddleware validates Bearer token and attaches session data to context
// SessionMiddleware creates middleware for encrypted session handling (Bearer-only)
func (se *SessionEncryptor) SessionMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				next.ServeHTTP(w, r) // No session
				return
			}

			sessionID := strings.TrimSpace(authHeader[7:])
			if sessionID == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Validate and decrypt session
			sessionData, err := se.ValidateAndDecryptSession(r.Context(), sessionID, true)
			if err != nil {
				logger.Debug("Invalid session token", "error", err)
				next.ServeHTTP(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), "encrypted_session", sessionData)
			ctx = context.WithValue(ctx, "session_user_id", sessionData.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// generateSessionID creates a cryptographically secure session ID
func (se *SessionEncryptor) generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// calculateSecurityLevel determines security level based on device fingerprint
func (se *SessionEncryptor) calculateSecurityLevel(fp *middleware.DeviceFingerprint) string {
	// Implement your security level logic
	if fp.Platform == "web" {
		return "MEDIUM"
	}
	if fp.TelemetryIDHash != "" && fp.DeviceInstanceIDHash != "" {
		return "HIGH"
	}
	return "LOW"
}

// calculateTrustScore calculates trust score based on device fingerprint
func (se *SessionEncryptor) calculateTrustScore(fp *middleware.DeviceFingerprint) int {
	score := 30 // Base score

	if fp.TelemetryIDHash != "" {
		score += 25
	}
	if fp.DeviceInstanceIDHash != "" {
		score += 25
	}
	if fp.Platform != "unknown" {
		score += 10
	}
	if fp.AppVersion != "" {
		score += 10
	}

	if score > 100 {
		score = 100
	}

	return score
}

// manageUserSessions enforces session limits per user
func (se *SessionEncryptor) manageUserSessions(ctx context.Context, userID uuid.UUID, newSessionID string) error {
	userSessionsKey := fmt.Sprintf("sessions:user:%s", userID.String())

	// Add new session to user's set
	if err := se.redis.SAdd(ctx, userSessionsKey, newSessionID).Err(); err != nil {
		return fmt.Errorf("failed to add session to user set: %w", err)
	}

	// Check session count and remove oldest if needed
	sessionCount, err := se.redis.SCard(ctx, userSessionsKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get session count: %w", err)
	}

	if int(sessionCount) > se.config.MaxSessions {
		// Get all sessions with creation times
		sessionIDs, err := se.redis.SMembers(ctx, userSessionsKey).Result()
		if err != nil {
			return fmt.Errorf("failed to get user sessions: %w", err)
		}

		// Get session creation times and sort
		type sessionWithTime struct {
			ID        string
			CreatedAt time.Time
		}

		var sessions []sessionWithTime
		for _, sessionID := range sessionIDs {
			sessionKey := fmt.Sprintf("session:encrypted:%s", sessionID)
			var encSession EncryptedSession
			if err := se.redis.GetJSON(ctx, sessionKey, &encSession); err == nil {
				sessions = append(sessions, sessionWithTime{
					ID:        sessionID,
					CreatedAt: encSession.CreatedAt,
				})
			}
		}

		// Sort by creation time (oldest first)
		sort.Slice(sessions, func(i, j int) bool {
			return sessions[i].CreatedAt.Before(sessions[j].CreatedAt)
		})

		// Remove oldest sessions
		toRemove := len(sessions) - se.config.MaxSessions
		for i := 0; i < toRemove; i++ {
			if err := se.deleteSession(ctx, sessions[i].ID); err != nil {
				logger.Warn("Failed to delete old session", "session_id", sessions[i].ID, "error", err)
			}
			se.redis.SRem(ctx, userSessionsKey, sessions[i].ID)
		}

		logger.Info("Removed old sessions due to limit",
			"user_id", userID,
			"removed_count", toRemove,
			"limit", se.config.MaxSessions)
	}

	// Set expiry on user sessions set
	se.redis.Expire(ctx, userSessionsKey, se.config.SessionDuration)

	return nil
}

// reEncryptSession re-encrypts session data after updates
func (se *SessionEncryptor) reEncryptSession(ctx context.Context, sessionData *SessionData) (*EncryptedSession, error) {
	// Serialize updated session data
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated session data: %w", err)
	}

	// Generate new data key
	dataKey, err := se.kmsHelper.GenerateDataKey(ctx, "AES_256")
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}
	defer Wipe(dataKey.Plaintext)

	// Encrypt session data
	encryptedData, err := dataKey.Encrypt(sessionBytes, []byte("session_v"+fmt.Sprint(se.config.EncryptionVersion)))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt session data: %w", err)
	}

	encryptedSession := &EncryptedSession{
		SessionID:     sessionData.SessionID,
		EncryptedData: base64.StdEncoding.EncodeToString(encryptedData),
		DataKeyB64:    dataKey.CiphertextB64,
		DeviceKey:     sessionData.DeviceKey,
		CreatedAt:     sessionData.CreatedAt,
		ExpiresAt:     sessionData.ExpiresAt,
		Version:       se.config.EncryptionVersion,
	}

	// Update in Redis
	sessionKey := fmt.Sprintf("session:encrypted:%s", sessionData.SessionID)
	if err := se.redis.SetJSON(ctx, sessionKey, encryptedSession, time.Until(sessionData.ExpiresAt)); err != nil {
		return nil, fmt.Errorf("failed to update encrypted session: %w", err)
	}

	return encryptedSession, nil
}

// updateSessionActivity updates session activity without full re-encryption
// Use Redis pipeline for atomic update of session data
func (se *SessionEncryptor) updateSessionActivity(ctx context.Context, sessionID string, sessionData *SessionData) error {
	// Use Redis pipeline for atomic update of session data
	return se.redis.Pipeline(ctx, func(pipe redis.Pipeliner) error { // Remove the * and client.
		script := client.NewScript(`
                local key = KEYS[1]
                local last_activity = ARGV[1]
                local session_data = redis.call('GET', key)
                if not session_data then
                    return nil
                end
                -- Update would require full re-encryption, so we'll handle this differently
                -- For now, just touch the TTL
                redis.call('TOUCH', key)
                return 'OK'
            `)
		return script.Run(ctx, pipe, []string{fmt.Sprintf("session:encrypted:%s", sessionID)}, time.Now().Format(time.RFC3339)).Err()
	})
}

// deleteSession removes a session from Redis
func (se *SessionEncryptor) deleteSession(ctx context.Context, sessionID string) error {
	sessionKey := fmt.Sprintf("session:encrypted:%s", sessionID)
	return se.redis.Del(ctx, sessionKey).Err()
}

// GetSessionFromContext extracts session data from request context
func GetSessionFromContext(ctx context.Context) (*SessionData, bool) {
	session, ok := ctx.Value("encrypted_session").(*SessionData)
	return session, ok
}

// GetUserIDFromSession extracts user ID from session context
func GetUserIDFromSession(ctx context.Context) (uuid.UUID, bool) {
	userID, ok := ctx.Value("session_user_id").(uuid.UUID)
	return userID, ok
}

// Config returns the session encryptor configuration
func (se *SessionEncryptor) Config() SessionEncryptorConfig {
	return se.config
}

// HybridSessionMiddleware validates JWT token and loads corresponding encrypted session
func (se *SessionEncryptor) HybridSessionMiddleware(jwtManager *util.JWTManager) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
                next.ServeHTTP(w, r) // No Bearer token, continue
                return
            }

            tokenStr := strings.TrimSpace(authHeader[7:])
            if tokenStr == "" {
                next.ServeHTTP(w, r)
                return
            }

            // Validate JWT token
            claims, err := jwtManager.ValidateToken(tokenStr)
            if err != nil {
                logger.Debug("Invalid JWT token", "error", err)
                next.ServeHTTP(w, r)
                return
            }

            // Lookup session ID via hybrid mapping
            hybridKey := fmt.Sprintf("hybrid_session:%s", claims.TokenID)
            sessionID, err := se.redis.Get(r.Context(), hybridKey).Result()
            if err != nil {
                logger.Debug("Hybrid session mapping not found", "token_id", claims.TokenID, "error", err)
                next.ServeHTTP(w, r)
                return
            }

            // Validate and decrypt session
            sessionData, err := se.ValidateAndDecryptSession(r.Context(), sessionID, true)
            if err != nil {
                logger.Debug("Session validation failed", "session_id", sessionID, "error", err)
                next.ServeHTTP(w, r)
                return
            }

            // Attach both JWT claims and session data to context
            ctx := context.WithValue(r.Context(), "jwt_claims", claims)
            ctx = context.WithValue(ctx, "encrypted_session", sessionData)
            ctx = context.WithValue(ctx, "session_user_id", sessionData.UserID)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
