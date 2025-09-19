package handler

import (
    "encoding/json"
    "fmt"
    "net/http"

    "github.com/ComUnity/auth-service/internal/client"
    "github.com/ComUnity/auth-service/internal/util"
    "github.com/ComUnity/auth-service/internal/util/logger"
    "github.com/ComUnity/auth-service/security"
)

// SessionInfoHandler returns session info via JWT or encrypted cookie.
func SessionInfoHandler(sessionEncryptor *security.SessionEncryptor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // First try JWT claims
        if claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims); ok {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]interface{}{
                "user_id":    claims.UserContext.UserID,
                "token_id":   claims.TokenID,
                "expires_at": claims.ExpiresAt,
                "device_key": claims.DeviceFingerprint,
                "session_id": claims.SessionID,
            })
            return
        }

        // Fallback to encrypted session cookie
        sessionData, ok := security.GetSessionFromContext(r.Context())
        if !ok {
            http.Error(w, "No active session", http.StatusUnauthorized)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "session_id":     sessionData.SessionID,
            "user_id":        sessionData.UserID,
            "created_at":     sessionData.CreatedAt,
            "last_activity":  sessionData.LastActivity,
            "expires_at":     sessionData.ExpiresAt,
            "platform":       sessionData.Platform,
            "security_level": sessionData.SecurityLevel,
            "trust_score":    sessionData.TrustScore,
        })
    }
}

// SessionRefreshHandler refreshes both JWT and encrypted session in hybrid mode
func SessionRefreshHandler(sessionEncryptor *security.SessionEncryptor, jwtManager *util.JWTManager, redisClient *client.RedisClient) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Try JWT claims first for hybrid refresh
        if claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims); ok {
            // Get current session ID from hybrid mapping
            hybridKey := fmt.Sprintf("hybrid_session:%s", claims.TokenID)
            sessionID, err := redisClient.Get(r.Context(), hybridKey).Result()
            if err != nil {
                http.Error(w, "Session mapping not found", http.StatusUnauthorized)
                return
            }

            // Extend encrypted session expiry
            _, err = sessionEncryptor.RefreshSession(r.Context(), sessionID)
            if err != nil {
                http.Error(w, "Failed to refresh session", http.StatusInternalServerError)
                return
            }

            // Issue new JWT tokens
            refreshToken := r.Header.Get("X-Refresh-Token")
            if refreshToken == "" {
                http.Error(w, "Missing refresh token", http.StatusBadRequest)
                return
            }

            newAccessToken, err := jwtManager.RefreshAccessToken(r.Context(), refreshToken, claims.DeviceFingerprint)
            if err != nil {
                http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
                return
            }

            // Get new token ID from new access token
            newClaims, err := jwtManager.ValidateToken(newAccessToken)
            if err != nil {
                http.Error(w, "Failed to parse new token", http.StatusInternalServerError)
                return
            }

            // Update hybrid mapping with new token ID
            newHybridKey := fmt.Sprintf("hybrid_session:%s", newClaims.TokenID)
            _ = redisClient.Set(r.Context(), newHybridKey, sessionID, sessionEncryptor.Config().SessionDuration).Err()
            
            // Clean up old mapping
            _ = redisClient.Del(r.Context(), hybridKey).Err()

            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]interface{}{
                "access_token": newAccessToken,
                "token_type":   "Bearer",
                "expires_in":   900,
            })
            return
        }

        // Fallback to encrypted session cookie refresh (legacy path)
        sessionData, ok := security.GetSessionFromContext(r.Context())
        if !ok {
            http.Error(w, "No active session", http.StatusUnauthorized)
            return
        }

        refreshed, err := sessionEncryptor.RefreshSession(r.Context(), sessionData.SessionID)
        if err != nil {
            http.Error(w, "Failed to refresh session", http.StatusInternalServerError)
            return
        }

        http.SetCookie(w, sessionEncryptor.CreateSessionCookie(refreshed))
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "message":    "Session refreshed",
            "expires_at": refreshed.ExpiresAt,
        })
    }
}

// InvalidateSessionHandler invalidates the current hybrid session
func InvalidateSessionHandler(sessionEncryptor *security.SessionEncryptor, tokenRotator *security.TokenRotator, redisClient *client.RedisClient) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Try JWT claims first for hybrid logout
        if claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims); ok {
            // Get session ID from hybrid mapping
            hybridKey := fmt.Sprintf("hybrid_session:%s", claims.TokenID)
            sessionID, err := redisClient.Get(r.Context(), hybridKey).Result()
            if err != nil {
                logger.Warn("Session mapping not found during logout", "token_id", claims.TokenID)
            } else {
                // Invalidate encrypted session
                _ = sessionEncryptor.InvalidateSession(r.Context(), sessionID, claims.UserContext.UserID)
            }

            // Delete hybrid mapping
            _ = redisClient.Del(r.Context(), hybridKey).Err()
            
            // Revoke JWT token
            _ = tokenRotator.RevokeToken(r.Context(), claims.TokenID)

            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"message": "Session invalidated"})
            return
        }

        // Fallback to encrypted session logout (legacy)
        sessionData, ok := security.GetSessionFromContext(r.Context())
        if !ok {
            http.Error(w, "No active session", http.StatusUnauthorized)
            return
        }

        if err := sessionEncryptor.InvalidateSession(r.Context(), sessionData.SessionID, sessionData.UserID); err != nil {
            http.Error(w, "Failed to invalidate session", http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"message": "Session invalidated"})
    }
}

// InvalidateAllSessionsHandler invalidates all sessions for the authenticated user
func InvalidateAllSessionsHandler(sessionEncryptor *security.SessionEncryptor, tokenRotator *security.TokenRotator) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
        if !ok {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        userID := claims.UserContext.UserID

        // Get all user's active tokens for hybrid cleanup
        userTokens, err := tokenRotator.GetUserTokens(r.Context(), userID)
        if err != nil {
            logger.Warn("Failed to get user tokens for cleanup", "user_id", userID, "error", err)
        }

        // Revoke all JWT tokens and clean hybrid mappings
        for _, tokenID := range userTokens {
            // Revoke each token (this also cleans up hybrid mapping)
            _ = tokenRotator.RevokeToken(r.Context(), tokenID)
        }

        // Invalidate all encrypted sessions
        if err := sessionEncryptor.InvalidateAllUserSessions(r.Context(), userID); err != nil {
            http.Error(w, "Failed to invalidate all sessions", http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "message": "All sessions invalidated",
            "user_id": userID,
        })
    }
}
