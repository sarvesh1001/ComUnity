package handler

import (
	"encoding/json"
	"net/http"

	"github.com/ComUnity/auth-service/internal/util"
	"github.com/ComUnity/auth-service/security"
)

// SessionRefreshHandler refreshes an encrypted session cookie.
func SessionRefreshHandler(sessionEncryptor *security.SessionEncryptor, jwtManager *util.JWTManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Try JWT claims first
		if claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims); ok {
			// Call your JWTManager to refresh tokens using the refresh token string and device fingerprint
			// You'll need to get the refresh token string from Authorization header or request body as per your API design
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

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": newAccessToken,
				"token_type":   "Bearer",
				"expires_in":   900, // or read from config
			})
			return
		}

		// Fallback to encrypted session cookie refresh
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

// InvalidateSessionHandler invalidates the current encrypted session.
func InvalidateSessionHandler(sessionEncryptor *security.SessionEncryptor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

// InvalidateAllSessionsHandler invalidates all sessions for the authenticated user.
func InvalidateAllSessionsHandler(sessionEncryptor *security.SessionEncryptor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if err := sessionEncryptor.InvalidateAllUserSessions(r.Context(), claims.UserContext.UserID); err != nil {
			http.Error(w, "Failed to invalidate all sessions", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "All sessions invalidated",
			"user_id": claims.UserContext.UserID,
		})
	}
}
