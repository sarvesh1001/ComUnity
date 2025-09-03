package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/ComUnity/auth-service/internal/client"
	"github.com/ComUnity/auth-service/internal/middleware"
	"github.com/ComUnity/auth-service/internal/models"
	"github.com/ComUnity/auth-service/internal/repository"
	"github.com/ComUnity/auth-service/internal/util"
	"github.com/ComUnity/auth-service/internal/util/logger"
	"github.com/ComUnity/auth-service/security"
)

type LoginHandler struct {
	jwtManager       *util.JWTManager
	userRepo         repository.UserRepository
	roleRepo         repository.RoleRepository
	deviceRepo       repository.DeviceRepository
	sessionEncryptor *security.SessionEncryptor
	tokenRotator     *security.TokenRotator
	redisClient      *client.RedisClient
}

type LoginRequest struct {
	Phone string `json:"phone"`
}

type LoginResponse struct {
	Status       string                  `json:"status"`
	Message      string                  `json:"message"`
	RequiresOTP  bool                    `json:"requires_otp,omitempty"`
	AccessToken  string                  `json:"access_token,omitempty"`
	RefreshToken string                  `json:"refresh_token,omitempty"`
	TokenType    string                  `json:"token_type,omitempty"`
	ExpiresIn    int                     `json:"expires_in,omitempty"`
	SessionID    string                  `json:"session_id,omitempty"`
	User         *map[string]interface{} `json:"user,omitempty"`
	DeviceInfo   *DeviceInfo             `json:"device_info,omitempty"`
}

type DeviceInfo struct {
	DeviceKey      string  `json:"device_key"`
	Platform       string  `json:"platform"`
	IsAutoDetected bool    `json:"is_auto_detected"`
	StabilityScore float64 `json:"stability_score"`
	TrustLevel     int     `json:"trust_level"`
	RiskScore      int     `json:"risk_score"`
	FirstSeen      bool    `json:"first_seen"`
}

func NewLoginHandler(
	jwtManager *util.JWTManager,
	userRepo repository.UserRepository,
	roleRepo repository.RoleRepository,
	deviceRepo repository.DeviceRepository,
	sessionEncryptor *security.SessionEncryptor,
	tokenRotator *security.TokenRotator,
	redisClient *client.RedisClient,
) *LoginHandler {
	return &LoginHandler{
		jwtManager:       jwtManager,
		userRepo:         userRepo,
		roleRepo:         roleRepo,
		deviceRepo:       deviceRepo,
		sessionEncryptor: sessionEncryptor,
		tokenRotator:     tokenRotator,
		redisClient:      redisClient,
	}
}

func (h *LoginHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// 1. Parse request
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	if strings.TrimSpace(req.Phone) == "" {
		h.writeError(w, http.StatusBadRequest, "Phone is required")
		return
	}

	// 2. Normalize phone
	phone := util.NormalizePhone(req.Phone)
	if !util.IsValidIndianPhone(phone) {
		h.writeError(w, http.StatusBadRequest, "Invalid phone")
		return
	}

	// 3. Get device fingerprint
	fp, ok := middleware.FromContext(ctx)
	if !ok || fp.DeviceKey == "" {
		h.writeError(w, http.StatusBadRequest, "Device fingerprint missing")
		return
	}
	deviceKey := fp.DeviceKey

	// 4. Upsert device
	deviceSignals := map[string]interface{}{
		"platform":         fp.Platform,
		"app_version":      fp.AppVersion,
		"is_auto_detected": fp.IsAutoDetected,
		"stability_score":  fp.StabilityScore,
		"browser_fp":       fp.BrowserFingerprint,
		"os_fp":            fp.OSFingerprint,
		"ip_bucket":        fp.IPBucket,
		"timezone_offset":  fp.TimezoneOffset,
		"language":         fp.Language,
		"ua_hash":          fp.UAHash,
	}
	deviceRecord, err := h.deviceRepo.UpsertDeviceByKey(ctx, deviceKey, fp.Platform, deviceSignals, fp.ObservedAt)
	if err != nil {
		logger.Errorf("Failed to upsert device: %v", err)
		h.writeError(w, http.StatusInternalServerError, "Device tracking error")
		return
	}
	isFirstSeen := deviceRecord.FirstSeen.Equal(deviceRecord.LastSeen)

	// 5. Trust check with persistent set
	trusted, err := h.redisClient.SIsMember(ctx, "devices:"+phone, deviceKey).Result()
	if err != nil {
		logger.Errorf("Redis error checking device trust: %v", err)
		h.writeError(w, http.StatusInternalServerError, "Redis error")
		return
	}
	isDeviceTrusted := trusted
	if deviceRecord.RiskScore > 80 {
		logger.Warnf("High risk device blocked: phone=%s, device=%s", phone, deviceKey[:12]+"...")
		h.writeError(w, http.StatusForbidden, "Device security check failed")
		return
	}

	// 6. OTP requirement
	recentKey := fmt.Sprintf("recent_verified:%s:%s", phone, deviceKey)
	recent, err := h.redisClient.Get(ctx, recentKey).Result()
	if !isDeviceTrusted && (err == redis.Nil || recent != "1") {
		h.writeJSON(w, http.StatusUnauthorized, LoginResponse{
			Status:      "otp_required",
			Message:     "OTP required for new device",
			RequiresOTP: true,
			DeviceInfo: &DeviceInfo{
				DeviceKey:      deviceKey,
				Platform:       fp.Platform,
				IsAutoDetected: fp.IsAutoDetected,
				StabilityScore: fp.StabilityScore,
				TrustLevel:     deviceRecord.TrustLevel,
				RiskScore:      deviceRecord.RiskScore,
				FirstSeen:      isFirstSeen,
			},
		})
		return
	}

	// 7. Mark device trusted and clear recent flag
	if !isDeviceTrusted {
		_ = h.redisClient.SAdd(ctx, "devices:"+phone, deviceKey).Err()
		_ = h.redisClient.Del(ctx, recentKey).Err()
	}

	// 8. Get or create user
	user, err := h.userRepo.GetByPhone(ctx, phone)
	if err != nil {
		logger.Errorf("DB error: %v", err)
		h.writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	devID, _ := uuid.Parse(deviceRecord.ID)
	if user == nil || user.ID == uuid.Nil {
		user = &models.User{
			ID:              uuid.New(),
			PhoneNumber:     phone,
			PhoneVerified:   true,
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
			PrimaryDeviceID: &devID,
		}
		_ = h.userRepo.CreateUser(ctx, user)
	} else if user.PrimaryDeviceID == nil {
		_ = h.userRepo.UpdateUser(ctx, user.ID, map[string]interface{}{"primary_device_id": devID})
	}

	// 9. Issue tokens
	authz := &models.AuthzContext{Attributes: map[string]interface{}{"user_id": user.ID}}
	at, rt, sid, err := h.jwtManager.IssueTokens(ctx, authz, deviceKey)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Token generation failed")
		return
	}
	if claims, e := h.jwtManager.ValidateToken(at); e == nil {
		h.tokenRotator.RegisterToken(ctx, claims.TokenID, user.ID,
			util.AccessToken, deviceKey, sid, claims.ExpiresAt.Time, 0)
	}

	// 10. Create session
	sessionData := models.JSONMap{"login_time": time.Now(), "device_key": deviceKey}
	var sessionID string
	if sess, e := h.sessionEncryptor.CreateSession(ctx, user.ID, sessionData); e == nil {
		http.SetCookie(w, h.sessionEncryptor.CreateSessionCookie(sess))
		sessionID = sess.SessionID
	}

	// 11. Build response
	userInfo := map[string]interface{}{"id": user.ID, "phone": user.PhoneNumber, "verified": user.PhoneVerified}
	h.writeJSON(w, http.StatusOK, LoginResponse{
		Status:       "success",
		Message:      "Login successful",
		AccessToken:  at,
		RefreshToken: rt,
		TokenType:    "Bearer",
		ExpiresIn:    900,
		SessionID:    sessionID,
		User:         &userInfo,
		DeviceInfo: &DeviceInfo{
			DeviceKey:      deviceKey,
			Platform:       fp.Platform,
			IsAutoDetected: fp.IsAutoDetected,
			StabilityScore: fp.StabilityScore,
			TrustLevel:     deviceRecord.TrustLevel,
			RiskScore:      deviceRecord.RiskScore,
			FirstSeen:      isFirstSeen,
		},
	})
}

func (h *LoginHandler) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *LoginHandler) writeError(w http.ResponseWriter, status int, msg string) {
	h.writeJSON(w, status, map[string]string{"message": msg})
}
