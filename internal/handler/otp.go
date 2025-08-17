package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ComUnity/auth-service/internal/middleware"
	"github.com/ComUnity/auth-service/internal/repository"
	"github.com/ComUnity/auth-service/internal/service"
	"github.com/ComUnity/auth-service/internal/util/logger"
)

type OTPHandler struct {
	service   *service.OTPService
	otpRepo   repository.OTPRepository
	otpSecret string // server-side secret/pepper for phone_hash
}

// Keep your original constructor signature if you prefer, or inject repo+secret here.
func NewOTPHandler(svc *service.OTPService, repo repository.OTPRepository, otpSecret string) *OTPHandler {
	return &OTPHandler{service: svc, otpRepo: repo, otpSecret: otpSecret}
}

func (h *OTPHandler) SendOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Phone   string `json:"phone"`
		Purpose string `json:"purpose"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Phone) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"message": "invalid request",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	ip := realIP(r)

	// Privacy-preserving fingerprint fields if available
	var deviceKey, ipBucket, uaHash, platform, appVersion *string
	if fp, ok := middleware.FromContext(r.Context()); ok && fp != nil {
		deviceKey = ptr(fp.DeviceKey)
		ipBucket = ptr(fp.IPBucket)
		uaHash = ptr(fp.UAHash)
		platform = ptr(fp.Platform)
		appVersion = ptr(fp.AppVersion)
	}

	// phone_hash (salted HMAC), no raw phone stored
	ph := phoneHash(h.otpSecret, req.Phone)
	expires := time.Now().Add(h.service.Config().Expiration)

	// Persist "requested" audit row before provider call (best-effort)
	var otpID string
	if h.otpRepo != nil {
		id, err := h.otpRepo.CreateOTPRequest(ctx, repository.OTPRequest{
			PhoneHash:    ph,
			DeviceKey:    deviceKey,
			Channel:      "sms",
			Provider:     nil, // set if you track provider id
			TemplateID:   nil, // set if you track template id
			SenderID:     nil, // set if you track sender id
			CreatedAt:    time.Now().UTC(),
			ExpiresAt:    expires,
			Status:       "requested",
			AttemptCount: 0,
			IPBucket:     ipBucket,
			UAHash:       uaHash,
			Platform:     platform,
			AppVersion:   appVersion,
			Metadata:     json.RawMessage(`{}`),
		})
		if err != nil {
			logger.Error("otp_audit_create_failed: err=%v", err)
		} else {
			otpID = id
		}
	}

	// Existing behavior: generate & send OTP via service (Redis only; no DB code stored)
	_, err := h.service.GenerateOTP(ctx, req.Phone, ip, req.Purpose)
	if err != nil {
		resp := map[string]any{"success": false, "message": err.Error()}
		if errors.Is(err, service.ErrResendCooldown) {
			resp["cooldown_sec"] = int(h.service.Config().ResendCooldown.Seconds())
		}
		writeJSON(w, http.StatusTooManyRequests, resp)
		logger.Warn("OTP send failed: phone=%s ip=%s err=%v", maskPhone(req.Phone), ip, err)

		// Update audit status to failed (best-effort)
		if h.otpRepo != nil && otpID != "" {
			_ = h.otpRepo.MarkOTPRequestStatus(ctx, otpID, "failed", map[string]any{
				"reason": err.Error(),
			})
		}
		return
	}

	// Keep status as "requested" unless you have delivery callbacks
	if h.otpRepo != nil && otpID != "" {
		_ = h.otpRepo.MarkOTPRequestStatus(ctx, otpID, "requested", nil)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "OTP sent",
	})
	logger.Info("OTP sent: phone=%s ip=%s", maskPhone(req.Phone), ip)
}

func (h *OTPHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Phone   string `json:"phone"`
		Code    string `json:"code"`
		Purpose string `json:"purpose"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"message": "invalid request",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	ip := realIP(r)

	// Privacy-preserving fingerprint fields if available
	var deviceKey, ipBucket, uaHash *string
	if fp, ok := middleware.FromContext(r.Context()); ok && fp != nil {
		deviceKey = ptr(fp.DeviceKey)
		ipBucket = ptr(fp.IPBucket)
		uaHash = ptr(fp.UAHash)
	}

	// Existing behavior: verify via service (Redis only)
	valid, err := h.service.VerifyOTP(ctx, req.Phone, req.Code, req.Purpose, ip)
	if err != nil || !valid {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"success": false,
			"message": err.Error(),
		})

		// Persist verification failure (best-effort) by correlating last request for phone_hash
		if h.otpRepo != nil {
			ph := phoneHash(h.otpSecret, req.Phone)
			if last, e := h.otpRepo.GetLastRequestByPhone(ctx, ph); e == nil && last != nil {
				reason := err.Error()
				_, _ = h.otpRepo.RecordOTPVerification(ctx, repository.OTPVerification{
					OTPID:        last.ID,
					VerifiedAt:   time.Now().UTC(),
					Result:       "failure",
					Reason:       &reason,
					DeviceKey:    deviceKey,
					IPBucket:     ipBucket,
					UAHash:       uaHash,
					RiskSnapshot: json.RawMessage(`{}`),
				})
				_ = h.otpRepo.IncrementOTPAttempts(ctx, last.ID)
			}
		}
		return
	}

	// Success path unchanged
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "OTP verified",
	})

	// Persist verification success (best-effort)
	if h.otpRepo != nil {
		ph := phoneHash(h.otpSecret, req.Phone)
		if last, e := h.otpRepo.GetLastRequestByPhone(ctx, ph); e == nil && last != nil {
			_, _ = h.otpRepo.RecordOTPVerification(ctx, repository.OTPVerification{
				OTPID:        last.ID,
				VerifiedAt:   time.Now().UTC(),
				Result:       "success",
				Reason:       nil,
				DeviceKey:    deviceKey,
				IPBucket:     ipBucket,
				UAHash:       uaHash,
				RiskSnapshot: json.RawMessage(`{}`),
			})
		}
	}
}

// Utilities

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func realIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.TrimSpace(strings.Split(ip, ",")[0])
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

func maskPhone(p string) string {
	// Mask except last 3 digits for logs
	if n := len(p); n >= 3 {
		return strings.Repeat("*", n-3) + p[n-3:]
	}
	return "***"
}

func ptr[T any](v T) *T { return &v }

// Local phoneHash helper (identical logic to your service’s phoneHash).
// If you prefer, export service.PhoneHash and call that instead.
func phoneHash(secret, phone string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(phone))
	return hex.EncodeToString(mac.Sum(nil))
}
