package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ComUnity/auth-service/internal/client"
	"github.com/ComUnity/auth-service/internal/middleware"
	"github.com/ComUnity/auth-service/internal/repository"
	"github.com/ComUnity/auth-service/internal/service"
	"github.com/ComUnity/auth-service/internal/util"
	"github.com/ComUnity/auth-service/internal/util/logger"
)

type OTPHandler struct {
	service   *service.OTPService
	otpRepo   repository.OTPRepository
	otpSecret string
	redis     *client.RedisClient
}

func NewOTPHandler(
	svc *service.OTPService,
	repo repository.OTPRepository,
	otpSecret string,
	redisClient *client.RedisClient,
) *OTPHandler {
	return &OTPHandler{
		service:   svc,
		otpRepo:   repo,
		otpSecret: otpSecret,
		redis:     redisClient,
	}
}

func (h *OTPHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Phone   string `json:"phone"`
		Code    string `json:"code"`
		Purpose string `json:"purpose"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		strings.TrimSpace(req.Phone) == "" ||
		strings.TrimSpace(req.Code) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false, "message": "invalid request",
		})
		return
	}

	normalized := util.NormalizePhone(req.Phone)

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	ip := realIP(r)

	var deviceKeyStr string
	if fp, ok := middleware.FromContext(ctx); ok && fp != nil {
		deviceKeyStr = fp.DeviceKey
	}

	valid, verr := h.service.VerifyOTP(ctx, normalized, req.Code, req.Purpose, ip)
	if !valid {
		msg := "unauthorized"
		status := http.StatusUnauthorized
		if verr != nil {
			msg = verr.Error()
			switch verr {
			case service.ErrOTPNotFound, service.ErrOTPExpired:
				status = http.StatusUnauthorized
			case service.ErrPhoneBlocked, service.ErrMaxAttempts:
				status = http.StatusTooManyRequests
			}
		}
		writeJSON(w, status, map[string]any{"success": false, "message": msg})
		recordOTPFailure(ctx, h, normalized, deviceKeyStr, msg)
		return
	}

	// Set short-lived flag for this phone+device only
	if deviceKeyStr != "" {
		key := fmt.Sprintf("recent_verified:%s:%s", normalized, deviceKeyStr)
		if err := h.redis.Set(ctx, key, "1", 5*time.Minute).Err(); err != nil {
			logger.Errorf("Failed to set %s: %v", key, err)
		} else {
			logger.Infof("Set recent_verified flag: %s", key)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "OTP verified",
	})
	recordOTPSuccess(ctx, h, normalized, deviceKeyStr)
}

func (h *OTPHandler) SendOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Phone   string `json:"phone"`
		Purpose string `json:"purpose"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		strings.TrimSpace(req.Phone) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false, "message": "invalid request",
		})
		return
	}

	normalized := util.NormalizePhone(req.Phone)
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	ip := realIP(r)
	code, err := h.service.GenerateOTP(ctx, normalized, ip, req.Purpose)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false, "message": err.Error(),
		})
		return
	}

	if h.service.Config().DeliverySimulation {
		writeJSON(w, http.StatusOK, map[string]any{
			"success": true, "message": "OTP generated (simulation mode)", "code": code,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "message": "OTP sent",
	})
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

func recordOTPFailure(
	ctx context.Context,
	h *OTPHandler,
	normalized, deviceKey, reason string,
) {
	if h.otpRepo == nil {
		return
	}
	ph := phoneHash(h.otpSecret, normalized)
	if last, err := h.otpRepo.GetLastRequestByPhone(ctx, ph); err == nil && last != nil {
		_, _ = h.otpRepo.RecordOTPVerification(ctx, repository.OTPVerification{
			OTPID:      last.ID,
			VerifiedAt: time.Now().UTC(),
			Result:     "failure",
			Reason:     &reason,
			DeviceKey:  &deviceKey,
			IPBucket:   ptr(""), UAHash: ptr(""), RiskSnapshot: nil,
		})
		h.otpRepo.IncrementOTPAttempts(ctx, last.ID)
	}
}

func recordOTPSuccess(
	ctx context.Context,
	h *OTPHandler,
	normalized, deviceKey string,
) {
	if h.otpRepo == nil {
		return
	}
	ph := phoneHash(h.otpSecret, normalized)
	if last, err := h.otpRepo.GetLastRequestByPhone(ctx, ph); err == nil && last != nil {
		_, _ = h.otpRepo.RecordOTPVerification(ctx, repository.OTPVerification{
			OTPID:      last.ID,
			VerifiedAt: time.Now().UTC(),
			Result:     "success",
			Reason:     nil,
			DeviceKey:  &deviceKey,
			IPBucket:   ptr(""), UAHash: ptr(""), RiskSnapshot: nil,
		})
	}
}

func ptr[T any](v T) *T { return &v }

func phoneHash(secret, phone string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(phone))
	return hex.EncodeToString(mac.Sum(nil))
}
