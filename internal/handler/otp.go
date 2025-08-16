package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ComUnity/auth-service/internal/service"
	"github.com/ComUnity/auth-service/internal/util/logger"
)

type OTPHandler struct {
	service *service.OTPService
}

func NewOTPHandler(svc *service.OTPService) *OTPHandler {
	return &OTPHandler{service: svc}
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
	_, err := h.service.GenerateOTP(ctx, req.Phone, ip, req.Purpose)
	if err != nil {
		resp := map[string]any{"success": false, "message": err.Error()}
		if errors.Is(err, service.ErrResendCooldown) {
			resp["cooldown_sec"] = int(h.service.Config().ResendCooldown.Seconds())
		}
		writeJSON(w, http.StatusTooManyRequests, resp)
		logger.Warn("OTP send failed: phone=%s ip=%s err=%v", req.Phone, ip, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "OTP sent",
	})
	logger.Info("OTP sent: phone=%s ip=%s", req.Phone, ip)
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
	valid, err := h.service.VerifyOTP(ctx, req.Phone, req.Code, req.Purpose, ip)
	if err != nil || !valid {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "OTP verified",
	})
}

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
