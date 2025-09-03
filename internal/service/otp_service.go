package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	
	"time"
	"github.com/ComUnity/auth-service/internal/config"

	client "github.com/ComUnity/auth-service/internal/client"
	"github.com/ComUnity/auth-service/internal/util"
	"github.com/ComUnity/auth-service/internal/util/logger"
)

var (
	ErrInvalidPhone       = errors.New("invalid phone number")
	ErrPhoneBlocked       = errors.New("phone number temporarily blocked")
	ErrResendCooldown     = errors.New("resend cooldown active")
	ErrDailyLimitExceeded = errors.New("daily OTP limit exceeded")
	ErrOTPNotFound        = errors.New("OTP not found or expired")
	ErrOTPExpired         = errors.New("OTP expired")
	ErrMaxAttempts        = errors.New("maximum attempts reached")
	ErrPurposeMismatch    = errors.New("OTP purpose mismatch")
)

type OTPConfig = config.OTPConfig

type OTPData struct {
	Code      string    `json:"code"`
	CreatedAt time.Time `json:"created_at"`
	Attempts  int       `json:"attempts"`
	Purpose   string    `json:"purpose"`
	IP        string    `json:"ip"`
}

type SMSProvider interface {
	SendOTP(ctx context.Context, phone, code string) error
}

type OTPService struct {
	redis  *client.RedisClient
	config OTPConfig
	sms    SMSProvider
}

func NewOTPService(redis *client.RedisClient, cfg OTPConfig, sms SMSProvider) *OTPService {
	if cfg.CodeLength < 4 || cfg.CodeLength > 8 {
		cfg.CodeLength = 6
	}
	if cfg.Expiration == 0 {
		cfg.Expiration = 10 * time.Minute
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.MaxDailyPerUser == 0 {
		cfg.MaxDailyPerUser = 5
	}
	if cfg.BlockDuration == 0 {
		cfg.BlockDuration = 24 * time.Hour
	}
	if cfg.ResendCooldown == 0 {
		cfg.ResendCooldown = 30 * time.Second
	}
	return &OTPService{redis: redis, config: cfg, sms: sms}
}

// Expose a read-only copy of config
func (s *OTPService) Config() OTPConfig {
	return s.config
}

// ------------------ Public Methods ------------------

func (s *OTPService) GenerateOTP(ctx context.Context, phone, ip, purpose string) (string, error) {
	normalized := util.NormalizePhone(phone)
	if !util.IsValidIndianPhone(normalized) {
		return "", ErrInvalidPhone
	}
	if blocked, _ := s.isBlocked(ctx, normalized); blocked {
		return "", ErrPhoneBlocked
	}
	if count, _ := s.getDailyCount(ctx, normalized); count >= s.config.MaxDailyPerUser {
		return "", ErrDailyLimitExceeded
	}
	if cooldown, _ := s.getResendCooldown(ctx, normalized); cooldown > 0 {
		return "", fmt.Errorf("%w: try again in %v", ErrResendCooldown, cooldown)
	}

	code, err := s.generateCode()
	if err != nil {
		return "", fmt.Errorf("generate OTP: %w", err)
	}

	otpData := OTPData{
		Code:      code,
		CreatedAt: time.Now(),
		Attempts:  0,
		Purpose:   purpose,
		IP:        ip,
	}
	if err := s.storeOTP(ctx, normalized, otpData); err != nil {
		return "", err
	}

	if s.config.DeliverySimulation {
		logger.Info("OTP simulation %s -> %s", normalized, code)
	} else {
		if !regexp.MustCompile(`^[0-9]{10,15}$`).MatchString(normalized) {
			return "", ErrInvalidPhone
		}
		if err := s.sms.SendOTP(ctx, normalized, code); err != nil {
			s.cleanupOTP(ctx, normalized)
			return "", err
		}
	}

	s.updateCounters(ctx, normalized)
	return code, nil
}

func (s *OTPService) VerifyOTP(ctx context.Context, phone, code, purpose, ip string) (bool, error) {
	normalized := util.NormalizePhone(phone)
	if blocked, _ := s.isBlocked(ctx, normalized); blocked {
		return false, ErrPhoneBlocked
	}

	stored, err := s.getStoredOTP(ctx, normalized)
	if err != nil {
		return false, err
	}
	if stored.Purpose != purpose {
		return false, ErrPurposeMismatch
	}
	if time.Since(stored.CreatedAt) > s.config.Expiration {
		s.cleanupOTP(ctx, normalized)
		return false, ErrOTPExpired
	}
	if stored.Attempts >= s.config.MaxAttempts {
		time.Sleep(time.Second)
		s.blockPhone(ctx, normalized)
		s.cleanupOTP(ctx, normalized)
		return false, ErrMaxAttempts
	}
	if subtle.ConstantTimeCompare([]byte(stored.Code), []byte(code)) != 1 {
		stored.Attempts++
		_ = s.updateStoredOTP(ctx, normalized, *stored)
		if stored.Attempts >= s.config.MaxAttempts {
			s.blockPhone(ctx, normalized)
			s.cleanupOTP(ctx, normalized)
			return false, ErrMaxAttempts
		}
		return false, nil
	}

	s.cleanupOTP(ctx, normalized)
	return true, nil
}

// SetRecentVerified sets the recent_verified flag for login handler
func (s *OTPService) SetRecentVerified(ctx context.Context, phone string) error {
    normalized := util.NormalizePhone(phone)
    key := "recent_verified:" + normalized
    ttl := s.config.Expiration
    logger.Infof("Setting Redis key %s with TTL=%v", key, ttl)
    err := s.redis.SetEx(ctx, key, "1", ttl).Err()
    if err != nil {
        logger.Errorf("Redis SetEx failed for %s: %v", key, err)
    }
    return err
}

// ------------------ Redis Helper Methods ------------------

func (s *OTPService) storeOTP(ctx context.Context, phone string, data OTPData) error {
	key := "otp:" + phone
	bytes, _ := json.Marshal(data)
	return s.redis.SetEx(ctx, key, bytes, s.config.Expiration).Err()
}

func (s *OTPService) getStoredOTP(ctx context.Context, phone string) (*OTPData, error) {
	key := "otp:" + phone
	val, err := s.redis.Get(ctx, key).Result()
	if err != nil || val == "" {
		return nil, ErrOTPNotFound
	}
	var data OTPData
	_ = json.Unmarshal([]byte(val), &data)
	return &data, nil
}

func (s *OTPService) updateStoredOTP(ctx context.Context, phone string, data OTPData) error {
	return s.storeOTP(ctx, phone, data)
}

func (s *OTPService) cleanupOTP(ctx context.Context, phone string) {
	_ = s.redis.Del(ctx, "otp:"+phone).Err()
}

func (s *OTPService) isBlocked(ctx context.Context, phone string) (bool, error) {
	exists, _ := s.redis.Exists(ctx, "block:"+phone).Result()
	return exists > 0, nil
}

func (s *OTPService) blockPhone(ctx context.Context, phone string) {
	_ = s.redis.SetEx(ctx, "block:"+phone, "1", s.config.BlockDuration).Err()
}

func (s *OTPService) getDailyCount(ctx context.Context, phone string) (int, error) {
	key := "count:" + phone + ":" + time.Now().Format("2006-01-02")
	val, _ := s.redis.Get(ctx, key).Result()
	if val == "" {
		return 0, nil
	}
	return strconv.Atoi(val)
}

func (s *OTPService) getResendCooldown(ctx context.Context, phone string) (time.Duration, error) {
	ttl, _ := s.redis.TTL(ctx, "cooldown:"+phone).Result()
	if ttl > 0 {
		return ttl, nil
	}
	return 0, nil
}

func (s *OTPService) updateCounters(ctx context.Context, phone string) {
	// Cooldown
	_ = s.redis.SetEx(ctx, "cooldown:"+phone, "1", s.config.ResendCooldown).Err()

	// Daily count
	key := "count:" + phone + ":" + time.Now().Format("2006-01-02")
	count, _ := s.getDailyCount(ctx, phone)
	_ = s.redis.SetEx(ctx, key, strconv.Itoa(count+1), 24*time.Hour).Err()
}

// ------------------ Utility ------------------

func phoneHash(secret, phone string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(phone))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *OTPService) generateCode() (string, error) {
	buf := make([]byte, s.config.CodeLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	digits := make([]byte, s.config.CodeLength)
	for i := range buf {
		digits[i] = byte((int(buf[i]) % 10) + '0')
	}
	return string(digits), nil
}