package service

import (
	"context"
	"encoding/json"
	"time"
	"github.com/ComUnity/auth-service/internal/repository"

)

// Breaker controls fail-open behavior when dependencies are unhealthy.
type Breaker interface {
	Allow() bool
}

// Minimal Redis JSON interface based on your internal/client Redis client.
// Your client exposes SetJSON and GetJSON helpers; Del can be omitted if you
// prefer eventual consistency via TTL. If you have a Del wrapper, add it here.
type redisJSON interface {
	SetJSON(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	GetJSON(ctx context.Context, key string, dest interface{}) error
	// Optional: expose Del if you want explicit invalidation
	// Del(ctx context.Context, keys ...string) *redis.IntCmd
}

type RiskDecision string

const (
	DecisionAllow  RiskDecision = "allow"
	DecisionStepUp RiskDecision = "step_up"
	DecisionDeny   RiskDecision = "deny"
)

type CurrentSignals struct {
	DeviceKey  string
	Platform   string
	AppVersion string
	UAHash     string
	IPBucket   string
	ObservedAt time.Time
	UserID     *string
}

type RiskConfig struct {
	NewDeviceStepUp            bool
	IPBucketChangeStepUp       bool
	MaxRiskBeforeDeny          int
	FailedBiometricRiskDelta   int
	SuccessStrongAuthTrustGain int
	SuccessStrongAuthRiskCut   int
	StaleDeviceDays            int
	MinTrustForFrictionless    int
}

type RiskEvalResult struct {
	Decision   RiskDecision
	TrustLevel int
	RiskScore  int
	Reason     string
	DeviceID   string
}

type RiskService struct {
	repo     repository.DeviceRepository
	cfg      RiskConfig
	breaker  Breaker
	rdb      redisJSON
	cacheTTL time.Duration
}

const deviceCachePrefix = "df:"

func NewRiskService(
	repo repository.DeviceRepository,
	cfg RiskConfig,
	breaker Breaker,
	rdb redisJSON,            // pass your *client.RedisClient here
	cacheTTL time.Duration,   // e.g., 5 * time.Minute
) *RiskService {
	return &RiskService{
		repo:     repo,
		cfg:      cfg,
		breaker:  breaker,
		rdb:      rdb,
		cacheTTL: cacheTTL,
	}
}

func (s *RiskService) Evaluate(ctx context.Context, sig CurrentSignals) (*RiskEvalResult, error) {
	// Fail-open if breaker is tripped
	if s.breaker != nil && !s.breaker.Allow() {
		return &RiskEvalResult{
			Decision:   DecisionAllow,
			TrustLevel: 0,
			RiskScore:  0,
			Reason:     "breaker_open_allow",
		}, nil
	}

	// Optional: use any cached prior state for quicker anomaly comparisons.
	// We still upsert to merge signals and update last_seen in DB.
	var cachedPrior *repository.DeviceFingerprintDB
	if c, ok := s.cacheGet(ctx, sig.DeviceKey); ok {
		cachedPrior = c
	}

	signals := map[string]any{
		"UAHash":     sig.UAHash,
		"IPBucket":   sig.IPBucket,
		"Platform":   sig.Platform,
		"AppVersion": sig.AppVersion,
	}
	dev, err := s.repo.UpsertDeviceByKey(ctx, sig.DeviceKey, sig.Platform, signals, sig.ObservedAt)
	if err != nil {
		return nil, err
	}
	s.cacheSet(ctx, sig.DeviceKey, dev)

	// Derive prior signals: prefer fresh DB row; fall back to cached if needed.
	var prior map[string]any
	if len(dev.Signals) > 0 {
		_ = json.Unmarshal(dev.Signals, &prior)
	} else if cachedPrior != nil && len(cachedPrior.Signals) > 0 {
		_ = json.Unmarshal(cachedPrior.Signals, &prior)
	}

	prevIPB, _ := prior["IPBucket"].(string)
	prevUAH, _ := prior["UAHash"].(string)

	isNew := dev.FirstSeen.Equal(dev.LastSeen)
	stale := s.cfg.StaleDeviceDays > 0 && time.Since(dev.LastSeen) > time.Duration(s.cfg.StaleDeviceDays)*24*time.Hour
	ipChanged := prevIPB != "" && sig.IPBucket != "" && prevIPB != sig.IPBucket
	uaChanged := prevUAH != "" && sig.UAHash != "" && prevUAH != sig.UAHash

	// Deny if already too risky
	if dev.RiskScore >= s.cfg.MaxRiskBeforeDeny {
		return &RiskEvalResult{
			Decision:   DecisionDeny,
			TrustLevel: dev.TrustLevel,
			RiskScore:  dev.RiskScore,
			Reason:     "risk_too_high",
			DeviceID:   dev.ID,
		}, nil
	}

	// Step-up conditions
	if (s.cfg.NewDeviceStepUp && (isNew || stale)) ||
		(s.cfg.IPBucketChangeStepUp && ipChanged) ||
		uaChanged ||
		(dev.TrustLevel < s.cfg.MinTrustForFrictionless) {
		return &RiskEvalResult{
			Decision:   DecisionStepUp,
			TrustLevel: dev.TrustLevel,
			RiskScore:  dev.RiskScore,
			Reason:     "anomaly_or_low_trust",
			DeviceID:   dev.ID,
		}, nil
	}

	return &RiskEvalResult{
		Decision:   DecisionAllow,
		TrustLevel: dev.TrustLevel,
		RiskScore:  dev.RiskScore,
		Reason:     "allow",
		DeviceID:   dev.ID,
	}, nil
}

// Call after client completes biometric or device credential successfully
func (s *RiskService) OnStrongAuthSuccess(ctx context.Context, deviceID string, userID *string, now time.Time, method string, ipBucket string) error {
	// Adjust trust/risk
	if err := s.repo.UpdateTrustAndRisk(ctx, deviceID, s.cfg.SuccessStrongAuthTrustGain, -s.cfg.SuccessStrongAuthRiskCut); err != nil {
		return err
	}
	// Record event (batched by repository)
	meta := map[string]any{"method": method, "ip_bucket": ipBucket}
	b, _ := json.Marshal(meta)
	s.repo.QueueEvent(repository.DeviceTrustEvent{
		DeviceID: deviceID,
		UserID:   userID,
		Type:     successEvent(method),
		TS:       now,
		Meta:     b,
	})

	// Optional: cache invalidation could be added if you track deviceKey here.
	// Otherwise rely on TTL-based eventual consistency.

	return nil
}

// Call after failed biometric attempts
func (s *RiskService) OnStrongAuthFailure(ctx context.Context, deviceID string, userID *string, now time.Time, ipBucket string) error {
	if err := s.repo.UpdateTrustAndRisk(ctx, deviceID, 0, s.cfg.FailedBiometricRiskDelta); err != nil {
		return err
	}
	meta := map[string]any{"ip_bucket": ipBucket}
	b, _ := json.Marshal(meta)
	s.repo.QueueEvent(repository.DeviceTrustEvent{
		DeviceID: deviceID,
		UserID:   userID,
		Type:     "failed_biometric",
		TS:       now,
		Meta:     b,
	})

	// Optional: cache invalidation could be added if you track deviceKey here.
	// Otherwise rely on TTL-based eventual consistency.

	return nil
}

func successEvent(method string) string {
	switch method {
	case "biometric":
		return "success_biometric"
	case "device_credential":
		return "success_device_credential"
	default:
		return "otp_only"
	}
}

// ---- Redis cache helpers ----

func (s *RiskService) cacheGet(ctx context.Context, deviceKey string) (*repository.DeviceFingerprintDB, bool) {
	if s.rdb == nil || s.cacheTTL <= 0 {
		return nil, false
	}
	var df repository.DeviceFingerprintDB
	if err := s.rdb.GetJSON(ctx, deviceCachePrefix+deviceKey, &df); err != nil {
		return nil, false
	}
	if df.ID == "" || df.DeviceKey == "" {
		return nil, false
	}
	return &df, true
}

func (s *RiskService) cacheSet(ctx context.Context, deviceKey string, df *repository.DeviceFingerprintDB) {
	if s.rdb == nil || s.cacheTTL <= 0 || df == nil {
		return
	}
	_ = s.rdb.SetJSON(ctx, deviceCachePrefix+deviceKey, df, s.cacheTTL)
}

// If you add a Del method to your client interface, you can expose:
// func (s *RiskService) cacheDel(ctx context.Context, deviceKey string) {
//     if s.rdb == nil { return }
//     // _ = s.rdb.Del(ctx, deviceCachePrefix+deviceKey)
// }
