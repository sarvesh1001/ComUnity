package compliance

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ComUnity/auth-service/internal/client"
	"github.com/ComUnity/auth-service/internal/models"
	"github.com/ComUnity/auth-service/internal/repository"
	"github.com/ComUnity/auth-service/internal/util/logger"
)

// KMS abstracts the minimal operations used by DataRetentionManager,
// so this package does not import the security package and avoids cycles.
type KMS interface {
	GenerateDataKey(ctx context.Context, keySpec string) (interface{ GetPlaintext() []byte }, error)
}

// RetentionPolicyType represents different types of retention policies
type RetentionPolicyType string

const (
	PolicyTypeFixed       RetentionPolicyType = "fixed"       // Fixed retention period
	PolicyTypeRolling     RetentionPolicyType = "rolling"     // Rolling window
	PolicyTypeConditional RetentionPolicyType = "conditional" // Based on conditions
	PolicyTypeUserDriven  RetentionPolicyType = "user_driven" // User-controlled retention
)

// DataCategory represents categories of data for retention
type DataCategory string

const (
	CategoryAuditLogs   DataCategory = "audit_logs"
	CategoryUserData    DataCategory = "user_data"
	CategorySessionData DataCategory = "session_data"
	CategoryDeviceData  DataCategory = "device_data"
	CategoryOTPData     DataCategory = "otp_data"
	CategoryTokenData   DataCategory = "token_data"
	CategoryPermissionData DataCategory = "permission_data"
	CategoryCommunityData  DataCategory = "community_data"
	CategoryConsentData    DataCategory = "consent_data"
	CategoryBillingData    DataCategory = "billing_data"
)

// RetentionPolicy defines a data retention policy
type RetentionPolicy struct {
	ID                  uuid.UUID         `json:"id"`
	Name                string            `json:"name"`
	Description         string            `json:"description"`
	DataCategory        DataCategory      `json:"data_category"`
	PolicyType          RetentionPolicyType `json:"policy_type"`
	RetentionPeriod     time.Duration     `json:"retention_period"`
	GracePeriod         time.Duration     `json:"grace_period"`
	ComplianceStandards []string          `json:"compliance_standards"`
	DataSources         []string          `json:"data_sources"` // DB tables, ES indices, Redis patterns
	Conditions          RetentionConditions `json:"conditions"`
	DeletionStrategy    DeletionStrategy    `json:"deletion_strategy"`
	Enabled             bool              `json:"enabled"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
	CreatedBy           uuid.UUID         `json:"created_by"`
	LastExecuted        *time.Time        `json:"last_executed,omitempty"`
	NextExecution       time.Time         `json:"next_execution"`
	ExecutionCount      int64             `json:"execution_count"`
	RecordsDeleted      int64             `json:"records_deleted"`
	Metadata            models.JSONMap    `json:"metadata"`
}

// RetentionConditions defines conditions for data retention
type RetentionConditions struct {
	UserStatus        []string          `json:"user_status,omitempty"` // active, inactive, deleted
	DataAge           *time.Duration    `json:"data_age,omitempty"`    // Minimum age before deletion
	RecordCount       *int64            `json:"record_count,omitempty"`// Keep only N most recent records
	UserRequest       bool              `json:"user_request"`          // User requested deletion
	AccountClosure    bool              `json:"account_closure"`       // Account closed/deleted
	ConsentWithdrawn  bool              `json:"consent_withdrawn"`     // User withdrew consent
	LegalHold         bool              `json:"legal_hold"`            // Data under legal hold
	BusinessNeed      bool              `json:"business_need"`         // Business still needs data
	CustomConditions  map[string]string `json:"custom_conditions,omitempty"` // Custom SQL/query conditions
}

// DeletionStrategy defines how data should be deleted
type DeletionStrategy struct {
	Method             DeletionMethod  `json:"method"`
	BatchSize          int             `json:"batch_size"`
	MaxConcurrency     int             `json:"max_concurrency"`
	VerifyDeletion     bool            `json:"verify_deletion"`
	CreateBackup       bool            `json:"create_backup"`
	BackupRetention    time.Duration   `json:"backup_retention"`
	EncryptBackup      bool            `json:"encrypt_backup"`
	AuditDeletion      bool            `json:"audit_deletion"`
	NotifyOnCompletion bool            `json:"notify_on_completion"`
	DryRun             bool            `json:"dry_run"`
}

// DeletionMethod represents different deletion methods
type DeletionMethod string

const (
	MethodHardDelete  DeletionMethod = "hard_delete"  // Permanent deletion
	MethodSoftDelete  DeletionMethod = "soft_delete"  // Mark as deleted
	MethodArchive     DeletionMethod = "archive"      // Move to archive
	MethodAnonymize   DeletionMethod = "anonymize"    // Remove PII, keep aggregate data
	MethodPurge       DeletionMethod = "purge"        // Complete removal including backups
)

// RetentionExecution represents a retention policy execution
type RetentionExecution struct {
	ID                  uuid.UUID      `json:"id"`
	PolicyID            uuid.UUID      `json:"policy_id"`
	PolicyName          string         `json:"policy_name"`
	StartedAt           time.Time      `json:"started_at"`
	CompletedAt         *time.Time     `json:"completed_at,omitempty"`
	Status              ExecutionStatus `json:"status"`
	RecordsScanned      int64          `json:"records_scanned"`
	RecordsDeleted      int64          `json:"records_deleted"`
	RecordsSkipped      int64          `json:"records_skipped"`
	RecordsArchived     int64          `json:"records_archived"`
	BytesDeleted        int64          `json:"bytes_deleted"`
	Duration            *time.Duration `json:"duration,omitempty"`
	Error               string         `json:"error,omitempty"`
	ExecutedBy          string         `json:"executed_by"`
	DryRun              bool           `json:"dry_run"`
	AffectedDataSources []string       `json:"affected_data_sources"`
	Metadata            models.JSONMap `json:"metadata"`
}

// ExecutionStatus represents the status of a retention execution
type ExecutionStatus string

const (
	StatusPending   ExecutionStatus = "pending"
	StatusRunning   ExecutionStatus = "running"
	StatusCompleted ExecutionStatus = "completed"
	StatusFailed    ExecutionStatus = "failed"
	StatusCancelled ExecutionStatus = "cancelled"
	StatusPartial   ExecutionStatus = "partial"
)

// RetentionExecutor executes retention policies
type RetentionExecutor struct {
	manager *DataRetentionManager
}

func NewRetentionExecutor(manager *DataRetentionManager) *RetentionExecutor {
	return &RetentionExecutor{manager: manager}
}

// Execute method placeholder
func (e *RetentionExecutor) Execute(ctx context.Context, policy *RetentionPolicy, dryRun bool) (*RetentionExecution, error) {
	// TODO: Implement execution logic
	return &RetentionExecution{
		ID:           uuid.New(),
		PolicyID:     policy.ID,
		PolicyName:   policy.Name,
		StartedAt:    time.Now(),
		Status:       StatusCompleted,
		RecordsScanned: 0,
		RecordsDeleted: 0,
		DryRun:       dryRun,
	}, nil
}

// RetentionScheduler schedules retention policy executions
type RetentionScheduler struct {
	manager *DataRetentionManager
}

func NewRetentionScheduler(manager *DataRetentionManager) *RetentionScheduler {
	return &RetentionScheduler{manager: manager}
}

// Start method placeholder
func (s *RetentionScheduler) Start() {
	logger.Info("Retention scheduler started")
	// TODO: Implement scheduling logic
}

// DataRetentionManager manages data retention policies and executions
type DataRetentionManager struct {
	config RetentionConfig
	db     *sql.DB
	redis  *client.RedisClient
	esClient *http.Client
	kmsHelper KMS

	// Repository dependencies
	userRepo  repository.UserRepository
	cacheRepo repository.CacheRepository

	// Policy management
	policies   sync.Map // map[uuid.UUID]*RetentionPolicy
	executions sync.Map // map[uuid.UUID]*RetentionExecution

	// Execution management
	executor  *RetentionExecutor
	scheduler *RetentionScheduler

	// Statistics
	stats   RetentionStats
	statsMu sync.RWMutex
}

// RetentionConfig holds configuration for data retention
type RetentionConfig struct {
	Enabled            bool              `yaml:"enabled"`
	DefaultRetention   time.Duration     `yaml:"default_retention"`
	MinRetention       time.Duration     `yaml:"min_retention"`
	MaxRetention       time.Duration     `yaml:"max_retention"`
	ExecutionInterval  time.Duration     `yaml:"execution_interval"`
	BatchSize          int               `yaml:"batch_size"`
	MaxConcurrency     int               `yaml:"max_concurrency"`
	DryRunDefault      bool              `yaml:"dry_run_default"`
	AuditRetention     bool              `yaml:"audit_retention"`
	BackupBeforeDeletion bool            `yaml:"backup_before_deletion"`
	ESConfig           ESRetentionConfig `yaml:"elasticsearch"`
	CategoryPolicies   map[DataCategory]CategoryPolicy `yaml:"category_policies"`
	ComplianceSettings ComplianceSettings `yaml:"compliance"`
}

// ESRetentionConfig for Elasticsearch data retention
type ESRetentionConfig struct {
	Endpoint    string `yaml:"endpoint"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	APIKey      string `yaml:"api_key"`
	IndexPrefix string `yaml:"index_prefix"`
}

// CategoryPolicy defines default policies for data categories
type CategoryPolicy struct {
	DefaultRetention time.Duration  `yaml:"default_retention"`
	MinRetention     time.Duration  `yaml:"min_retention"`
	MaxRetention     time.Duration  `yaml:"max_retention"`
	DeletionMethod   DeletionMethod `yaml:"deletion_method"`
	RequireBackup    bool           `yaml:"require_backup"`
	AuditRequired    bool           `yaml:"audit_required"`
}

// ComplianceSettings for various compliance frameworks
type ComplianceSettings struct {
	GDPR GDPRSettings `yaml:"gdpr"`
	CCPA CCPASettings `yaml:"ccpa"`
	HIPAA HIPAASettings `yaml:"hipaa"`
}

// GDPRSettings for GDPR compliance
type GDPRSettings struct {
	Enabled                 bool          `yaml:"enabled"`
	DefaultRetention        time.Duration `yaml:"default_retention"`
	UserDataRetention       time.Duration `yaml:"user_data_retention"`
	ConsentWithdrawalGrace  time.Duration `yaml:"consent_withdrawal_grace"`
	RightToErasureEnabled   bool          `yaml:"right_to_erasure_enabled"`
	DataPortabilityEnabled  bool          `yaml:"data_portability_enabled"`
	AutoDeleteInactiveUsers bool          `yaml:"auto_delete_inactive_users"`
	InactiveUserThreshold   time.Duration `yaml:"inactive_user_threshold"`
}

// CCPASettings for CCPA compliance
type CCPASettings struct {
	Enabled                     bool          `yaml:"enabled"`
	BusinessRecordsRetention    time.Duration `yaml:"business_records_retention"`
	ConsumerDataRetention       time.Duration `yaml:"consumer_data_retention"`
	RightToDeleteEnabled        bool          `yaml:"right_to_delete_enabled"`
	SaleOptOutRetention         time.Duration `yaml:"sale_opt_out_retention"`
}

// HIPAASettings for HIPAA compliance
type HIPAASettings struct {
	Enabled               bool          `yaml:"enabled"`
	PHIRetention          time.Duration `yaml:"phi_retention"`
	AuditLogRetention     time.Duration `yaml:"audit_log_retention"`
	BackupRequirement     bool          `yaml:"backup_requirement"`
	SecureDeletionRequired bool         `yaml:"secure_deletion_required"`
}

// RetentionStats tracks retention statistics
type RetentionStats struct {
	TotalPolicies        int64         `json:"total_policies"`
	ActivePolicies       int64         `json:"active_policies"`
	TotalExecutions      int64         `json:"total_executions"`
	SuccessfulExecutions int64         `json:"successful_executions"`
	FailedExecutions     int64         `json:"failed_executions"`
	RecordsDeleted       int64         `json:"records_deleted"`
	BytesDeleted         int64         `json:"bytes_deleted"`
	LastExecution        *time.Time    `json:"last_execution,omitempty"`
	AverageExecutionTime time.Duration `json:"average_execution_time"`
}

// NewDataRetentionManager creates a new data retention manager
func NewDataRetentionManager(
	config RetentionConfig,
	db *sql.DB,
	redis *client.RedisClient,
	kmsHelper KMS,
	userRepo repository.UserRepository,
	cacheRepo repository.CacheRepository,
) *DataRetentionManager {
	// Set defaults
	if config.DefaultRetention == 0 {
		config.DefaultRetention = 90 * 24 * time.Hour
	}
	if config.MinRetention == 0 {
		config.MinRetention = 24 * time.Hour
	}
	if config.MaxRetention == 0 {
		config.MaxRetention = 7 * 365 * 24 * time.Hour
	}
	if config.ExecutionInterval == 0 {
		config.ExecutionInterval = 24 * time.Hour
	}
	if config.BatchSize == 0 {
		config.BatchSize = 1000
	}
	if config.MaxConcurrency == 0 {
		config.MaxConcurrency = 5
	}

	drm := &DataRetentionManager{
		config:    config,
		db:        db,
		redis:     redis,
		kmsHelper: kmsHelper,
		userRepo:  userRepo,
		cacheRepo: cacheRepo,
		esClient:  &http.Client{Timeout: 30 * time.Second},
	}

	if config.Enabled {
		drm.executor = NewRetentionExecutor(drm)
		drm.scheduler = NewRetentionScheduler(drm)

		if err := drm.loadPolicies(); err != nil {
			logger.Error("Failed to load retention policies", "error", err)
		}
		if err := drm.createDefaultPolicies(); err != nil {
			logger.Error("Failed to create default policies", "error", err)
		}

		go drm.scheduler.Start()

		logger.Info("Data retention manager initialized",
			"default_retention", config.DefaultRetention,
			"execution_interval", config.ExecutionInterval,
			"dry_run_default", config.DryRunDefault)
	}

	return drm
}

// CreatePolicy creates a new retention policy
func (drm *DataRetentionManager) CreatePolicy(ctx context.Context, policy *RetentionPolicy, createdBy uuid.UUID) (*RetentionPolicy, error) {
	if !drm.config.Enabled {
		return nil, fmt.Errorf("data retention manager is disabled")
	}
	if err := drm.validatePolicy(policy); err != nil {
		return nil, fmt.Errorf("invalid retention policy: %w", err)
	}

	policy.ID = uuid.New()
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	policy.CreatedBy = createdBy
	policy.NextExecution = time.Now().Add(drm.config.ExecutionInterval)

	if err := drm.storePolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to store policy: %w", err)
	}

	drm.policies.Store(policy.ID, policy)
	drm.updateStats(func(s *RetentionStats) {
		s.TotalPolicies++
		if policy.Enabled {
			s.ActivePolicies++
		}
	})

	logger.Info("Retention policy created",
		"policy_id", policy.ID,
		"name", policy.Name,
		"category", policy.DataCategory,
		"retention_period", policy.RetentionPeriod)

	return policy, nil
}

// GetPolicy retrieves a retention policy by ID
func (drm *DataRetentionManager) GetPolicy(ctx context.Context, policyID uuid.UUID) (*RetentionPolicy, error) {
	if cached, ok := drm.policies.Load(policyID); ok {
		return cached.(*RetentionPolicy), nil
	}
	policy, err := drm.loadPolicy(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("policy not found: %w", err)
	}
	drm.policies.Store(policyID, policy)
	return policy, nil
}

// ListPolicies returns all retention policies
func (drm *DataRetentionManager) ListPolicies(ctx context.Context) ([]*RetentionPolicy, error) {
	var policies []*RetentionPolicy
	drm.policies.Range(func(_, value interface{}) bool {
		policies = append(policies, value.(*RetentionPolicy))
		return true
	})
	return policies, nil
}

// UpdatePolicy updates an existing retention policy
func (drm *DataRetentionManager) UpdatePolicy(ctx context.Context, policy *RetentionPolicy) error {
	if !drm.config.Enabled {
		return fmt.Errorf("data retention manager is disabled")
	}
	if err := drm.validatePolicy(policy); err != nil {
		return fmt.Errorf("invalid retention policy: %w", err)
	}

	policy.UpdatedAt = time.Now()
	if err := drm.storePolicy(ctx, policy); err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}
	drm.policies.Store(policy.ID, policy)
	logger.Info("Retention policy updated", "policy_id", policy.ID, "name", policy.Name)
	return nil
}

// DeletePolicy deletes a retention policy
func (drm *DataRetentionManager) DeletePolicy(ctx context.Context, policyID uuid.UUID) error {
	if err := drm.removePolicy(ctx, policyID); err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}
	drm.policies.Delete(policyID)
	drm.updateStats(func(s *RetentionStats) {
		s.TotalPolicies--
	})
	logger.Info("Retention policy deleted", "policy_id", policyID)
	return nil
}

// ExecutePolicy manually executes a retention policy
func (drm *DataRetentionManager) ExecutePolicy(ctx context.Context, policyID uuid.UUID, dryRun bool) (*RetentionExecution, error) {
	policy, err := drm.GetPolicy(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("policy not found: %w", err)
	}
	if !policy.Enabled {
		return nil, fmt.Errorf("policy is disabled")
	}
	return drm.executor.Execute(ctx, policy, dryRun)
}

// GetExecution retrieves a retention execution by ID
func (drm *DataRetentionManager) GetExecution(ctx context.Context, executionID uuid.UUID) (*RetentionExecution, error) {
	if cached, ok := drm.executions.Load(executionID); ok {
		return cached.(*RetentionExecution), nil
	}
	execution, err := drm.loadExecution(ctx, executionID)
	if err != nil {
		return nil, fmt.Errorf("execution not found: %w", err)
	}
	return execution, nil
}

// ListExecutions returns recent executions
func (drm *DataRetentionManager) ListExecutions(ctx context.Context, limit int) ([]*RetentionExecution, error) {
	var executions []*RetentionExecution
	count := 0
	drm.executions.Range(func(_, value interface{}) bool {
		if limit > 0 && count >= limit {
			return false
		}
		executions = append(executions, value.(*RetentionExecution))
		count++
		return true
	})
	return executions, nil
}

// RequestUserDataDeletion handles GDPR/CCPA user data deletion requests
func (drm *DataRetentionManager) RequestUserDataDeletion(ctx context.Context, userID uuid.UUID, reason string) (*RetentionExecution, error) {
	policy := &RetentionPolicy{
		ID:          uuid.New(),
		Name:        fmt.Sprintf("User Data Deletion - %s", userID.String()[:8]),
		Description: fmt.Sprintf("Delete all data for user %s - Reason: %s", userID, reason),
		DataCategory:    CategoryUserData,
		PolicyType:      PolicyTypeUserDriven,
		RetentionPeriod: 0,
		GracePeriod:     24 * time.Hour,
		ComplianceStandards: []string{"GDPR", "CCPA"},
		DataSources:     []string{"users", "sessions", "devices", "otp_logs", "audit_logs"},
		Conditions:      RetentionConditions{
			UserRequest:      true,
			ConsentWithdrawn: true,
			CustomConditions: map[string]string{"user_id": userID.String()},
		},
		DeletionStrategy: DeletionStrategy{
			Method:             MethodAnonymize,
			BatchSize:          100,
			MaxConcurrency:     1,
			VerifyDeletion:     true,
			CreateBackup:       true,
			BackupRetention:    7 * 24 * time.Hour,
			EncryptBackup:      true,
			AuditDeletion:      true,
			NotifyOnCompletion: true,
		},
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata:  models.JSONMap{
			"user_id":         userID.String(),
			"deletion_reason": reason,
			"request_type":    "user_data_deletion",
		},
	}
	return drm.executor.Execute(ctx, policy, false)
}

// GetUserDataRetentionInfo returns retention information for a user
func (drm *DataRetentionManager) GetUserDataRetentionInfo(ctx context.Context, userID uuid.UUID) (*UserRetentionInfo, error) {
	info := &UserRetentionInfo{
		UserID:       userID,
		DataCategories: make(map[DataCategory]CategoryRetentionInfo),
		GeneratedAt:    time.Now(),
	}
	user, err := drm.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	info.UserCreatedAt = user.CreatedAt
	if user.LastLoginAt != nil {
		info.LastActivity = user.LastLoginAt
	} else {
		info.LastActivity = &user.CreatedAt
	}

	for category, cp := range drm.config.CategoryPolicies {
		ci := CategoryRetentionInfo{
			RetentionPeriod: cp.DefaultRetention,
			DeletionMethod:  cp.DeletionMethod,
			EstimatedSize:   0,
		}
		var ref time.Time
		switch category {
		case CategoryUserData:
			ref = user.CreatedAt
		case CategorySessionData, CategoryDeviceData:
			ref = *info.LastActivity
		default:
			ref = time.Now()
		}
		ci.DeleteAfter = ref.Add(cp.DefaultRetention)
		ci.EstimatedSize = drm.estimateUserDataSize(ctx, userID, category)
		info.DataCategories[category] = ci
	}
	return info, nil
}

// createDefaultPolicies creates and stores default retention policies if they don't exist
func (drm *DataRetentionManager) createDefaultPolicies() error {
	ctx := context.Background()

	defaultPolicies := []*RetentionPolicy{
		{
			Name: "Audit Logs Retention",
			Description: "Retain audit logs for compliance and security analysis",
			DataCategory: CategoryAuditLogs,
			PolicyType: PolicyTypeFixed,
			RetentionPeriod: 90 * 24 * time.Hour,
			ComplianceStandards: []string{"GDPR", "SOX", "ISO27001"},
			DataSources: []string{"audit-*"},
			DeletionStrategy: DeletionStrategy{
				Method: MethodHardDelete,
				BatchSize: 1000,
				MaxConcurrency: 3,
				AuditDeletion: true,
			},
			Enabled: true,
		},
		{
			Name: "Session Data Retention",
			Description: "Clean up expired session data",
			DataCategory: CategorySessionData,
			PolicyType: PolicyTypeRolling,
			RetentionPeriod: 30 * 24 * time.Hour,
			DataSources: []string{"session:*"},
			DeletionStrategy: DeletionStrategy{
				Method: MethodHardDelete,
				BatchSize: 500,
				MaxConcurrency: 2,
			},
			Enabled: true,
		},
		{
			Name: "OTP Data Retention",
			Description: "Clean up old OTP verification records",
			DataCategory: CategoryOTPData,
			PolicyType: PolicyTypeFixed,
			RetentionPeriod: 7 * 24 * time.Hour,
			DataSources: []string{"otp_verifications"},
			DeletionStrategy: DeletionStrategy{
				Method: MethodHardDelete,
				BatchSize: 1000,
				MaxConcurrency: 2,
			},
			Enabled: true,
		},
		{
			Name: "Device Data Retention",
			Description: "Retain device fingerprint data for security analysis",
			DataCategory: CategoryDeviceData,
			PolicyType: PolicyTypeConditional,
			RetentionPeriod: 180 * 24 * time.Hour,
			Conditions: RetentionConditions{
				UserStatus: []string{"active"},
				DataAge: &[]time.Duration{90 * 24 * time.Hour}[0], // Note: corrected way to pass a pointer to a literal
			},
			DataSources: []string{"device:*"},
			DeletionStrategy: DeletionStrategy{
				Method: MethodSoftDelete,
				BatchSize: 200,
				MaxConcurrency: 1,
				AuditDeletion: true,
			},
			Enabled: true,
		},
		{
			Name: "Inactive User Cleanup",
			Description: "Remove data for inactive users per GDPR requirements",
			DataCategory: CategoryUserData,
			PolicyType: PolicyTypeConditional,
			RetentionPeriod: 3 * 365 * 24 * time.Hour,
			ComplianceStandards: []string{"GDPR", "CCPA"},
			Conditions: RetentionConditions{
				UserStatus: []string{"inactive"},
				DataAge: &[]time.Duration{2 * 365 * 24 * time.Hour}[0], // Note: corrected way to pass a pointer to a literal
			},
			DataSources: []string{"users", "user_profiles", "user_sessions"},
			DeletionStrategy: DeletionStrategy{
				Method: MethodAnonymize,
				BatchSize: 50,
				MaxConcurrency: 1,
				CreateBackup: true,
				BackupRetention: 7 * 24 * time.Hour,
				EncryptBackup: true,
				AuditDeletion: true,
				NotifyOnCompletion: true,
			},
			Enabled: drm.config.ComplianceSettings.GDPR.Enabled &&
				drm.config.ComplianceSettings.GDPR.AutoDeleteInactiveUsers,
		},
	}

	for _, p := range defaultPolicies {
		existing, err := drm.findPolicyByName(ctx, p.Name)
		if err == nil && existing != nil {
			continue
		}
		if _, err := drm.CreatePolicy(ctx, p, uuid.Nil); err != nil {
			logger.Error("Failed to create default policy", "name", p.Name, "error", err)
		} else {
			logger.Info("Created default retention policy", "name", p.Name)
		}
	}
	return nil
}

// Data size estimation
func (drm *DataRetentionManager) estimateUserDataSize(ctx context.Context, userID uuid.UUID, category DataCategory) int64 {
	switch category {
	case CategoryUserData:
		return 1024
	case CategorySessionData:
		return 2048
	case CategoryDeviceData:
		return 512
	case CategoryAuditLogs:
		return 10240
	case CategoryOTPData:
		return 256
	default:
		return 1024
	}
}

// Storage operations
func (drm *DataRetentionManager) storePolicy(ctx context.Context, policy *RetentionPolicy) error {
	key := fmt.Sprintf("retention:policy:%s", policy.ID.String())
	return drm.redis.SetJSON(ctx, key, policy, 0)
}

func (drm *DataRetentionManager) loadPolicy(ctx context.Context, policyID uuid.UUID) (*RetentionPolicy, error) {
	key := fmt.Sprintf("retention:policy:%s", policyID.String())
	var policy RetentionPolicy
	if err := drm.redis.GetJSON(ctx, key, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func (drm *DataRetentionManager) removePolicy(ctx context.Context, policyID uuid.UUID) error {
	key := fmt.Sprintf("retention:policy:%s", policyID.String())
	return drm.redis.Del(ctx, key).Err()
}

func (drm *DataRetentionManager) loadPolicies() error {
	ctx := context.Background()
	keys, err := drm.redis.Keys(ctx, "retention:policy:*").Result()
	if err != nil {
		return err
	}
	for _, key := range keys {
		var policy RetentionPolicy
		if err := drm.redis.GetJSON(ctx, key, &policy); err != nil {
			logger.Warn("Failed to load retention policy", "key", key, "error", err)
			continue
		}
		drm.policies.Store(policy.ID, &policy)
		drm.updateStats(func(s *RetentionStats) {
			s.TotalPolicies++
			if policy.Enabled {
				s.ActivePolicies++
			}
		})
	}
	return nil
}

func (drm *DataRetentionManager) findPolicyByName(ctx context.Context, name string) (*RetentionPolicy, error) {
	var found *RetentionPolicy
	drm.policies.Range(func(_, value interface{}) bool {
		p := value.(*RetentionPolicy)
		if p.Name == name {
			found = p
			return false
		}
		return true
	})
	if found == nil {
		return nil, fmt.Errorf("policy not found")
	}
	return found, nil
}

func (drm *DataRetentionManager) storeExecution(ctx context.Context, execution *RetentionExecution) error {
	key := fmt.Sprintf("retention:execution:%s", execution.ID.String())
	return drm.redis.SetJSON(ctx, key, execution, 90*24*time.Hour)
}

func (drm *DataRetentionManager) loadExecution(ctx context.Context, executionID uuid.UUID) (*RetentionExecution, error) {
	key := fmt.Sprintf("retention:execution:%s", executionID.String())
	var execution RetentionExecution
	if err := drm.redis.GetJSON(ctx, key, &execution); err != nil {
		return nil, err
	}
	return &execution, nil
}

func (drm *DataRetentionManager) validatePolicy(policy *RetentionPolicy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	if policy.DataCategory == "" {
		return fmt.Errorf("data category is required")
	}
	if policy.RetentionPeriod < drm.config.MinRetention {
		return fmt.Errorf("retention period cannot be less than %v", drm.config.MinRetention)
	}
	if policy.RetentionPeriod > drm.config.MaxRetention {
		return fmt.Errorf("retention period cannot be more than %v", drm.config.MaxRetention)
	}
	if len(policy.DataSources) == 0 {
		return fmt.Errorf("at least one data source is required")
	}
	return nil
}

func (drm *DataRetentionManager) updateStats(update func(*RetentionStats)) {
	drm.statsMu.Lock()
	defer drm.statsMu.Unlock()
	update(&drm.stats)
}

// GetStats returns retention statistics
func (drm *DataRetentionManager) GetStats() RetentionStats {
	drm.statsMu.RLock()
	defer drm.statsMu.RUnlock()
	return drm.stats
}

// UserRetentionInfo represents retention information for a specific user
type UserRetentionInfo struct {
	UserID         uuid.UUID                   `json:"user_id"`
	UserCreatedAt  time.Time                   `json:"user_created_at"`
	LastActivity   *time.Time                  `json:"last_activity,omitempty"`
	DataCategories map[DataCategory]CategoryRetentionInfo `json:"data_categories"`
	GeneratedAt    time.Time                   `json:"generated_at"`
}

// CategoryRetentionInfo represents retention info for a data category
type CategoryRetentionInfo struct {
	RetentionPeriod  time.Duration    `json:"retention_period"`
	DeleteAfter      time.Time        `json:"delete_after"`
	DeletionMethod   DeletionMethod   `json:"deletion_method"`
	EstimatedSize    int64            `json:"estimated_size_bytes"`
}