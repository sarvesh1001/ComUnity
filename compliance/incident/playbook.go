package incident

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ComUnity/auth-service/internal/models"
	"github.com/ComUnity/auth-service/internal/util/logger"
)

// Playbook represents an automated incident response playbook
type Playbook struct {
	ID                uuid.UUID          `json:"id"`
	Name              string             `json:"name"`
	Description       string             `json:"description"`
	Category          IncidentCategory   `json:"category"`
	Severity          []IncidentSeverity `json:"severity"`
	Version           string             `json:"version"`
	TriggerConditions []TriggerCondition `json:"trigger_conditions"`
	Steps             []PlaybookStep     `json:"steps"`
	AutoExecute       bool               `json:"auto_execute"`
	RequireApproval   bool               `json:"require_approval"`
	Timeout           time.Duration      `json:"timeout"`
	MaxRetries        int               `json:"max_retries"`
	CreatedBy         uuid.UUID          `json:"created_by"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
	Enabled           bool               `json:"enabled"`
	Tags              []string           `json:"tags"`
	Metadata          models.JSONMap     `json:"metadata"`
}

// TriggerCondition defines when a playbook should be activated
type TriggerCondition struct {
	Field    string      `json:"field"`    // incident field to check
	Operator string      `json:"operator"` // equals, contains, greater_than, etc.
	Value    interface{} `json:"value"`    // value to compare against
	Required bool        `json:"required"` // must match for playbook to trigger
}

// PlaybookStep represents a single step in a playbook
type PlaybookStep struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Action          string                 `json:"action"` // isolate_user, block_ip, send_alert, etc.
	Parameters      map[string]interface{} `json:"parameters"`
	DependsOn       []string               `json:"depends_on"` // Step IDs that must complete first
	Timeout         time.Duration          `json:"timeout"`
	MaxRetries      int                    `json:"max_retries"`
	ContinueOnError bool                   `json:"continue_on_error"`
	RequireApproval bool                   `json:"require_approval"`
	Enabled         bool                   `json:"enabled"`
}

// PlaybookExecution tracks the execution of a playbook
type PlaybookExecution struct {
	ID          uuid.UUID               `json:"id"`
	PlaybookID  uuid.UUID               `json:"playbook_id"`
	IncidentID  uuid.UUID               `json:"incident_id"`
	Status      PlaybookExecutionStatus `json:"status"`
	StartedAt   time.Time               `json:"started_at"`
	CompletedAt *time.Time              `json:"completed_at,omitempty"`
	Steps       []StepExecution         `json:"steps"`
	Error       string                  `json:"error,omitempty"`
	ExecutedBy  string                  `json:"executed_by"`
	ApprovedBy  *uuid.UUID              `json:"approved_by,omitempty"`
	Metadata    models.JSONMap          `json:"metadata"`
}

// PlaybookExecutionStatus represents the status of playbook execution
type PlaybookExecutionStatus string

const (
	ExecutionPending         PlaybookExecutionStatus = "pending"
	ExecutionRunning         PlaybookExecutionStatus = "running"
	ExecutionCompleted       PlaybookExecutionStatus = "completed"
	ExecutionFailed          PlaybookExecutionStatus = "failed"
	ExecutionCancelled       PlaybookExecutionStatus = "cancelled"
	ExecutionAwaitingApproval PlaybookExecutionStatus = "awaiting_approval"
)

// StepExecution tracks the execution of a single playbook step
type StepExecution struct {
	StepID      string                 `json:"step_id"`
	Status      StepExecutionStatus    `json:"status"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Result      map[string]interface{} `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Retries     int                    `json:"retries"`
}

// StepExecutionStatus represents the status of step execution
type StepExecutionStatus string

const (
	StepPending          StepExecutionStatus = "pending"
	StepRunning          StepExecutionStatus = "running"
	StepCompleted        StepExecutionStatus = "completed"
	StepFailed           StepExecutionStatus = "failed"
	StepSkipped          StepExecutionStatus = "skipped"
	StepAwaitingApproval StepExecutionStatus = "awaiting_approval"
)

// PlaybookRegistry manages playbooks for a specific category
type PlaybookRegistry struct {
	category  IncidentCategory
	playbooks map[uuid.UUID]*Playbook
	manager   *IncidentManager
}

// NewPlaybookRegistry creates a new playbook registry
func NewPlaybookRegistry(category IncidentCategory, manager *IncidentManager) *PlaybookRegistry {
	return &PlaybookRegistry{
		category:  category,
		playbooks: make(map[uuid.UUID]*Playbook),
		manager:   manager,
	}
}

// RegisterPlaybook registers a new playbook
func (pr *PlaybookRegistry) RegisterPlaybook(playbook *Playbook) error {
	if playbook.Category != pr.category {
		return fmt.Errorf("playbook category mismatch: expected %s, got %s", pr.category, playbook.Category)
	}

	pr.playbooks[playbook.ID] = playbook

	logger.Info("Playbook registered",
		"playbook_id", playbook.ID,
		"name", playbook.Name,
		"category", playbook.Category)

	return nil
}

// FindMatchingPlaybooks finds playbooks that match an incident
func (pr *PlaybookRegistry) FindMatchingPlaybooks(incident *Incident) []*Playbook {
	var matching []*Playbook

	for _, playbook := range pr.playbooks {
		if !playbook.Enabled {
			continue
		}

		if pr.matches(playbook, incident) {
			matching = append(matching, playbook)
		}
	}

	return matching
}

// matches checks if a playbook matches an incident
func (pr *PlaybookRegistry) matches(playbook *Playbook, incident *Incident) bool {
	// Check category
	if playbook.Category != incident.Category {
		return false
	}

	// Check severity
	severityMatch := false
	for _, severity := range playbook.Severity {
		if severity == incident.Severity {
			severityMatch = true
			break
		}
	}
	if !severityMatch {
		return false
	}

	// Check trigger conditions
	for _, condition := range playbook.TriggerConditions {
		if condition.Required && !pr.evaluateCondition(condition, incident) {
			return false
		}
	}

	return true
}

// evaluateCondition evaluates a trigger condition against an incident
func (pr *PlaybookRegistry) evaluateCondition(condition TriggerCondition, incident *Incident) bool {
	var fieldValue interface{}

	// Extract field value from incident
	switch condition.Field {
	case "severity":
		fieldValue = string(incident.Severity)
	case "category":
		fieldValue = string(incident.Category)
	case "affected_users_count":
		fieldValue = len(incident.AffectedUsers)
	case "affected_systems_count":
		fieldValue = len(incident.AffectedSystems)
	case "data_compromised":
		fieldValue = incident.DataCompromised
	case "compliance_relevant":
		fieldValue = incident.ComplianceRelevant
	case "escalation_level":
		fieldValue = incident.EscalationLevel
	default:
		// Check metadata
		if val, ok := incident.Metadata[condition.Field]; ok {
			fieldValue = val
		}
	}

	// Evaluate condition
	return pr.evaluateOperator(fieldValue, condition.Operator, condition.Value)
}

// evaluateOperator evaluates an operator condition
func (pr *PlaybookRegistry) evaluateOperator(fieldValue interface{}, operator string, expectedValue interface{}) bool {
	switch operator {
	case "equals":
		return fieldValue == expectedValue
	case "not_equals":
		return fieldValue != expectedValue
	case "contains":
		if str, ok := fieldValue.(string); ok {
			if substr, ok := expectedValue.(string); ok {
				return contains(str, substr)
			}
		}
		return false
	case "greater_than":
		return compareNumbers(fieldValue, expectedValue) > 0
	case "less_than":
		return compareNumbers(fieldValue, expectedValue) < 0
	case "greater_equal":
		return compareNumbers(fieldValue, expectedValue) >= 0
	case "less_equal":
		return compareNumbers(fieldValue, expectedValue) <= 0
	default:
		return false
	}
}

// Helper functions
func contains(str, substr string) bool {
	// substring check (was suffix before)
	return len(substr) == 0 || (len(str) >= len(substr) && ( // fast path
		// quick scan
		func() bool {
			// naive contains to avoid importing strings
			for i := 0; i+len(substr) <= len(str); i++ {
				if str[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}()))
}

func compareNumbers(a, b interface{}) int {
	toFloat := func(x interface{}) (float64, bool) {
		switch v := x.(type) {
		case int:
			return float64(v), true
		case int8:
			return float64(v), true
		case int16:
			return float64(v), true
		case int32:
			return float64(v), true
		case int64:
			return float64(v), true
		case uint:
			return float64(v), true
		case uint8:
			return float64(v), true
		case uint16:
			return float64(v), true
		case uint32:
			return float64(v), true
		case uint64:
			return float64(v), true
		case float32:
			return float64(v), true
		case float64:
			return v, true
		default:
			return 0, false
		}
	}

	af, okA := toFloat(a)
	bf, okB := toFloat(b)
	if !okA || !okB {
		// not comparable -> treat as equal
		return 0
	}

	if af > bf {
		return 1
	} else if af < bf {
		return -1
	}
	return 0
}

// Default playbooks registration

func (im *IncidentManager) registerDefaultPlaybooks() {
	categories := []IncidentCategory{
		CategoryAuthFailure,
		CategorySuspiciousActivity,
		CategoryDataBreach,
		CategoryComplianceViolation,
		CategorySystemFailure,
		CategorySecurityThreat,
	}

	for _, category := range categories {
		registry := NewPlaybookRegistry(category, im)
		im.playbooks[category] = registry

		// Register default playbooks for each category
		switch category {
		case CategoryAuthFailure:
			im.registerAuthFailurePlaybooks(registry)
		case CategorySuspiciousActivity:
			im.registerSuspiciousActivityPlaybooks(registry)
		case CategoryDataBreach:
			im.registerDataBreachPlaybooks(registry)
		case CategoryComplianceViolation:
			im.registerComplianceViolationPlaybooks(registry)
		case CategorySystemFailure:
			im.registerSystemFailurePlaybooks(registry)
		case CategorySecurityThreat:
			im.registerSecurityThreatPlaybooks(registry)
		}
	}
}

func (im *IncidentManager) registerAuthFailurePlaybooks(registry *PlaybookRegistry) {
	// High-volume auth failure playbook
	authFailurePlaybook := &Playbook{
		ID:          uuid.New(),
		Name:        "High Volume Authentication Failures",
		Description: "Responds to high volume of authentication failures from single source",
		Category:    CategoryAuthFailure,
		Severity:    []IncidentSeverity{SeverityHigh, SeverityCritical},
		Version:     "1.0",
		TriggerConditions: []TriggerCondition{
			{Field: "affected_users_count", Operator: "greater_than", Value: 10, Required: true},
		},
		Steps: []PlaybookStep{
			{
				ID:          "analyze_source",
				Name:        "Analyze Attack Source",
				Description: "Analyze the source of authentication failures",
				Action:      "analyze_auth_source",
				Parameters: map[string]interface{}{
					"lookback_minutes": 60,
					"threshold":        10,
				},
				Timeout: 5 * time.Minute,
			},
			{
				ID:          "block_suspicious_ips",
				Name:        "Block Suspicious IPs",
				Description: "Temporarily block IPs with high failure rates",
				Action:      "block_ips",
				Parameters: map[string]interface{}{
					"duration_minutes":  60,
					"failure_threshold": 20,
				},
				DependsOn:  []string{"analyze_source"},
				Timeout:    2 * time.Minute,
				MaxRetries: 3,
			},
			{
				ID:          "notify_security_team",
				Name:        "Notify Security Team",
				Description: "Send alert to security team",
				Action:      "send_notification",
				Parameters: map[string]interface{}{
					"channel":  "security",
					"priority": "high",
				},
				DependsOn: []string{"analyze_source"},
				Timeout:   1 * time.Minute,
			},
		},
		AutoExecute: true,
		Timeout:     15 * time.Minute,
		MaxRetries:  2,
		CreatedAt:   time.Now(),
		Enabled:     true,
	}

	_ = registry.RegisterPlaybook(authFailurePlaybook)
}

func (im *IncidentManager) registerSuspiciousActivityPlaybooks(registry *PlaybookRegistry) {
	// Suspicious device activity playbook
	suspiciousDevicePlaybook := &Playbook{
		ID:          uuid.New(),
		Name:        "Suspicious Device Activity",
		Description: "Responds to suspicious device behavior patterns",
		Category:    CategorySuspiciousActivity,
		Severity:    []IncidentSeverity{SeverityMedium, SeverityHigh},
		Version:     "1.0",
		TriggerConditions: []TriggerCondition{
			{Field: "risk_score", Operator: "greater_than", Value: 0.7, Required: true},
		},
		Steps: []PlaybookStep{
			{
				ID:          "analyze_device_behavior",
				Name:        "Analyze Device Behavior",
				Description: "Deep analysis of device behavior patterns",
				Action:      "analyze_device_behavior",
				Parameters: map[string]interface{}{
					"lookback_hours": 24,
					"risk_threshold": 0.7,
				},
				Timeout: 10 * time.Minute,
			},
			{
				ID:          "require_additional_auth",
				Name:        "Require Additional Authentication",
				Description: "Force additional authentication for suspicious devices",
				Action:      "require_additional_auth",
				Parameters: map[string]interface{}{
					"auth_method":   "otp",
					"duration_hours": 24,
				},
				DependsOn: []string{"analyze_device_behavior"},
				Timeout:   5 * time.Minute,
			},
			{
				ID:          "monitor_enhanced",
				Name:        "Enhanced Monitoring",
				Description: "Enable enhanced monitoring for the device",
				Action:      "enable_enhanced_monitoring",
				Parameters: map[string]interface{}{
					"duration_hours": 72,
					"log_level":      "detailed",
				},
				DependsOn: []string{"analyze_device_behavior"},
				Timeout:   2 * time.Minute,
			},
		},
		AutoExecute: true,
		Timeout:     30 * time.Minute,
		CreatedAt:   time.Now(),
		Enabled:     true,
	}

	_ = registry.RegisterPlaybook(suspiciousDevicePlaybook)
}

func (im *IncidentManager) registerDataBreachPlaybooks(registry *PlaybookRegistry) {
	// Data breach response playbook
	dataBreachPlaybook := &Playbook{
		ID:          uuid.New(),
		Name:        "Data Breach Response",
		Description: "Comprehensive response to potential data breach incidents",
		Category:    CategoryDataBreach,
		Severity:    []IncidentSeverity{SeverityHigh, SeverityCritical},
		Version:     "1.0",
		TriggerConditions: []TriggerCondition{
			{Field: "data_compromised", Operator: "equals", Value: true, Required: true},
		},
		Steps: []PlaybookStep{
			{
				ID:          "immediate_containment",
				Name:        "Immediate Containment",
				Description: "Immediate actions to contain the breach",
				Action:      "contain_breach",
				Parameters: map[string]interface{}{
					"isolate_affected_systems": true,
					"revoke_access_tokens":     true,
				},
				Timeout:         5 * time.Minute,
				MaxRetries:      3,
				ContinueOnError: false,
			},
			{
				ID:              "assess_scope",
				Name:            "Assess Breach Scope",
				Description:     "Determine the scope and impact of the breach",
				Action:          "assess_breach_scope",
				Parameters: map[string]interface{}{
					"investigate_timeframe":  "72h",
					"data_sensitivity_check": true,
				},
				DependsOn:       []string{"immediate_containment"},
				Timeout:         30 * time.Minute,
				RequireApproval: true,
			},
			{
				ID:              "notify_authorities",
				Name:            "Notify Regulatory Authorities",
				Description:     "Notify relevant authorities as required by law",
				Action:          "notify_authorities",
				Parameters: map[string]interface{}{
					"gdpr_notification": true,
					"local_authorities": true,
					"deadline_hours":    72,
				},
				DependsOn:       []string{"assess_scope"},
				Timeout:         4 * time.Hour,
				RequireApproval: true,
			},
			{
				ID:          "customer_notification",
				Name:        "Customer Notification",
				Description: "Prepare and send customer notifications",
				Action:      "notify_customers",
				Parameters: map[string]interface{}{
					"template": "data_breach",
					"priority": "high",
					"channels": []string{"email", "app_notification"},
				},
				DependsOn:       []string{"assess_scope"},
				Timeout:         2 * time.Hour,
				RequireApproval: true,
			},
			{
				ID:          "forensic_investigation",
				Name:        "Start Forensic Investigation",
				Description: "Begin detailed forensic investigation",
				Action:      "start_forensics",
				Parameters: map[string]interface{}{
					"preserve_evidence": true,
					"external_experts":  false,
				},
				DependsOn: []string{"immediate_containment"},
				Timeout:   1 * time.Hour,
			},
		},
		AutoExecute:     false, // Requires manual approval due to severity
		RequireApproval: true,
		Timeout:         24 * time.Hour,
		CreatedAt:       time.Now(),
		Enabled:         true,
	}

	_ = registry.RegisterPlaybook(dataBreachPlaybook)
}

func (im *IncidentManager) registerComplianceViolationPlaybooks(registry *PlaybookRegistry) {
	// GDPR compliance violation playbook
	gdprViolationPlaybook := &Playbook{
		ID:          uuid.New(),
		Name:        "GDPR Compliance Violation Response",
		Description: "Responds to potential GDPR compliance violations",
		Category:    CategoryComplianceViolation,
		Severity:    []IncidentSeverity{SeverityMedium, SeverityHigh, SeverityCritical},
		Version:     "1.0",
		TriggerConditions: []TriggerCondition{
			{Field: "compliance_relevant", Operator: "equals", Value: true, Required: true},
			{Field: "regulation", Operator: "contains", Value: "GDPR", Required: false},
		},
		Steps: []PlaybookStep{
			{
				ID:          "assess_violation",
				Name:        "Assess GDPR Violation",
				Description: "Assess the nature and scope of GDPR violation",
				Action:      "assess_gdpr_violation",
				Parameters: map[string]interface{}{
					"check_data_processing": true,
					"check_consent":         true,
					"check_data_transfer":   true,
				},
				Timeout: 15 * time.Minute,
			},
			{
				ID:          "document_violation",
				Name:        "Document Violation",
				Description: "Create detailed documentation of the violation",
				Action:      "document_violation",
				Parameters: map[string]interface{}{
					"include_evidence": true,
					"legal_assessment": true,
				},
				DependsOn: []string{"assess_violation"},
				Timeout:   20 * time.Minute,
			},
			{
				ID:              "remediate_violation",
				Name:            "Remediate Violation",
				Description:     "Take corrective actions to remediate the violation",
				Action:          "remediate_gdpr_violation",
				Parameters: map[string]interface{}{
					"stop_processing": true,
					"notify_dpo":      true,
				},
				DependsOn:       []string{"assess_violation"},
				Timeout:         30 * time.Minute,
				RequireApproval: true,
			},
			{
				ID:              "prepare_breach_notification",
				Name:            "Prepare Breach Notification",
				Description:     "Prepare notification to supervisory authority if required",
				Action:          "prepare_breach_notification",
				Parameters: map[string]interface{}{
					"deadline_hours": 72,
					"template":       "gdpr_breach",
				},
				DependsOn:       []string{"document_violation"},
				Timeout:         2 * time.Hour,
				RequireApproval: true,
			},
		},
		AutoExecute:     false,
		RequireApproval: true,
		Timeout:         8 * time.Hour,
		CreatedAt:       time.Now(),
		Enabled:         true,
	}

	_ = registry.RegisterPlaybook(gdprViolationPlaybook)
}

func (im *IncidentManager) registerSystemFailurePlaybooks(registry *PlaybookRegistry) {
	// High availability system failure playbook
	systemFailurePlaybook := &Playbook{
		ID:          uuid.New(),
		Name:        "Critical System Failure Response",
		Description: "Responds to critical system failures affecting availability",
		Category:    CategorySystemFailure,
		Severity:    []IncidentSeverity{SeverityHigh, SeverityCritical},
		Version:     "1.0",
		Steps: []PlaybookStep{
			{
				ID:          "check_system_health",
				Name:        "Check System Health",
				Description: "Comprehensive system health check",
				Action:      "check_system_health",
				Parameters: map[string]interface{}{
					"check_dependencies": true,
					"check_resources":    true,
				},
				Timeout: 5 * time.Minute,
			},
			{
				ID:          "attempt_auto_recovery",
				Name:        "Attempt Automatic Recovery",
				Description: "Try automatic recovery procedures",
				Action:      "attempt_recovery",
				Parameters: map[string]interface{}{
					"restart_services": true,
					"clear_caches":     true,
					"scale_resources":  true,
				},
				DependsOn:  []string{"check_system_health"},
				Timeout:    10 * time.Minute,
				MaxRetries: 2,
			},
			{
				ID:              "escalate_to_oncall",
				Name:            "Escalate to On-Call",
				Description:     "Escalate to on-call engineer if auto-recovery fails",
				Action:          "escalate_oncall",
				Parameters: map[string]interface{}{
					"team":     "platform",
					"priority": "critical",
				},
				DependsOn:       []string{"attempt_auto_recovery"},
				Timeout:         5 * time.Minute,
				ContinueOnError: true,
			},
			{
				ID:          "status_page_update",
				Name:        "Update Status Page",
				Description: "Update public status page with incident information",
				Action:      "update_status_page",
				Parameters: map[string]interface{}{
					"status":  "degraded_performance",
					"message": "Investigating system issues",
				},
				DependsOn: []string{"check_system_health"},
				Timeout:   2 * time.Minute,
			},
		},
		AutoExecute: true,
		Timeout:     30 * time.Minute,
		CreatedAt:   time.Now(),
		Enabled:     true,
	}

	_ = registry.RegisterPlaybook(systemFailurePlaybook)
}

func (im *IncidentManager) registerSecurityThreatPlaybooks(registry *PlaybookRegistry) {
	// Security threat response playbook
	securityThreatPlaybook := &Playbook{
		ID:          uuid.New(),
		Name:        "Security Threat Response",
		Description: "General security threat response procedures",
		Category:    CategorySecurityThreat,
		Severity:    []IncidentSeverity{SeverityMedium, SeverityHigh, SeverityCritical},
		Version:     "1.0",
		Steps: []PlaybookStep{
			{
				ID:          "threat_assessment",
				Name:        "Threat Assessment",
				Description: "Assess the nature and severity of the security threat",
				Action:      "assess_threat",
				Parameters: map[string]interface{}{
					"threat_intelligence": true,
					"impact_analysis":     true,
				},
				Timeout: 10 * time.Minute,
			},
			{
				ID:          "isolate_threat",
				Name:        "Isolate Threat",
				Description: "Isolate the threat to prevent further damage",
				Action:      "isolate_threat",
				Parameters: map[string]interface{}{
					"block_sources":     true,
					"quarantine_assets": true,
				},
				DependsOn: []string{"threat_assessment"},
				Timeout:   5 * time.Minute,
			},
			{
				ID:          "collect_evidence",
				Name:        "Collect Evidence",
				Description: "Collect evidence for further analysis and potential legal action",
				Action:      "collect_evidence",
				Parameters: map[string]interface{}{
					"preserve_logs":   true,
					"network_captures": true,
				},
				DependsOn: []string{"threat_assessment"},
				Timeout:   15 * time.Minute,
			},
			{
				ID:          "notify_security_team",
				Name:        "Notify Security Team",
				Description: "Alert the security team for manual investigation",
				Action:      "notify_team",
				Parameters: map[string]interface{}{
					"team":       "security",
					"escalation": "immediate",
				},
				DependsOn: []string{"isolate_threat"},
				Timeout:   2 * time.Minute,
			},
		},
		AutoExecute: true,
		Timeout:     45 * time.Minute,
		CreatedAt:   time.Now(),
		Enabled:     true,
	}

	_ = registry.RegisterPlaybook(securityThreatPlaybook)
}