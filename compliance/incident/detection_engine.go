package incident

import (
    
    "fmt"
    "strings"
    "time"


    "github.com/ComUnity/auth-service/internal/telemetry"
    "github.com/ComUnity/auth-service/internal/util/logger"
)

// DetectionEngine analyzes events to identify potential incidents
type DetectionEngine struct {
    manager         *IncidentManager
    detectionRules  map[string]*DetectionRule
    thresholds      map[string]*ThresholdTracker
}

// DetectionRule defines a rule for detecting incidents
type DetectionRule struct {
    ID              string               `json:"id"`
    Name            string               `json:"name"`
    Description     string               `json:"description"`
    EventTypes      []string             `json:"event_types"`
    Conditions      []DetectionCondition `json:"conditions"`
    Category        IncidentCategory     `json:"category"`
    Severity        IncidentSeverity     `json:"severity"`
    TimeWindow      time.Duration        `json:"time_window"`
    Threshold       int                  `json:"threshold"`
    Enabled         bool                 `json:"enabled"`
}

// DetectionCondition defines a condition for event detection
type DetectionCondition struct {
    Field    string      `json:"field"`
    Operator string      `json:"operator"`
    Value    interface{} `json:"value"`
    Weight   float64     `json:"weight"` // For scoring
}

// ThresholdTracker tracks event counts over time windows
type ThresholdTracker struct {
    events     []time.Time
    timeWindow time.Duration
    threshold  int
}

// NewDetectionEngine creates a new detection engine
func NewDetectionEngine(manager *IncidentManager) *DetectionEngine {
    engine := &DetectionEngine{
        manager:        manager,
        detectionRules: make(map[string]*DetectionRule),
        thresholds:     make(map[string]*ThresholdTracker),
    }
    
    // Register default detection rules
    engine.registerDefaultRules()
    
    return engine
}

// AnalyzeEvent analyzes an event and returns any detected incidents
func (de *DetectionEngine) AnalyzeEvent(event interface{}) []*Incident {
    var incidents []*Incident
    
    // Analyze different event types
    switch e := event.(type) {
    case telemetry.DeviceAuditEvent:
        incidents = append(incidents, de.analyzeDeviceEvent(e)...)
    case telemetry.OTPAuditEvent:
        incidents = append(incidents, de.analyzeOTPEvent(e)...)
    default:
        // Handle unknown event types
        logger.Debug("Unknown event type", "type", fmt.Sprintf("%T", event))
    }
    
    return incidents
}

// analyzeDeviceEvent analyzes device audit events
func (de *DetectionEngine) analyzeDeviceEvent(event telemetry.DeviceAuditEvent) []*Incident {
    var incidents []*Incident
    
    // Check each detection rule
    for _, rule := range de.detectionRules {
        if !rule.Enabled {
            continue
        }
        
        // Check if rule applies to this event type
        if !de.eventTypeMatches(rule.EventTypes, "device_audit") {
            continue
        }
        
        if de.evaluateDeviceEventRule(rule, event) {
            incident := de.createIncidentFromRule(rule, event)
            incidents = append(incidents, incident)
        }
    }
    
    return incidents
}

// analyzeOTPEvent analyzes OTP audit events
func (de *DetectionEngine) analyzeOTPEvent(event telemetry.OTPAuditEvent) []*Incident {
    var incidents []*Incident
    
    // Check each detection rule
    for _, rule := range de.detectionRules {
        if !rule.Enabled {
            continue
        }
        
        // Check if rule applies to this event type
        if !de.eventTypeMatches(rule.EventTypes, "otp_audit") {
            continue
        }
        
        if de.evaluateOTPEventRule(rule, event) {
            incident := de.createIncidentFromRule(rule, event)
            incidents = append(incidents, incident)
        }
    }
    
    return incidents
}

// evaluateDeviceEventRule evaluates a rule against a device event
func (de *DetectionEngine) evaluateDeviceEventRule(rule *DetectionRule, event telemetry.DeviceAuditEvent) bool {
    score := 0.0
    totalWeight := 0.0
    
    for _, condition := range rule.Conditions {
        var fieldValue interface{}
        
        // Extract field value from event
        switch condition.Field {
        case "status":
            fieldValue = event.Status
        case "method":
            fieldValue = event.Method
        case "path":
            fieldValue = event.Path
        case "duration_ms":
            fieldValue = event.DurationMs
        case "risk_score":
            fieldValue = event.RiskScore
        case "decision":
            fieldValue = event.Decision
        case "platform":
            fieldValue = event.Platform
        case "device_key":
            fieldValue = event.DeviceKey
        default:
            continue
        }
        
        if de.evaluateCondition(condition, fieldValue) {
            score += condition.Weight
        }
        totalWeight += condition.Weight
    }
    
    // Check if weighted score meets threshold
    if totalWeight > 0 {
        normalizedScore := score / totalWeight
        if normalizedScore >= 0.7 { // 70% threshold
            return de.checkThreshold(rule, event.Timestamp)
        }
    }
    
    return false
}

// evaluateOTPEventRule evaluates a rule against an OTP event
func (de *DetectionEngine) evaluateOTPEventRule(rule *DetectionRule, event telemetry.OTPAuditEvent) bool {
    score := 0.0
    totalWeight := 0.0
    
    for _, condition := range rule.Conditions {
        var fieldValue interface{}
        
        // Extract field value from event
        switch condition.Field {
        case "status":
            fieldValue = event.Status
        case "method":
            fieldValue = event.Method
        case "route":
            fieldValue = event.Route
        case "duration_ms":
            fieldValue = event.DurationMs
        case "outcome":
            fieldValue = event.Outcome
        case "platform":
            fieldValue = event.Platform
        case "device_key":
            fieldValue = event.DeviceKey
        default:
            continue
        }
        
        if de.evaluateCondition(condition, fieldValue) {
            score += condition.Weight
        }
        totalWeight += condition.Weight
    }
    
    // Check if weighted score meets threshold
    if totalWeight > 0 {
        normalizedScore := score / totalWeight
        if normalizedScore >= 0.7 { // 70% threshold
            return de.checkThreshold(rule, event.Timestamp)
        }
    }
    
    return false
}

// evaluateCondition evaluates a single condition
func (de *DetectionEngine) evaluateCondition(condition DetectionCondition, fieldValue interface{}) bool {
    switch condition.Operator {
    case "equals":
        return fieldValue == condition.Value
    case "not_equals":
        return fieldValue != condition.Value
    case "contains":
        if str, ok := fieldValue.(string); ok {
            if substr, ok := condition.Value.(string); ok {
                return strings.Contains(str, substr)
            }
        }
        return false
    case "greater_than":
        return compareNumbers(fieldValue, condition.Value) > 0
    case "less_than":
        return compareNumbers(fieldValue, condition.Value) < 0
    case "greater_equal":
        return compareNumbers(fieldValue, condition.Value) >= 0
    case "less_equal":
        return compareNumbers(fieldValue, condition.Value) <= 0
    case "in_range":
        // For ranges like [400, 499] for HTTP status codes
        if rng, ok := condition.Value.([]interface{}); ok && len(rng) == 2 {
            return compareNumbers(fieldValue, rng[0]) >= 0 && compareNumbers(fieldValue, rng[1]) <= 0
        }
        return false
    default:
        return false
    }
}

// checkThreshold checks if the threshold is met within the time window
func (de *DetectionEngine) checkThreshold(rule *DetectionRule, eventTime time.Time) bool {
    tracker, exists := de.thresholds[rule.ID]
    if !exists {
        tracker = &ThresholdTracker{
            timeWindow: rule.TimeWindow,
            threshold:  rule.Threshold,
        }
        de.thresholds[rule.ID] = tracker
    }
    
    // Add current event
    tracker.events = append(tracker.events, eventTime)
    
    // Clean old events outside time window
    cutoff := eventTime.Add(-tracker.timeWindow)
    validEvents := tracker.events[:0]
    for _, eventTimestamp := range tracker.events {
        if eventTimestamp.After(cutoff) {
            validEvents = append(validEvents, eventTimestamp)
        }
    }
    tracker.events = validEvents
    
    // Check if threshold is exceeded
    return len(tracker.events) >= tracker.threshold
}

// createIncidentFromRule creates an incident from a triggered rule
func (de *DetectionEngine) createIncidentFromRule(rule *DetectionRule, event interface{}) *Incident {
    incident := &Incident{
        Title:           fmt.Sprintf("%s - %s", rule.Name, time.Now().Format("2006-01-02 15:04:05")),
        Description:     rule.Description,
        Category:        rule.Category,
        Severity:        rule.Severity,
        DetectedBy:      "detection_engine",
        DetectionMethod: rule.Name,
        SourceEvents:    []string{rule.ID}, // Could include actual event IDs
    }
    
    // Extract affected systems and users from event
    switch e := event.(type) {
    case telemetry.DeviceAuditEvent:
        incident.AffectedSystems = []string{"auth-service"}
        if e.DeviceKey != "" {
            // Could map device to user if needed
            incident.Metadata = map[string]interface{}{
                "device_key": e.DeviceKey,
                "platform":   e.Platform,
                "path":       e.Path,
                "method":     e.Method,
                "status":     e.Status,
            }
        }
    case telemetry.OTPAuditEvent:
        incident.AffectedSystems = []string{"otp-service"}
        if e.DeviceKey != "" {
            incident.Metadata = map[string]interface{}{
                "device_key": e.DeviceKey,
                "platform":   e.Platform,
                "route":      e.Route,
                "method":     e.Method,
                "status":     e.Status,
            }
        }
    }
    
    return incident
}

// eventTypeMatches checks if rule event types match the given type
func (de *DetectionEngine) eventTypeMatches(ruleTypes []string, eventType string) bool {
    if len(ruleTypes) == 0 {
        return true // No restriction
    }
    
    for _, ruleType := range ruleTypes {
        if ruleType == eventType || ruleType == "*" {
            return true
        }
    }
    
    return false
}

// registerDefaultRules registers default detection rules
func (de *DetectionEngine) registerDefaultRules() {
    rules := []*DetectionRule{
        // High volume authentication failures
        {
            ID:          "auth_failure_volume",
            Name:        "High Volume Authentication Failures",
            Description: "Detects high volume of authentication failures",
            EventTypes:  []string{"device_audit"},
            Conditions: []DetectionCondition{
                {Field: "path", Operator: "contains", Value: "/auth/login", Weight: 1.0},
                {Field: "status", Operator: "in_range", Value: []interface{}{400, 499}, Weight: 2.0},
            },
            Category:   CategoryAuthFailure,
            Severity:   SeverityHigh,
            TimeWindow: 5 * time.Minute,
            Threshold:  20, // 20 failed logins in 5 minutes
            Enabled:    true,
        },
        
        // Suspicious OTP activity
        {
            ID:          "otp_abuse",
            Name:        "OTP Abuse Detection",
            Description: "Detects potential OTP abuse or brute force attempts",
            EventTypes:  []string{"otp_audit"},
            Conditions: []DetectionCondition{
                {Field: "route", Operator: "equals", Value: "/otp/verify", Weight: 1.0},
                {Field: "status", Operator: "in_range", Value: []interface{}{400, 499}, Weight: 2.0},
            },
            Category:   CategorySuspiciousActivity,
            Severity:   SeverityMedium,
            TimeWindow: 10 * time.Minute,
            Threshold:  10, // 10 failed OTP verifications in 10 minutes
            Enabled:    true,
        },
        
        // High risk score devices
        {
            ID:          "high_risk_device",
            Name:        "High Risk Device Activity",
            Description: "Detects activity from high-risk devices",
            EventTypes:  []string{"device_audit"},
            Conditions: []DetectionCondition{
                {Field: "risk_score", Operator: "greater_than", Value: 0.8, Weight: 3.0},
                {Field: "decision", Operator: "equals", Value: "block", Weight: 1.0},
            },
            Category:   CategorySuspiciousActivity,
            Severity:   SeverityHigh,
            TimeWindow: 1 * time.Minute,
            Threshold:  1, // Any high-risk activity triggers incident
            Enabled:    true,
        },
        
        // System performance degradation
        {
            ID:          "performance_degradation",
            Name:        "Performance Degradation",
            Description: "Detects significant performance degradation",
            EventTypes:  []string{"device_audit", "otp_audit"},
            Conditions: []DetectionCondition{
                {Field: "duration_ms", Operator: "greater_than", Value: 5000, Weight: 2.0}, // 5+ seconds
            },
            Category:   CategorySystemFailure,
            Severity:   SeverityMedium,
            TimeWindow: 5 * time.Minute,
            Threshold:  10, // 10 slow requests in 5 minutes
            Enabled:    true,
        },
        
        // Unusual platform activity
        {
            ID:          "unusual_platform",
            Name:        "Unusual Platform Activity",
            Description: "Detects activity from unusual or suspicious platforms",
            EventTypes:  []string{"device_audit", "otp_audit"},
            Conditions: []DetectionCondition{
                {Field: "platform", Operator: "equals", Value: "unknown", Weight: 1.5},
                {Field: "status", Operator: "equals", Value: 200, Weight: 1.0}, // Successful requests are more concerning
            },
            Category:   CategorySuspiciousActivity,
            Severity:   SeverityLow,
            TimeWindow: 30 * time.Minute,
            Threshold:  5, // 5 requests from unknown platform
            Enabled:    true,
        },
        
        // Rapid fire requests (potential bot activity)
        {
            ID:          "rapid_fire_requests",
            Name:        "Rapid Fire Request Pattern",
            Description: "Detects rapid fire request patterns indicating bot activity",
            EventTypes:  []string{"device_audit"},
            Conditions: []DetectionCondition{
                {Field: "duration_ms", Operator: "less_than", Value: 100, Weight: 1.0}, // Very fast requests
            },
            Category:   CategorySuspiciousActivity,
            Severity:   SeverityMedium,
            TimeWindow: 1 * time.Minute,
            Threshold:  30, // 30 very fast requests in 1 minute
            Enabled:    true,
        },
        
        // Error rate spike
        {
            ID:          "error_rate_spike",
            Name:        "Error Rate Spike",
            Description: "Detects spikes in error rates indicating system issues",
            EventTypes:  []string{"device_audit", "otp_audit"},
            Conditions: []DetectionCondition{
                {Field: "status", Operator: "in_range", Value: []interface{}{500, 599}, Weight: 2.0},
            },
            Category:   CategorySystemFailure,
            Severity:   SeverityHigh,
            TimeWindow: 2 * time.Minute,
            Threshold:  15, // 15 server errors in 2 minutes
            Enabled:    true,
        },
    }
    
    for _, rule := range rules {
        de.detectionRules[rule.ID] = rule
        logger.Info("Detection rule registered", "rule_id", rule.ID, "name", rule.Name)
    }
}