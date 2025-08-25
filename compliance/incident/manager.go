package incident

import (
    "context"
    "database/sql"
    "fmt"
    "sync"
    "time"

    "github.com/google/uuid"

    "github.com/ComUnity/auth-service/internal/client"
    "github.com/ComUnity/auth-service/internal/models"
    "github.com/ComUnity/auth-service/internal/util/logger"
    "github.com/ComUnity/auth-service/security"
)

// IncidentSeverity represents the severity level of an incident
type IncidentSeverity string

const (
    SeverityCritical IncidentSeverity = "critical"
    SeverityHigh     IncidentSeverity = "high"
    SeverityMedium   IncidentSeverity = "medium"
    SeverityLow      IncidentSeverity = "low"
    SeverityInfo     IncidentSeverity = "info"
)

// IncidentStatus represents the current status of an incident
type IncidentStatus string

const (
    StatusOpen       IncidentStatus = "open"
    StatusInProgress IncidentStatus = "in_progress"
    StatusContained  IncidentStatus = "contained"
    StatusResolved   IncidentStatus = "resolved"
    StatusClosed     IncidentStatus = "closed"
    StatusFalsePositive IncidentStatus = "false_positive"
)

// IncidentCategory represents the category of an incident
type IncidentCategory string

const (
    CategoryAuthFailure      IncidentCategory = "auth_failure"
    CategorySuspiciousActivity IncidentCategory = "suspicious_activity"
    CategoryDataBreach       IncidentCategory = "data_breach"
    CategoryComplianceViolation IncidentCategory = "compliance_violation"
    CategorySystemFailure    IncidentCategory = "system_failure"
    CategorySecurityThreat   IncidentCategory = "security_threat"
    CategoryPerformance      IncidentCategory = "performance"
    CategoryCapacityLimit    IncidentCategory = "capacity_limit"
)

// Incident represents a security or operational incident
type Incident struct {
    ID                  uuid.UUID            `json:"id"`
    Title               string               `json:"title"`
    Description         string               `json:"description"`
    Category            IncidentCategory     `json:"category"`
    Severity            IncidentSeverity     `json:"severity"`
    Status              IncidentStatus       `json:"status"`
    Priority            int                  `json:"priority"` // 1-5, 1 being highest
    
    // Detection details
    DetectedAt          time.Time            `json:"detected_at"`
    DetectedBy          string               `json:"detected_by"` // system, user, external
    DetectionMethod     string               `json:"detection_method"`
    SourceEvents        []string             `json:"source_events"` // Event IDs that triggered this
    
    // Response details
    AssignedTo          *uuid.UUID           `json:"assigned_to,omitempty"`
    RespondedAt         *time.Time           `json:"responded_at,omitempty"`
    ContainedAt         *time.Time           `json:"contained_at,omitempty"`
    ResolvedAt          *time.Time           `json:"resolved_at,omitempty"`
    ClosedAt            *time.Time           `json:"closed_at,omitempty"`
    
    // Impact assessment
    AffectedUsers       []uuid.UUID          `json:"affected_users,omitempty"`
    AffectedSystems     []string             `json:"affected_systems,omitempty"`
    ImpactAssessment    string               `json:"impact_assessment"`
    DataCompromised     bool                 `json:"data_compromised"`
    
    // Response tracking
    PlaybookID          *uuid.UUID           `json:"playbook_id,omitempty"`
    ResponseActions     []ResponseAction     `json:"response_actions"`
    EscalationLevel     int                  `json:"escalation_level"`
    NotificationsEnabled bool                `json:"notifications_enabled"`
    
    // Analysis and metrics
    MTTR                *time.Duration       `json:"mttr,omitempty"` // Mean Time To Recovery
    RootCause           string               `json:"root_cause,omitempty"`
    LessonsLearned      string               `json:"lessons_learned,omitempty"`
    
    // Compliance and reporting
    ComplianceRelevant  bool                 `json:"compliance_relevant"`
    RegulatorNotified   bool                 `json:"regulator_notified"`
    CustomerNotified    bool                 `json:"customer_notified"`
    ReportGenerated     bool                 `json:"report_generated"`
    
    // Metadata
    Tags                []string             `json:"tags"`
    Metadata            models.JSONMap       `json:"metadata"`
    CreatedAt           time.Time            `json:"created_at"`
    UpdatedAt           time.Time            `json:"updated_at"`
}

// ResponseAction represents an action taken in response to an incident
type ResponseAction struct {
    ID              uuid.UUID          `json:"id"`
    IncidentID      uuid.UUID          `json:"incident_id"`
    ActionType      string             `json:"action_type"`
    Description     string             `json:"description"`
    ExecutedAt      time.Time          `json:"executed_at"`
    ExecutedBy      string             `json:"executed_by"`
    Status          string             `json:"status"` // pending, completed, failed
    Result          string             `json:"result,omitempty"`
    Error           string             `json:"error,omitempty"`
    Automated       bool               `json:"automated"`
    Metadata        models.JSONMap     `json:"metadata"`
}

// IncidentManager manages security and operational incidents
type IncidentManager struct {
    config      IncidentConfig
    db          *sql.DB
    redis       *client.RedisClient
    kmsHelper   *security.Helper
    
    // Detection and response
    detectionEngine *DetectionEngine
    responseEngine  *ResponseEngine
    playbooks      map[IncidentCategory]*PlaybookRegistry
    
    // Active incidents
    incidents       sync.Map // map[uuid.UUID]*Incident
    
    // Event processing
    eventChannel    chan interface{}
    
    // Statistics
    stats           IncidentStats
    statsMu         sync.RWMutex
}

// IncidentConfig holds configuration for incident management
type IncidentConfig struct {
    Enabled             bool                    `yaml:"enabled"`
    AutoResponse        bool                    `yaml:"auto_response"`
    MaxConcurrentEvents int                     `yaml:"max_concurrent_events"`
    EventBufferSize     int                     `yaml:"event_buffer_size"`
    
    // Detection settings
    DetectionInterval   time.Duration           `yaml:"detection_interval"`
    AlertThresholds     map[string]int          `yaml:"alert_thresholds"`
    SuspiciousThresholds map[string]float64     `yaml:"suspicious_thresholds"`
    
    // Response settings
    AutoContainment     bool                    `yaml:"auto_containment"`
    EscalationTimeout   time.Duration           `yaml:"escalation_timeout"`
    MaxEscalationLevel  int                     `yaml:"max_escalation_level"`
    
    // Notification settings
    NotificationChannels []NotificationChannel  `yaml:"notification_channels"`
    EscalationPaths     map[IncidentSeverity][]string `yaml:"escalation_paths"`
    
    // Compliance settings
    ComplianceReporting bool                    `yaml:"compliance_reporting"`
    RegulatoryDeadlines map[string]time.Duration `yaml:"regulatory_deadlines"`
}

// NotificationChannel represents a notification channel
type NotificationChannel struct {
    Name        string            `yaml:"name"`
    Type        string            `yaml:"type"` // email, slack, webhook, sms
    Config      map[string]string `yaml:"config"`
    Severity    []IncidentSeverity `yaml:"severity"`
    Categories  []IncidentCategory `yaml:"categories"`
}

// IncidentStats tracks incident management statistics
type IncidentStats struct {
    TotalIncidents      int64              `json:"total_incidents"`
    OpenIncidents       int64              `json:"open_incidents"`
    ResolvedIncidents   int64              `json:"resolved_incidents"`
    FalsePositives      int64              `json:"false_positives"`
    
    // Performance metrics
    AverageMTTR         time.Duration      `json:"average_mttr"`
    AverageMTTD         time.Duration      `json:"average_mttd"` // Mean Time To Detection
    AverageResponseTime time.Duration      `json:"average_response_time"`
    
    // Severity breakdown
    CriticalIncidents   int64              `json:"critical_incidents"`
    HighIncidents       int64              `json:"high_incidents"`
    MediumIncidents     int64              `json:"medium_incidents"`
    LowIncidents        int64              `json:"low_incidents"`
    
    // Category breakdown
    CategoryBreakdown   map[IncidentCategory]int64 `json:"category_breakdown"`
    
    // Recent activity
    Last24Hours         int64              `json:"last_24_hours"`
    LastWeek            int64              `json:"last_week"`
    LastMonth           int64              `json:"last_month"`
}

// NewIncidentManager creates a new incident manager
func NewIncidentManager(
    config IncidentConfig,
    db *sql.DB,
    redis *client.RedisClient,
    kmsHelper *security.Helper,
) *IncidentManager {
    
    // Set defaults
    if config.MaxConcurrentEvents == 0 {
        config.MaxConcurrentEvents = 1000
    }
    if config.EventBufferSize == 0 {
        config.EventBufferSize = 10000
    }
    if config.DetectionInterval == 0 {
        config.DetectionInterval = 30 * time.Second
    }
    if config.EscalationTimeout == 0 {
        config.EscalationTimeout = 4 * time.Hour // 4 hours
    }
    if config.MaxEscalationLevel == 0 {
        config.MaxEscalationLevel = 3
    }
    
    im := &IncidentManager{
        config:       config,
        db:          db,
        redis:       redis,
        kmsHelper:   kmsHelper,
        eventChannel: make(chan interface{}, config.EventBufferSize),
        playbooks:   make(map[IncidentCategory]*PlaybookRegistry),
        stats: IncidentStats{
            CategoryBreakdown: make(map[IncidentCategory]int64),
        },
    }
    
    if config.Enabled {
        // Initialize detection engine
        im.detectionEngine = NewDetectionEngine(im)
        
        // Initialize response engine
        im.responseEngine = NewResponseEngine(im)
        
        // Load existing incidents
        if err := im.loadIncidents(); err != nil {
            logger.Error("Failed to load incidents", "error", err)
        }
        
        // Register default playbooks
        im.registerDefaultPlaybooks()
        
        // Start event processor
        go im.eventProcessor()
        
        // Start periodic tasks
        go im.periodicTasks()
        
        logger.Info("Incident manager initialized",
            "auto_response", config.AutoResponse,
            "detection_interval", config.DetectionInterval,
            "max_concurrent_events", config.MaxConcurrentEvents)
    }
    
    return im
}

// ProcessEvent processes an audit event for incident detection
func (im *IncidentManager) ProcessEvent(event interface{}) {
    if !im.config.Enabled {
        return
    }
    
    select {
    case im.eventChannel <- event:
        // Event queued successfully
    default:
        // Channel full, drop event to prevent blocking
        logger.Warn("Event channel full, dropping event")
    }
}

// CreateIncident creates a new incident
func (im *IncidentManager) CreateIncident(ctx context.Context, incident *Incident) (*Incident, error) {
    incident.ID = uuid.New()
    incident.CreatedAt = time.Now()
    incident.UpdatedAt = time.Now()
    incident.DetectedAt = time.Now()
    incident.Status = StatusOpen
    
    // Set priority based on severity
    incident.Priority = im.calculatePriority(incident.Severity, incident.Category)
    
    // Store incident
    if err := im.storeIncident(ctx, incident); err != nil {
        return nil, fmt.Errorf("failed to store incident: %w", err)
    }
    
    // Cache incident
    im.incidents.Store(incident.ID, incident)
    
    // Update statistics
    im.updateStats(func(s *IncidentStats) {
        s.TotalIncidents++
        s.OpenIncidents++
        s.CategoryBreakdown[incident.Category]++
        
        switch incident.Severity {
        case SeverityCritical:
            s.CriticalIncidents++
        case SeverityHigh:
            s.HighIncidents++
        case SeverityMedium:
            s.MediumIncidents++
        case SeverityLow:
            s.LowIncidents++
        }
        
        // Update time-based stats
        now := time.Now()
        if incident.DetectedAt.After(now.Add(-24 * time.Hour)) {
            s.Last24Hours++
        }
        if incident.DetectedAt.After(now.Add(-7 * 24 * time.Hour)) {
            s.LastWeek++
        }
        if incident.DetectedAt.After(now.Add(-30 * 24 * time.Hour)) {
            s.LastMonth++
        }
    })
    
    // Trigger automatic response if enabled
    if im.config.AutoResponse {
        go im.responseEngine.TriggerResponse(ctx, incident)
    }
    
    // Send notifications
    go im.sendNotifications(incident, "incident_created")
    
    logger.Info("Incident created",
        "incident_id", incident.ID,
        "category", incident.Category,
        "severity", incident.Severity,
        "title", incident.Title)
    
    return incident, nil
}

// GetIncident retrieves an incident by ID
func (im *IncidentManager) GetIncident(ctx context.Context, incidentID uuid.UUID) (*Incident, error) {
    // Check cache first
    if cached, ok := im.incidents.Load(incidentID); ok {
        return cached.(*Incident), nil
    }
    
    // Load from storage
    incident, err := im.loadIncident(ctx, incidentID)
    if err != nil {
        return nil, fmt.Errorf("incident not found: %w", err)
    }
    
    // Cache for next time
    im.incidents.Store(incidentID, incident)
    
    return incident, nil
}

// UpdateIncident updates an existing incident
func (im *IncidentManager) UpdateIncident(ctx context.Context, incident *Incident) error {
    incident.UpdatedAt = time.Now()
    
    // Update storage
    if err := im.storeIncident(ctx, incident); err != nil {
        return fmt.Errorf("failed to update incident: %w", err)
    }
    
    // Update cache
    im.incidents.Store(incident.ID, incident)
    
    // Update statistics if status changed
    im.updateIncidentStats(incident)
    
    logger.Info("Incident updated",
        "incident_id", incident.ID,
        "status", incident.Status,
        "severity", incident.Severity)
    
    return nil
}

// ListIncidents returns incidents with optional filtering
func (im *IncidentManager) ListIncidents(ctx context.Context, filters IncidentFilters) ([]*Incident, error) {
    var incidents []*Incident
    
    im.incidents.Range(func(key, value interface{}) bool {
        incident := value.(*Incident)
        
        // Apply filters
        if filters.Status != "" && incident.Status != filters.Status {
            return true
        }
        if filters.Severity != "" && incident.Severity != filters.Severity {
            return true
        }
        if filters.Category != "" && incident.Category != filters.Category {
            return true
        }
        if filters.AssignedTo != uuid.Nil && (incident.AssignedTo == nil || *incident.AssignedTo != filters.AssignedTo) {
            return true
        }
        if !filters.StartTime.IsZero() && incident.DetectedAt.Before(filters.StartTime) {
            return true
        }
        if !filters.EndTime.IsZero() && incident.DetectedAt.After(filters.EndTime) {
            return true
        }
        
        incidents = append(incidents, incident)
        return true
    })
    
    // Apply limit
    if filters.Limit > 0 && len(incidents) > filters.Limit {
        incidents = incidents[:filters.Limit]
    }
    
    return incidents, nil
}

// AddResponseAction adds a response action to an incident
func (im *IncidentManager) AddResponseAction(ctx context.Context, incidentID uuid.UUID, action *ResponseAction) error {
    incident, err := im.GetIncident(ctx, incidentID)
    if err != nil {
        return err
    }
    
    action.ID = uuid.New()
    action.IncidentID = incidentID
    action.ExecutedAt = time.Now()
    
    incident.ResponseActions = append(incident.ResponseActions, *action)
    incident.UpdatedAt = time.Now()
    
    return im.UpdateIncident(ctx, incident)
}

// CloseIncident closes an incident
func (im *IncidentManager) CloseIncident(ctx context.Context, incidentID uuid.UUID, resolution string, rootCause string) error {
    incident, err := im.GetIncident(ctx, incidentID)
    if err != nil {
        return err
    }
    
    now := time.Now()
    incident.Status = StatusClosed
    incident.ClosedAt = &now
    incident.RootCause = rootCause
    incident.UpdatedAt = now
    
    // Calculate MTTR
    if incident.DetectedAt != (time.Time{}) {
        mttr := now.Sub(incident.DetectedAt)
        incident.MTTR = &mttr
    }
    
    // Add resolution action
    resolutionAction := ResponseAction{
        ID:          uuid.New(),
        IncidentID:  incidentID,
        ActionType:  "resolution",
        Description: resolution,
        ExecutedAt:  now,
        ExecutedBy:  "system",
        Status:      "completed",
        Result:      "incident_closed",
        Automated:   false,
    }
    
    incident.ResponseActions = append(incident.ResponseActions, resolutionAction)
    
    // Update statistics
    im.updateStats(func(s *IncidentStats) {
        s.OpenIncidents--
        s.ResolvedIncidents++
        
        if incident.MTTR != nil {
            s.AverageMTTR = (s.AverageMTTR + *incident.MTTR) / 2
        }
    })
    
    return im.UpdateIncident(ctx, incident)
}

// Event processing

func (im *IncidentManager) eventProcessor() {
    for event := range im.eventChannel {
        im.processEvent(event)
    }
}

func (im *IncidentManager) processEvent(event interface{}) {
    // Analyze event for potential incidents
    incidents := im.detectionEngine.AnalyzeEvent(event)
    
    for _, incident := range incidents {
        if existingIncident := im.findSimilarIncident(incident); existingIncident != nil {
            // Update existing incident
            existingIncident.SourceEvents = append(existingIncident.SourceEvents, incident.SourceEvents...)
            existingIncident.UpdatedAt = time.Now()
            im.UpdateIncident(context.Background(), existingIncident)
        } else {
            // Create new incident
            im.CreateIncident(context.Background(), incident)
        }
    }
}

func (im *IncidentManager) findSimilarIncident(newIncident *Incident) *Incident {
    var similarIncident *Incident
    cutoffTime := time.Now().Add(-1 * time.Hour) // Look for similar incidents in last hour
    
    im.incidents.Range(func(key, value interface{}) bool {
        incident := value.(*Incident)
        
        if incident.DetectedAt.Before(cutoffTime) {
            return true // Skip old incidents
        }
        
        if incident.Status == StatusClosed || incident.Status == StatusFalsePositive {
            return true // Skip closed incidents
        }
        
        if incident.Category == newIncident.Category &&
           incident.Severity == newIncident.Severity &&
           im.hasSimilarAffectedSystems(incident.AffectedSystems, newIncident.AffectedSystems) {
            similarIncident = incident
            return false // Stop iteration
        }
        
        return true
    })
    
    return similarIncident
}

func (im *IncidentManager) hasSimilarAffectedSystems(systems1, systems2 []string) bool {
    if len(systems1) == 0 && len(systems2) == 0 {
        return true
    }
    
    systemSet := make(map[string]bool)
    for _, system := range systems1 {
        systemSet[system] = true
    }
    
    for _, system := range systems2 {
        if systemSet[system] {
            return true
        }
    }
    
    return false
}

// Periodic tasks

func (im *IncidentManager) periodicTasks() {
    ticker := time.NewTicker(im.config.DetectionInterval)
    defer ticker.Stop()
    
    for range ticker.C {
        im.checkEscalations()
        im.checkStaleIncidents()
        im.updateMetrics()
    }
}

func (im *IncidentManager) checkEscalations() {
    cutoffTime := time.Now().Add(-im.config.EscalationTimeout)
    
    im.incidents.Range(func(key, value interface{}) bool {
        incident := value.(*Incident)
        
        if incident.Status == StatusClosed || incident.Status == StatusFalsePositive {
            return true
        }
        
        if incident.DetectedAt.Before(cutoffTime) && incident.EscalationLevel < im.config.MaxEscalationLevel {
            im.escalateIncident(incident)
        }
        
        return true
    })
}

func (im *IncidentManager) checkStaleIncidents() {
    staleTime := time.Now().Add(-24 * time.Hour)
    
    im.incidents.Range(func(key, value interface{}) bool {
        incident := value.(*Incident)
        
        if incident.Status == StatusOpen && incident.DetectedAt.Before(staleTime) {
            // Mark as stale and send notification
            incident.Tags = append(incident.Tags, "stale")
            im.UpdateIncident(context.Background(), incident)
            
            logger.Warn("Stale incident detected",
                "incident_id", incident.ID,
                "age", time.Since(incident.DetectedAt))
        }
        
        return true
    })
}

func (im *IncidentManager) escalateIncident(incident *Incident) {
    incident.EscalationLevel++
    incident.UpdatedAt = time.Now()
    
    // Add escalation action
    escalationAction := ResponseAction{
        ID:          uuid.New(),
        IncidentID:  incident.ID,
        ActionType:  "escalation",
        Description: fmt.Sprintf("Escalated to level %d due to timeout", incident.EscalationLevel),
        ExecutedAt:  time.Now(),
        ExecutedBy:  "system",
        Status:      "completed",
        Automated:   true,
    }
    
    incident.ResponseActions = append(incident.ResponseActions, escalationAction)
    
    im.UpdateIncident(context.Background(), incident)
    
    // Send escalation notifications
    im.sendNotifications(incident, "incident_escalated")
    
    logger.Info("Incident escalated",
        "incident_id", incident.ID,
        "escalation_level", incident.EscalationLevel)
}

func (im *IncidentManager) updateMetrics() {
    // Recalculate statistics
    var stats IncidentStats
    stats.CategoryBreakdown = make(map[IncidentCategory]int64)
    
    var totalMTTR time.Duration
    var mttrCount int
    cutoff24h := time.Now().Add(-24 * time.Hour)
    cutoff7d := time.Now().Add(-7 * 24 * time.Hour)
    cutoff30d := time.Now().Add(-30 * 24 * time.Hour)
    
    im.incidents.Range(func(key, value interface{}) bool {
        incident := value.(*Incident)
        stats.TotalIncidents++
        stats.CategoryBreakdown[incident.Category]++
        
        // Status breakdown
        switch incident.Status {
        case StatusOpen, StatusInProgress, StatusContained:
            stats.OpenIncidents++
        case StatusResolved, StatusClosed:
            stats.ResolvedIncidents++
        case StatusFalsePositive:
            stats.FalsePositives++
        }
        
        // Severity breakdown
        switch incident.Severity {
        case SeverityCritical:
            stats.CriticalIncidents++
        case SeverityHigh:
            stats.HighIncidents++
        case SeverityMedium:
            stats.MediumIncidents++
        case SeverityLow:
            stats.LowIncidents++
        }
        
        // MTTR calculation
        if incident.MTTR != nil {
            totalMTTR += *incident.MTTR
            mttrCount++
        }
        
        // Time-based stats
        if incident.DetectedAt.After(cutoff24h) {
            stats.Last24Hours++
        }
        if incident.DetectedAt.After(cutoff7d) {
            stats.LastWeek++
        }
        if incident.DetectedAt.After(cutoff30d) {
            stats.LastMonth++
        }
        
        return true
    })
    
    if mttrCount > 0 {
        stats.AverageMTTR = totalMTTR / time.Duration(mttrCount)
    }
    
    // Update stats
    im.statsMu.Lock()
    im.stats = stats
    im.statsMu.Unlock()
}

// Utility methods

func (im *IncidentManager) calculatePriority(severity IncidentSeverity, category IncidentCategory) int {
    basePriority := map[IncidentSeverity]int{
        SeverityCritical: 1,
        SeverityHigh:     2,
        SeverityMedium:   3,
        SeverityLow:      4,
        SeverityInfo:     5,
    }[severity]
    
    // Adjust based on category
    if category == CategoryDataBreach || category == CategoryComplianceViolation {
        basePriority = max(1, basePriority-1) // Increase priority
    }
    
    return basePriority
}

func (im *IncidentManager) sendNotifications(incident *Incident, eventType string) {
    for _, channel := range im.config.NotificationChannels {
        // Check if severity matches
        severityMatch := false
        for _, severity := range channel.Severity {
            if severity == incident.Severity {
                severityMatch = true
                break
            }
        }
        
        // Check if category matches
        categoryMatch := len(channel.Categories) == 0 // If no categories specified, match all
        for _, category := range channel.Categories {
            if category == incident.Category {
                categoryMatch = true
                break
            }
        }
        
        if severityMatch && categoryMatch {
            im.sendNotification(channel, incident, eventType)
        }
    }
}

func (im *IncidentManager) sendNotification(channel NotificationChannel, incident *Incident, eventType string) {
    // Implementation would depend on the channel type
    logger.Info("Sending notification",
        "channel", channel.Name,
        "type", channel.Type,
        "incident_id", incident.ID,
        "event_type", eventType)
    
    // You would implement actual notification sending here
    // For example: email, Slack, webhook, SMS, etc.
}

// Storage operations

func (im *IncidentManager) storeIncident(ctx context.Context, incident *Incident) error {
    key := fmt.Sprintf("incident:%s", incident.ID.String())
    return im.redis.SetJSON(ctx, key, incident, 30*24*time.Hour) // 30 days TTL
}

func (im *IncidentManager) loadIncident(ctx context.Context, incidentID uuid.UUID) (*Incident, error) {
    key := fmt.Sprintf("incident:%s", incidentID.String())
    var incident Incident
    if err := im.redis.GetJSON(ctx, key, &incident); err != nil {
        return nil, err
    }
    return &incident, nil
}

func (im *IncidentManager) loadIncidents() error {
    ctx := context.Background()
    pattern := "incident:*"
    
    keys, err := im.redis.Keys(ctx, pattern).Result()
    if err != nil {
        return err
    }
    
    for _, key := range keys {
        var incident Incident
        if err := im.redis.GetJSON(ctx, key, &incident); err != nil {
            logger.Warn("Failed to load incident", "key", key, "error", err)
            continue
        }
        
        im.incidents.Store(incident.ID, &incident)
    }
    
    return nil
}

func (im *IncidentManager) updateIncidentStats(incident *Incident) {
    im.updateStats(func(s *IncidentStats) {
        // This would contain more sophisticated stats updates
        // based on incident status changes
    })
}

func (im *IncidentManager) updateStats(update func(*IncidentStats)) {
    im.statsMu.Lock()
    defer im.statsMu.Unlock()
    update(&im.stats)
}

// GetStats returns incident statistics
func (im *IncidentManager) GetStats() IncidentStats {
    im.statsMu.RLock()
    defer im.statsMu.RUnlock()
    return im.stats
}

// IncidentFilters for filtering incident lists
type IncidentFilters struct {
    Status     IncidentStatus   `json:"status,omitempty"`
    Severity   IncidentSeverity `json:"severity,omitempty"`
    Category   IncidentCategory `json:"category,omitempty"`
    AssignedTo uuid.UUID        `json:"assigned_to,omitempty"`
    StartTime  time.Time        `json:"start_time,omitempty"`
    EndTime    time.Time        `json:"end_time,omitempty"`
    Limit      int              `json:"limit,omitempty"`
}

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}
