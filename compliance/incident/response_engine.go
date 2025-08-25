package incident

import (
    "context"
    "fmt"
    "time"

    "github.com/google/uuid"

    "github.com/ComUnity/auth-service/internal/util/logger"
)

// ResponseEngine handles automated incident response
type ResponseEngine struct {
    manager   *IncidentManager
    executors map[string]ActionExecutor
}

// ActionExecutor interface for executing response actions
type ActionExecutor interface {
    Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error)
}

// NewResponseEngine creates a new response engine
func NewResponseEngine(manager *IncidentManager) *ResponseEngine {
    engine := &ResponseEngine{
        manager:   manager,
        executors: make(map[string]ActionExecutor),
    }
    
    // Register default action executors
    engine.registerDefaultExecutors()
    
    return engine
}

// TriggerResponse triggers automated response for an incident
func (re *ResponseEngine) TriggerResponse(ctx context.Context, incident *Incident) {
    logger.Info("Triggering automated response",
        "incident_id", incident.ID,
        "category", incident.Category,
        "severity", incident.Severity)
    
    // Find matching playbooks
    registry, exists := re.manager.playbooks[incident.Category]
    if !exists {
        logger.Warn("No playbook registry found for category", "category", incident.Category)
        return
    }
    
    playbooks := registry.FindMatchingPlaybooks(incident)
    if len(playbooks) == 0 {
        logger.Info("No matching playbooks found", "incident_id", incident.ID)
        return
    }
    
    // Execute the first matching playbook (could be enhanced to choose best match)
    playbook := playbooks[0]
    
    if !playbook.AutoExecute {
        logger.Info("Playbook requires manual approval", "playbook_id", playbook.ID)
        return
    }
    
    go re.executePlaybook(ctx, playbook, incident)
}

// executePlaybook executes a playbook for an incident
func (re *ResponseEngine) executePlaybook(ctx context.Context, playbook *Playbook, incident *Incident) {
    execution := &PlaybookExecution{
        ID:         uuid.New(),
        PlaybookID: playbook.ID,
        IncidentID: incident.ID,
        Status:     ExecutionRunning,
        StartedAt:  time.Now(),
        ExecutedBy: "automated_response",
        Steps:      make([]StepExecution, 0, len(playbook.Steps)),
        Metadata:   make(map[string]interface{}),
    }
    
    logger.Info("Starting playbook execution",
        "execution_id", execution.ID,
        "playbook_id", playbook.ID,
        "incident_id", incident.ID)
    
    // Execute steps
    success := re.executeSteps(ctx, playbook, incident, execution)
    
    // Complete execution
    completedAt := time.Now()
    execution.CompletedAt = &completedAt
    
    if success {
        execution.Status = ExecutionCompleted
        logger.Info("Playbook execution completed successfully",
            "execution_id", execution.ID,
            "duration", completedAt.Sub(execution.StartedAt))
    } else {
        execution.Status = ExecutionFailed
        logger.Error("Playbook execution failed",
            "execution_id", execution.ID,
            "error", execution.Error)
    }
    
    // Update incident with playbook execution
    incident.PlaybookID = &playbook.ID
    incident.ResponseActions = append(incident.ResponseActions, ResponseAction{
        ID:          uuid.New(),
        IncidentID:  incident.ID,
        ActionType:  "playbook_execution",
        Description: fmt.Sprintf("Executed playbook: %s", playbook.Name),
        ExecutedAt:  execution.StartedAt,
        ExecutedBy:  "response_engine",
        Status:      string(execution.Status),
        Result:      fmt.Sprintf("Execution %s", execution.Status),
        Automated:   true,
        Metadata: map[string]interface{}{
            "execution_id": execution.ID,
            "playbook_id":  playbook.ID,
        },
    })
    
    re.manager.UpdateIncident(ctx, incident)
}

// executeSteps executes the steps of a playbook
func (re *ResponseEngine) executeSteps(ctx context.Context, playbook *Playbook, incident *Incident, execution *PlaybookExecution) bool {
    stepStatus := make(map[string]StepExecutionStatus)
    
    // Initialize all steps as pending
    for _, step := range playbook.Steps {
        stepStatus[step.ID] = StepPending
    }
    
    // Execute steps in dependency order
    for {
        executed := false
        
        for _, step := range playbook.Steps {
            if !step.Enabled || stepStatus[step.ID] != StepPending {
                continue
            }
            
            // Check dependencies
            canExecute := true
            for _, depID := range step.DependsOn {
                if stepStatus[depID] != StepCompleted {
                    canExecute = false
                    break
                }
            }
            
            if !canExecute {
                continue
            }
            
            // Execute step
            stepExec := re.executeStep(ctx, step, incident)
            execution.Steps = append(execution.Steps, *stepExec)
            stepStatus[step.ID] = stepExec.Status
            executed = true
            
            // If step failed and shouldn't continue on error, fail the whole execution
            if stepExec.Status == StepFailed && !step.ContinueOnError {
                execution.Error = fmt.Sprintf("Step '%s' failed: %s", step.Name, stepExec.Error)
                return false
            }
        }
        
        // Check if we're done
        if !executed {
            break
        }
    }
    
    // Check if all enabled steps completed
    for _, step := range playbook.Steps {
        if step.Enabled && stepStatus[step.ID] != StepCompleted && stepStatus[step.ID] != StepSkipped {
            return false
        }
    }
    
    return true
}

// executeStep executes a single playbook step
func (re *ResponseEngine) executeStep(ctx context.Context, step PlaybookStep, incident *Incident) *StepExecution {
    stepExec := &StepExecution{
        StepID:    step.ID,
        Status:    StepRunning,
        StartedAt: time.Now(),
        Retries:   0,
    }
    
    logger.Info("Executing playbook step",
        "step_id", step.ID,
        "step_name", step.Name,
        "incident_id", incident.ID)
    
    // Get executor for action
    executor, exists := re.executors[step.Action]
    if !exists {
        stepExec.Status = StepFailed
        stepExec.Error = fmt.Sprintf("No executor found for action: %s", step.Action)
        completedAt := time.Now()
        stepExec.CompletedAt = &completedAt
        return stepExec
    }
    
    // Execute with retries
    maxRetries := step.MaxRetries
    if maxRetries == 0 {
        maxRetries = 1
    }
    
    for attempt := 0; attempt < maxRetries; attempt++ {
        if attempt > 0 {
            stepExec.Retries = attempt
            time.Sleep(time.Duration(attempt) * time.Second) // Exponential backoff
        }
        
        // Execute with timeout
        execCtx := ctx
        if step.Timeout > 0 {
            var cancel context.CancelFunc
            execCtx, cancel = context.WithTimeout(ctx, step.Timeout)
            defer cancel()
        }
        
        result, err := executor.Execute(execCtx, step, incident)
        if err == nil {
            *stepExec = *result
            return stepExec
        }
        
        stepExec.Error = err.Error()
        logger.Warn("Step execution attempt failed",
            "step_id", step.ID,
            "attempt", attempt+1,
            "error", err)
    }
    
    // All attempts failed
    stepExec.Status = StepFailed
    completedAt := time.Now()
    stepExec.CompletedAt = &completedAt
    
    return stepExec
}

// Default action executors

func (re *ResponseEngine) registerDefaultExecutors() {
    re.executors["analyze_auth_source"] = &AnalyzeAuthSourceExecutor{engine: re}
    re.executors["block_ips"] = &BlockIPsExecutor{engine: re}
    re.executors["send_notification"] = &SendNotificationExecutor{engine: re}
    re.executors["analyze_device_behavior"] = &AnalyzeDeviceBehaviorExecutor{engine: re}
    re.executors["require_additional_auth"] = &RequireAdditionalAuthExecutor{engine: re}
    re.executors["enable_enhanced_monitoring"] = &EnableEnhancedMonitoringExecutor{engine: re}
    re.executors["contain_breach"] = &ContainBreachExecutor{engine: re}
    re.executors["assess_breach_scope"] = &AssessBreachScopeExecutor{engine: re}
    re.executors["notify_authorities"] = &NotifyAuthoritiesExecutor{engine: re}
    re.executors["notify_customers"] = &NotifyCustomersExecutor{engine: re}
    re.executors["start_forensics"] = &StartForensicsExecutor{engine: re}
    re.executors["check_system_health"] = &CheckSystemHealthExecutor{engine: re}
    re.executors["attempt_recovery"] = &AttemptRecoveryExecutor{engine: re}
    re.executors["escalate_oncall"] = &EscalateOnCallExecutor{engine: re}
    re.executors["update_status_page"] = &UpdateStatusPageExecutor{engine: re}
}

// Example action executors (simplified implementations)

type AnalyzeAuthSourceExecutor struct {
    engine *ResponseEngine
}

func (e *AnalyzeAuthSourceExecutor) Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error) {
    stepExec := &StepExecution{
        StepID:    action.ID,
        Status:    StepRunning,
        StartedAt: time.Now(),
    }
    
    // Simulate analysis
    time.Sleep(1 * time.Second)
    
    completedAt := time.Now()
    stepExec.Status = StepCompleted
    stepExec.CompletedAt = &completedAt
    stepExec.Result = map[string]interface{}{
        "suspicious_ips": []string{"192.168.1.100", "10.0.0.5"},
        "failure_rate":   0.85,
        "source_count":   3,
    }
    
    return stepExec, nil
}

type BlockIPsExecutor struct {
    engine *ResponseEngine
}

func (e *BlockIPsExecutor) Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error) {
    stepExec := &StepExecution{
        StepID:    action.ID,
        Status:    StepRunning,
        StartedAt: time.Now(),
    }
    
    // This would integrate with your WAF/firewall to block IPs
    logger.Info("Blocking suspicious IPs", "incident_id", incident.ID)
    
    completedAt := time.Now()
    stepExec.Status = StepCompleted
    stepExec.CompletedAt = &completedAt
    stepExec.Result = map[string]interface{}{
        "blocked_ips": []string{"192.168.1.100", "10.0.0.5"},
        "duration":    action.Parameters["duration_minutes"],
    }
    
    return stepExec, nil
}

type SendNotificationExecutor struct {
    engine *ResponseEngine
}

func (e *SendNotificationExecutor) Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error) {
    stepExec := &StepExecution{
        StepID:    action.ID,
        Status:    StepRunning,
        StartedAt: time.Now(),
    }
    
    // Send notification through configured channels
    channel := action.Parameters["channel"].(string)
    priority := action.Parameters["priority"].(string)
    
    logger.Info("Sending notification",
        "incident_id", incident.ID,
        "channel", channel,
        "priority", priority)
    
    completedAt := time.Now()
    stepExec.Status = StepCompleted
    stepExec.CompletedAt = &completedAt
    stepExec.Result = map[string]interface{}{
        "channel":  channel,
        "priority": priority,
        "sent_at":  completedAt,
    }
    
    return stepExec, nil
}

// Additional executor implementations would follow similar patterns...
// For brevity, I'll provide stub implementations:

type AnalyzeDeviceBehaviorExecutor struct{ engine *ResponseEngine }
func (e *AnalyzeDeviceBehaviorExecutor) Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error) {
    return &StepExecution{StepID: action.ID, Status: StepCompleted, StartedAt: time.Now(), CompletedAt: &[]time.Time{time.Now()}[0]}, nil
}

type RequireAdditionalAuthExecutor struct{ engine *ResponseEngine }
func (e *RequireAdditionalAuthExecutor) Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error) {
    return &StepExecution{StepID: action.ID, Status: StepCompleted, StartedAt: time.Now(), CompletedAt: &[]time.Time{time.Now()}[0]}, nil
}

type EnableEnhancedMonitoringExecutor struct{ engine *ResponseEngine }
func (e *EnableEnhancedMonitoringExecutor) Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error) {
    return &StepExecution{StepID: action.ID, Status: StepCompleted, StartedAt: time.Now(), CompletedAt: &[]time.Time{time.Now()}[0]}, nil
}

type ContainBreachExecutor struct{ engine *ResponseEngine }
func (e *ContainBreachExecutor) Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error) {
    return &StepExecution{StepID: action.ID, Status: StepCompleted, StartedAt: time.Now(), CompletedAt: &[]time.Time{time.Now()}[0]}, nil
}

type AssessBreachScopeExecutor struct{ engine *ResponseEngine }
func (e *AssessBreachScopeExecutor) Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error) {
    return &StepExecution{StepID: action.ID, Status: StepCompleted, StartedAt: time.Now(), CompletedAt: &[]time.Time{time.Now()}[0]}, nil
}

type NotifyAuthoritiesExecutor struct{ engine *ResponseEngine }
func (e *NotifyAuthoritiesExecutor) Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error) {
    return &StepExecution{StepID: action.ID, Status: StepCompleted, StartedAt: time.Now(), CompletedAt: &[]time.Time{time.Now()}[0]}, nil
}

type NotifyCustomersExecutor struct{ engine *ResponseEngine }
func (e *NotifyCustomersExecutor) Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error) {
    return &StepExecution{StepID: action.ID, Status: StepCompleted, StartedAt: time.Now(), CompletedAt: &[]time.Time{time.Now()}[0]}, nil
}

type StartForensicsExecutor struct{ engine *ResponseEngine }
func (e *StartForensicsExecutor) Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error) {
    return &StepExecution{StepID: action.ID, Status: StepCompleted, StartedAt: time.Now(), CompletedAt: &[]time.Time{time.Now()}[0]}, nil
}

type CheckSystemHealthExecutor struct{ engine *ResponseEngine }
func (e *CheckSystemHealthExecutor) Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error) {
    return &StepExecution{StepID: action.ID, Status: StepCompleted, StartedAt: time.Now(), CompletedAt: &[]time.Time{time.Now()}[0]}, nil
}

type AttemptRecoveryExecutor struct{ engine *ResponseEngine }
func (e *AttemptRecoveryExecutor) Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error) {
    return &StepExecution{StepID: action.ID, Status: StepCompleted, StartedAt: time.Now(), CompletedAt: &[]time.Time{time.Now()}[0]}, nil
}

type EscalateOnCallExecutor struct{ engine *ResponseEngine }
func (e *EscalateOnCallExecutor) Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error) {
    return &StepExecution{StepID: action.ID, Status: StepCompleted, StartedAt: time.Now(), CompletedAt: &[]time.Time{time.Now()}[0]}, nil
}

type UpdateStatusPageExecutor struct{ engine *ResponseEngine }
func (e *UpdateStatusPageExecutor) Execute(ctx context.Context, action PlaybookStep, incident *Incident) (*StepExecution, error) {
    return &StepExecution{StepID: action.ID, Status: StepCompleted, StartedAt: time.Now(), CompletedAt: &[]time.Time{time.Now()}[0]}, nil
}
