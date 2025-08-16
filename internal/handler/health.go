package handler

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "strconv"
    "strings"
    "time"

    "github.com/ComUnity/auth-service/internal/client"
    "github.com/ComUnity/auth-service/internal/config"
    "github.com/ComUnity/auth-service/internal/util/logger"
    _ "github.com/lib/pq" // PostgreSQL driver
)

var startTime = time.Now()

// HealthStatus represents the overall health status
type HealthStatus string

const (
    HealthStatusHealthy   HealthStatus = "healthy"
    HealthStatusUnhealthy HealthStatus = "unhealthy"
    HealthStatusDegraded  HealthStatus = "degraded"
)

// HealthResponse represents the health check response
type HealthResponse struct {
    Status      HealthStatus           `json:"status"`
    Timestamp   time.Time              `json:"timestamp"`
    Version     string                 `json:"version,omitempty"`
    Environment string                 `json:"environment"`
    Uptime      string                 `json:"uptime"`
    Checks      map[string]CheckResult `json:"checks,omitempty"`
    Summary     HealthSummary          `json:"summary"`
}

// HealthSummary provides summary statistics
type HealthSummary struct {
    TotalChecks     int `json:"total_checks"`
    HealthyChecks   int `json:"healthy_checks"`
    DegradedChecks  int `json:"degraded_checks"`
    UnhealthyChecks int `json:"unhealthy_checks"`
}

// CheckResult represents individual health check results
type CheckResult struct {
    Status    HealthStatus           `json:"status"`
    Message   string                 `json:"message,omitempty"`
    Error     string                 `json:"error,omitempty"`
    Latency   string                 `json:"latency,omitempty"`
    Timestamp time.Time              `json:"timestamp"`
    Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// HealthChecker interface for implementing health checks
type HealthChecker interface {
    Name() string
    Check() CheckResult
}

// HealthHandler handles health check requests
type HealthHandler struct {
    config   *config.Config
    checkers []HealthChecker
    version  string
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(cfg *config.Config, version string) *HealthHandler {
    logger.Info("Initializing health handler with version: %s", version)

    h := &HealthHandler{
        config:  cfg,
        version: version,
    }

    // Initialize health checkers based on configuration
    h.initializeCheckers()

    logger.Info("Health handler initialized with %d checkers", len(h.checkers))
    return h
}

// initializeCheckers sets up health checkers based on available services
func (h *HealthHandler) initializeCheckers() {
    logger.Debug("Initializing health checkers...")

    // Add database health check if database URL is configured
    if h.config.DatabaseURL != "" {
        logger.Debug("Adding database health checker")
        h.checkers = append(h.checkers, &DatabaseHealthChecker{dsn: h.config.DatabaseURL})
    }

    // Add Redis health check if Redis URL is configured
    if h.config.RedisURL != "" {
        logger.Debug("Adding Redis health checker")
        h.checkers = append(h.checkers, &RedisHealthChecker{url: h.config.RedisURL})
    }

    // Add application-specific health checks
    h.checkers = append(h.checkers, &ApplicationHealthChecker{
        config: h.config,
    })

    logger.Info("Initialized %d health checkers", len(h.checkers))
}

// ServeHTTP handles /health endpoint
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    requestStart := time.Now()
    logger.Debug("Starting health check request from %s", r.RemoteAddr)

    response := HealthResponse{
        Status:      HealthStatusHealthy,
        Timestamp:   time.Now().UTC(),
        Version:     h.version,
        Environment: h.config.Env,
        Uptime:      time.Since(startTime).String(),
        Checks:      make(map[string]CheckResult),
        Summary:     HealthSummary{},
    }

    overallStatus := HealthStatusHealthy
    summary := HealthSummary{}

    // Run all health checks
    for _, checker := range h.checkers {
        logger.Debug("Running health check: %s", checker.Name())
        checkStart := time.Now()
        result := checker.Check()
        result.Latency = time.Since(checkStart).String()
        result.Timestamp = time.Now().UTC()

        response.Checks[checker.Name()] = result
        summary.TotalChecks++

        // Update counters and overall status
        switch result.Status {
        case HealthStatusHealthy:
            summary.HealthyChecks++
        case HealthStatusDegraded:
            summary.DegradedChecks++
            if overallStatus != HealthStatusUnhealthy {
                overallStatus = HealthStatusDegraded
            }
        case HealthStatusUnhealthy:
            summary.UnhealthyChecks++
            overallStatus = HealthStatusUnhealthy
        }
    }

    response.Status = overallStatus
    response.Summary = summary

    // Set HTTP status code based on health
    statusCode := http.StatusOK
    if overallStatus == HealthStatusUnhealthy {
        statusCode = http.StatusServiceUnavailable
    } else if overallStatus == HealthStatusDegraded {
        statusCode = http.StatusPartialContent // 206
    }

    // Log health check results
    totalLatency := time.Since(requestStart)
    logger.Info("Health check completed: status=%s, checks=%d, latency=%s",
        overallStatus, summary.TotalChecks, totalLatency)

    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
    w.WriteHeader(statusCode)

    if err := json.NewEncoder(w).Encode(response); err != nil {
        logger.Error("Failed to encode health response: %v", err)
    }
}

// ReadinessHandler handles /ready endpoint
func (h *HealthHandler) ReadinessHandler(w http.ResponseWriter, r *http.Request) {
    logger.Debug("Readiness probe from %s", r.RemoteAddr)

    // Check critical dependencies for readiness
    critical := []string{"database"}

    for _, checker := range h.checkers {
        for _, criticalName := range critical {
            if checker.Name() == criticalName {
                result := checker.Check()
                if result.Status == HealthStatusUnhealthy {
                    w.WriteHeader(http.StatusServiceUnavailable)
                    fmt.Fprintf(w, "not ready - %s: %s\n", criticalName, result.Error)
                    return
                }
            }
        }
    }

    w.WriteHeader(http.StatusOK)
    fmt.Fprintln(w, "ready")
}

// LivenessHandler handles /live endpoint
func (h *HealthHandler) LivenessHandler(w http.ResponseWriter, r *http.Request) {
    uptime := time.Since(startTime).String()

    w.Header().Set("Content-Type", "text/plain")
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, "live - uptime: %s\n", uptime)
}

// DatabaseHealthChecker checks the health of the database
type DatabaseHealthChecker struct {
    dsn string
}

func (d *DatabaseHealthChecker) Name() string {
    return "database"
}

func (d *DatabaseHealthChecker) Check() CheckResult {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // Determine driver based on DSN
    var driverName string
    switch {
    case strings.Contains(d.dsn, "mysql://"):
        driverName = "mysql"
    case strings.Contains(d.dsn, "postgres://"):
        driverName = "postgres"
    default:
        return CheckResult{
            Status: HealthStatusUnhealthy,
            Error:  "Unsupported database driver",
        }
    }

    db, err := sql.Open(driverName, d.dsn)
    if err != nil {
        logger.Error("Database connection error: %v", err)
        return CheckResult{
            Status: HealthStatusUnhealthy,
            Error:  fmt.Sprintf("Connection failed: %v", err),
        }
    }
    defer db.Close()

    // Test the connection
    if err := db.PingContext(ctx); err != nil {
        logger.Error("Database ping error: %v", err)
        return CheckResult{
            Status: HealthStatusUnhealthy,
            Error:  fmt.Sprintf("Ping failed: %v", err),
        }
    }

    // Get database stats
    stats := db.Stats()
    metadata := map[string]interface{}{
        "driver":           driverName,
        "open_connections": stats.OpenConnections,
        "in_use":           stats.InUse,
        "idle":             stats.Idle,
        "wait_count":       stats.WaitCount,
        "wait_duration":    stats.WaitDuration.String(),
    }

    return CheckResult{
        Status:   HealthStatusHealthy,
        Message:  "Database connection successful",
        Metadata: metadata,
    }
}

// RedisHealthChecker checks the health of Redis using internal client
type RedisHealthChecker struct {
    url string
}

func (r *RedisHealthChecker) Name() string {
    return "redis"
}

func (r *RedisHealthChecker) Check() CheckResult {
    // Parse redis:// URL and convert to client.RedisConfig
    cfg, err := parseRedisURLToConfig(r.url)
    if err != nil {
        logger.Error("Redis URL parse error: %v", err)
        return CheckResult{
            Status: HealthStatusUnhealthy,
            Error:  fmt.Sprintf("URL parse failed: %v", err),
        }
    }

    // Create client and test ping
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()

    rc, err := client.NewRedisClient(ctx, cfg)
    if err != nil {
        logger.Error("Redis connect error: %v", err)
        return CheckResult{
            Status: HealthStatusUnhealthy,
            Error:  fmt.Sprintf("Connection failed: %v", err),
        }
    }
    defer rc.Close()

    // Ping
    pong, err := rc.Ping(ctx).Result()
    if err != nil {
        logger.Error("Redis ping error: %v", err)
        return CheckResult{
            Status: HealthStatusUnhealthy,
            Error:  fmt.Sprintf("Ping failed: %v", err),
        }
    }

    // INFO server (optional, same as previous behavior)
    info, _ := rc.Info(ctx, "server").Result()
    metadata := map[string]interface{}{
        "ping_response": pong,
        "database":      cfg.DB,
        "pool_size":     cfg.PoolSize,
    }

    if strings.Contains(info, "redis_version") {
        lines := strings.Split(info, "\r\n")
        for _, line := range lines {
            if strings.HasPrefix(line, "redis_version:") {
                metadata["version"] = strings.TrimPrefix(line, "redis_version:")
                break
            }
        }
    }

    return CheckResult{
        Status:   HealthStatusHealthy,
        Message:  "Redis connection successful",
        Metadata: metadata,
    }
}

// Convert redis:// URL to client.RedisConfig (no behavior change)
func parseRedisURLToConfig(u string) (client.RedisConfig, error) {
    parsed, err := url.Parse(u)
    if err != nil {
        return client.RedisConfig{}, err
    }

    // Default host:port if missing port
    host := parsed.Host
    if host == "" {
        host = "127.0.0.1:6379"
    } else if !strings.Contains(host, ":") {
        host = host + ":6379"
    }

    // Password from URL userinfo
    var password string
    if parsed.User != nil {
        if p, ok := parsed.User.Password(); ok {
            password = p
        }
    }

    // DB number from path
    db := 0
    if len(parsed.Path) > 1 {
        if n, err := strconv.Atoi(strings.TrimPrefix(parsed.Path, "/")); err == nil {
            db = n
        }
    }

    // Keep defaults consistent with your client
    return client.RedisConfig{
        Address:         host,
        Password:        password,
        DB:              db,
        PoolSize:        10,                 // same sensible defaults as client
        MinIdleConns:    5,                  // half of PoolSize
        DialTimeout:     5 * time.Second,
        ReadTimeout:     3 * time.Second,
        WriteTimeout:    3 * time.Second,
        PoolTimeout:     4 * time.Second,
        ConnMaxIdleTime: 5 * time.Minute,
        CircuitBreaker: client.CircuitBreakerConfig{
            Enabled:      false, // health check should not be blocked by CB
            FailureRatio: 0.5,
            RecoveryTime: 30 * time.Second,
            MinRequests:  20,
        },
    }, nil
}

// ApplicationHealthChecker checks application-specific health
type ApplicationHealthChecker struct {
    config *config.Config
}

func (a *ApplicationHealthChecker) Name() string {
    return "application"
}

func (a *ApplicationHealthChecker) Check() CheckResult {
    metadata := map[string]interface{}{
        "environment":     a.config.Env,
        "compliance_mode": a.config.ComplianceMode,
        "port":            a.config.Port,
        "log_level":       a.config.LogLevel,
    }

    // Check if we're in a valid state
    if a.config.Env == "production" {
        if a.config.JWTSigningKey == "" {
            return CheckResult{
                Status:   HealthStatusUnhealthy,
                Message:  "Production secrets not configured",
                Metadata: metadata,
            }
        }
    }

    // Check OTP lifetime is valid
    if a.config.OTPLifetime != "" {
        if _, err := time.ParseDuration(a.config.OTPLifetime); err != nil {
            metadata["otp_lifetime_error"] = err.Error()
            return CheckResult{
                Status:   HealthStatusUnhealthy,
                Message:  "Invalid OTP lifetime configuration",
                Metadata: metadata,
            }
        }
        metadata["otp_lifetime"] = a.config.OTPLifetime
    }

    return CheckResult{
        Status:   HealthStatusHealthy,
        Message:  "Application configuration is valid",
        Metadata: metadata,
    }
}
