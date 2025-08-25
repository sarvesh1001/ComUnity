// internal/client/redis_client.go
package client

import (
    "context"
    "encoding/json"
    "fmt"
    "net"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "time"
    
    "github.com/ComUnity/auth-service/internal/util/logger"
    "github.com/redis/go-redis/v9"
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/trace"
)

// RedisConfig defines configuration for Redis client
type RedisConfig struct {
    Address         string               `yaml:"address"`
    Password        string               `yaml:"password"`
    DB              int                  `yaml:"db"`
    PoolSize        int                  `yaml:"pool_size"`
    MinIdleConns    int                  `yaml:"min_idle_conns"`
    MaxRetries      int                  `yaml:"max_retries"`
    DialTimeout     time.Duration        `yaml:"dial_timeout"`
    ReadTimeout     time.Duration        `yaml:"read_timeout"`
    WriteTimeout    time.Duration        `yaml:"write_timeout"`
    PoolTimeout     time.Duration        `yaml:"pool_timeout"`
    ConnMaxIdleTime time.Duration        `yaml:"conn_max_idle_time"`
    ConnMaxLifetime time.Duration        `yaml:"conn_max_lifetime"`
    DisableMetrics  bool                 `yaml:"disable_metrics"`
    CircuitBreaker  CircuitBreakerConfig `yaml:"circuit_breaker"`
}

type CircuitBreakerConfig struct {
    Enabled      bool          `yaml:"enabled"`
    FailureRatio float64       `yaml:"failure_ratio"`
    RecoveryTime time.Duration `yaml:"recovery_time"`
    MinRequests  uint64        `yaml:"min_requests"`
}

// RedisClient wraps redis.Client with additional features
type RedisClient struct {
    *redis.Client
    config RedisConfig
    mu     sync.RWMutex
    closed bool
    tracer trace.Tracer
    stats  *RedisStats
    cb     *circuitBreaker
}

type RedisStats struct {
    Commands    uint64
    Hits        uint64
    Misses      uint64
    Errors      uint64
    Timeouts    uint64
    CircuitOpen uint64
}

type circuitBreaker struct {
    mu           sync.Mutex
    state        string // "closed", "open", "half-open"
    failures     uint64
    successes    uint64
    total        uint64
    lastFailure  time.Time
    failureRatio float64
    recoveryTime time.Duration
    minRequests  uint64
}

// NewRedisClient creates a new Redis client instance
func NewRedisClient(ctx context.Context, cfg RedisConfig) (*RedisClient, error) {
    // Set defaults
    if cfg.PoolSize == 0 {
        cfg.PoolSize = 10 * runtime.GOMAXPROCS(0)
    }
    if cfg.MinIdleConns == 0 {
        cfg.MinIdleConns = cfg.PoolSize / 2
    }
    if cfg.DialTimeout == 0 {
        cfg.DialTimeout = 5 * time.Second
    }
    if cfg.ReadTimeout == 0 {
        cfg.ReadTimeout = 3 * time.Second
    }
    if cfg.WriteTimeout == 0 {
        cfg.WriteTimeout = 3 * time.Second
    }
    if cfg.PoolTimeout == 0 {
        cfg.PoolTimeout = 4 * time.Second
    }
    if cfg.ConnMaxIdleTime == 0 {
        cfg.ConnMaxIdleTime = 5 * time.Minute
    }

    // Create base client
    client := redis.NewClient(&redis.Options{
        Addr:            cfg.Address,
        Password:        cfg.Password,
        DB:              cfg.DB,
        PoolSize:        cfg.PoolSize,
        MinIdleConns:    cfg.MinIdleConns,
        MaxRetries:      cfg.MaxRetries,
        DialTimeout:     cfg.DialTimeout,
        ReadTimeout:     cfg.ReadTimeout,
        WriteTimeout:    cfg.WriteTimeout,
        PoolTimeout:     cfg.PoolTimeout,
        ConnMaxIdleTime: cfg.ConnMaxIdleTime,
        ConnMaxLifetime: cfg.ConnMaxLifetime,
        OnConnect: func(ctx context.Context, cn *redis.Conn) error {
            logger.Debug("New Redis connection established to %s", cfg.Address)
            return nil
        },
    })

    // Verify connection
    if err := client.Ping(ctx).Err(); err != nil {
        return nil, fmt.Errorf("redis ping failed: %w", err)
    }

    rc := &RedisClient{
        Client: client,
        config: cfg,
        tracer: otel.Tracer("redis"),
        stats:  &RedisStats{},
    }

    // Initialize circuit breaker
    if cfg.CircuitBreaker.Enabled {
        rc.cb = &circuitBreaker{
            state:        "closed",
            failureRatio: cfg.CircuitBreaker.FailureRatio,
            recoveryTime: cfg.CircuitBreaker.RecoveryTime,
            minRequests:  cfg.CircuitBreaker.MinRequests,
        }
    }

    // Add tracing hooks
    client.AddHook(rc.tracingHook())

    logger.Info("Redis client connected to %s (DB:%d)", cfg.Address, cfg.DB)
    return rc, nil
}

// Close terminates the Redis client connection
func (c *RedisClient) Close() error {
    c.mu.Lock()
    defer c.mu.Unlock()
    if c.closed {
        return nil
    }
    c.closed = true
    logger.Info("Closing Redis client")
    return c.Client.Close()
}

// HealthCheck verifies Redis connectivity
func (c *RedisClient) HealthCheck(ctx context.Context) error {
    if c.isCircuitOpen() {
        return fmt.Errorf("redis circuit breaker open")
    }
    err := c.Ping(ctx).Err()
    if err != nil {
        c.recordFailure()
        return fmt.Errorf("redis health check failed: %w", err)
    }
    c.recordSuccess()
    return nil
}

// Stats returns current Redis client statistics
func (c *RedisClient) Stats() RedisStats {
    c.mu.RLock()
    defer c.mu.RUnlock()
    return *c.stats
}

// WithContext adds tracing to Redis operations
func (c *RedisClient) WithContext(ctx context.Context) *RedisClient {
    // Returns the same client since we use hooks
    return c
}

// InstrumentedDo executes a Redis command with instrumentation
func (c *RedisClient) InstrumentedDo(ctx context.Context, fn func(ctx context.Context) error) error {
    // Check circuit breaker
    if c.isCircuitOpen() {
        c.stats.CircuitOpen++
        return fmt.Errorf("redis circuit breaker open")
    }

    // Execute with tracing
    start := time.Now()
    err := fn(ctx)
    duration := time.Since(start)

    c.mu.Lock()
    defer c.mu.Unlock()
    c.stats.Commands++
    if err != nil {
        c.stats.Errors++
        if isTimeoutError(err) {
            c.stats.Timeouts++
        }
        c.recordFailure()
    } else {
        c.recordSuccess()
    }

    // Record latency metrics
    if !c.config.DisableMetrics {
        recordRedisLatency(duration, err == nil)
    }
    return err
}

// CircuitBreakerState returns current circuit breaker status
func (c *RedisClient) CircuitBreakerState() string {
    if c.cb == nil {
        return "disabled"
    }
    c.cb.mu.Lock()
    defer c.cb.mu.Unlock()
    return c.cb.state
}

// --- Internal Methods ---

func (c *RedisClient) tracingHook() redis.Hook {
    return tracingHook{}
}

type tracingHook struct{}

// DialHook implements the optional DialHook for go-redis v9 hooks.
func (t tracingHook) DialHook(next redis.DialHook) redis.DialHook {
    return func(ctx context.Context, network, addr string) (net.Conn, error) {
        // Optionally add tracing here:
        // span := trace.SpanFromContext(ctx)
        // if span.IsRecording() {
        //     span.SetAttributes(
        //         attribute.String("net.transport", network),
        //         attribute.String("net.peer.name", addr),
        //     )
        // }
        return next(ctx, network, addr)
    }
}

// ProcessHook adapts Before/AfterProcess to the v9 hook form.
func (t tracingHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
    return func(ctx context.Context, cmd redis.Cmder) error {
        // Before
        var err error
        if ctx, err = t.BeforeProcess(ctx, cmd); err != nil {
            return err
        }
        // Invoke downstream
        err = next(ctx, cmd)
        // After
        if aerr := t.AfterProcess(ctx, cmd); aerr != nil && err == nil {
            err = aerr
        }
        return err
    }
}

// ProcessPipelineHook adapts Before/AfterProcessPipeline to the v9 hook form.
func (t tracingHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
    return func(ctx context.Context, cmds []redis.Cmder) error {
        // Before
        var err error
        if ctx, err = t.BeforeProcessPipeline(ctx, cmds); err != nil {
            return err
        }
        // Invoke downstream
        err = next(ctx, cmds)
        // After
        if aerr := t.AfterProcessPipeline(ctx, cmds); aerr != nil && err == nil {
            err = aerr
        }
        return err
    }
}

func (t tracingHook) BeforeProcess(ctx context.Context, cmd redis.Cmder) (context.Context, error) {
    if !trace.SpanFromContext(ctx).IsRecording() {
        return ctx, nil
    }
    span := trace.SpanFromContext(ctx)
    span.SetAttributes(
        attribute.String("db.system", "redis"),
        attribute.String("db.operation", cmd.Name()),
        attribute.String("db.statement", cmd.String()),
    )
    return ctx, nil
}

func (t tracingHook) AfterProcess(ctx context.Context, cmd redis.Cmder) error {
    if span := trace.SpanFromContext(ctx); span.IsRecording() {
        if err := cmd.Err(); err != nil && err != redis.Nil {
            span.RecordError(err)
        }
    }
    return nil
}

func (t tracingHook) BeforeProcessPipeline(ctx context.Context, cmds []redis.Cmder) (context.Context, error) {
    if !trace.SpanFromContext(ctx).IsRecording() {
        return ctx, nil
    }
    span := trace.SpanFromContext(ctx)
    span.SetAttributes(
        attribute.String("db.system", "redis"),
        attribute.String("db.operation", "pipeline"),
        attribute.Int("db.command_count", len(cmds)),
    )
    return ctx, nil
}

func (t tracingHook) AfterProcessPipeline(ctx context.Context, cmds []redis.Cmder) error {
    if span := trace.SpanFromContext(ctx); span.IsRecording() {
        for _, cmd := range cmds {
            if err := cmd.Err(); err != nil && err != redis.Nil {
                span.RecordError(err)
                break
            }
        }
    }
    return nil
}

func (c *RedisClient) isCircuitOpen() bool {
    if c.cb == nil {
        return false
    }
    c.cb.mu.Lock()
    defer c.cb.mu.Unlock()

    if c.cb.state == "open" {
        if time.Since(c.cb.lastFailure) > c.cb.recoveryTime {
            c.cb.state = "half-open"
            c.cb.failures = 0
            c.cb.successes = 0
            c.cb.total = 0
            logger.Warn("Redis circuit moving to half-open state")
        } else {
            return true
        }
    }
    return false
}

func (c *RedisClient) recordFailure() {
    if c.cb == nil {
        return
    }
    c.cb.mu.Lock()
    defer c.cb.mu.Unlock()

    c.cb.failures++
    c.cb.total++
    c.cb.lastFailure = time.Now()

    if c.cb.state == "half-open" {
        c.cb.state = "open"
        logger.Error("Redis circuit re-opened after failure")
        return
    }
    if c.cb.total >= c.cb.minRequests {
        failureRatio := float64(c.cb.failures) / float64(c.cb.total)
        if failureRatio >= c.cb.failureRatio {
            c.cb.state = "open"
            logger.Error("Redis circuit opened due to high failure ratio: %.2f", failureRatio)
        }
    }
}

func (c *RedisClient) recordSuccess() {
    if c.cb == nil {
        return
    }
    c.cb.mu.Lock()
    defer c.cb.mu.Unlock()

    c.cb.successes++
    c.cb.total++

    if c.cb.state == "half-open" && c.cb.successes >= c.cb.minRequests/2 {
        c.cb.state = "closed"
        c.cb.failures = 0
        c.cb.successes = 0
        c.cb.total = 0
        logger.Warn("Redis circuit closed after successful operations")
    }
}

func isTimeoutError(err error) bool {
    if err == nil {
        return false
    }
    if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
        return true
    }
    // Check for Redis-specific timeouts
    if strings.Contains(err.Error(), "i/o timeout") {
        return true
    }
    return false
}

func recordRedisLatency(duration time.Duration, success bool) {
    // Integrate with your metrics system (Prometheus, OpenTelemetry, etc.)
    // Example:
    // metrics.RecordRedisLatency(duration, success)
}

// --- Helper Functions ---

// GetInt returns an integer value from Redis
func (c *RedisClient) GetInt(ctx context.Context, key string) (int, error) {
    val, err := c.Get(ctx, key).Result()
    if err == redis.Nil {
        return 0, nil
    }
    if err != nil {
        return 0, err
    }
    return strconv.Atoi(val)
}

// IncrementWithTTL atomically increments a key and sets TTL if not set
func (c *RedisClient) IncrementWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error) {
    script := redis.NewScript(`
local current = redis.call("GET", KEYS[1])
if current == false then
  current = 0
  redis.call("SET", KEYS[1], current, "EX", ARGV[1])
end
return redis.call("INCR", KEYS[1])
`)
    val, err := script.Run(ctx, c.Client, []string{key}, int(ttl.Seconds())).Int64()
    if err != nil {
        return 0, fmt.Errorf("incrementWithTTL failed: %w", err)
    }
    return val, nil
}

// SetJSON marshals and sets a JSON value
func (c *RedisClient) SetJSON(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
    jsonData, err := json.Marshal(value)
    if err != nil {
        return err
    }
    return c.Set(ctx, key, jsonData, ttl).Err()
}

// GetJSON retrieves and unmarshals a JSON value
func (c *RedisClient) GetJSON(ctx context.Context, key string, dest interface{}) error {
    data, err := c.Get(ctx, key).Result()
    if err != nil {
        return err
    }
    return json.Unmarshal([]byte(data), dest)
}

// HGetAllMap returns hash as map[string]string
func (c *RedisClient) HGetAllMap(ctx context.Context, key string) (map[string]string, error) {
    return c.HGetAll(ctx, key).Result()
}

// Pipeline executes a pipeline of commands
func (c *RedisClient) Pipeline(ctx context.Context, fn func(pipe redis.Pipeliner) error) error {
    return c.InstrumentedDo(ctx, func(ctx context.Context) error {
        _, err := c.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
            return fn(pipe)
        })
        return err
    })
}

// Lock acquires a distributed lock
func (c *RedisClient) Lock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
    return c.SetNX(ctx, key, "locked", ttl).Result()
}

// Unlock releases a distributed lock
func (c *RedisClient) Unlock(ctx context.Context, key string) error {
    return c.Del(ctx, key).Err()
}
// NewScript exposes redis.NewScript through the client package for convenience.
func NewScript(script string) *redis.Script {
    return redis.NewScript(script)
}