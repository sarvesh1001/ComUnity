package main

import (
    "context"
    "crypto/tls"
    "database/sql"
    "encoding/json"
    "fmt"
    "net/http"
    "os/signal"
    "syscall"
    "time"

    "github.com/go-chi/chi/v5"
    chimw "github.com/go-chi/chi/v5/middleware"
    "github.com/redis/go-redis/v9"
    _ "github.com/lib/pq"
    "github.com/google/uuid"
    "github.com/aws/aws-sdk-go-v2/service/kms/types" // Add this import

    "github.com/ComUnity/auth-service/internal/client"
    "github.com/ComUnity/auth-service/internal/handler"
    "github.com/ComUnity/auth-service/internal/loader"
    "github.com/ComUnity/auth-service/internal/middleware"
    "github.com/ComUnity/auth-service/internal/models"
    "github.com/ComUnity/auth-service/internal/repository"
    "github.com/ComUnity/auth-service/internal/service"
    "github.com/ComUnity/auth-service/internal/telemetry"
    "github.com/ComUnity/auth-service/internal/util"
    "github.com/ComUnity/auth-service/internal/util/logger"
    "github.com/ComUnity/auth-service/security"
    // Add compliance imports
    "github.com/ComUnity/auth-service/compliance"
    "github.com/ComUnity/auth-service/compliance/audit"
    "github.com/ComUnity/auth-service/compliance/incident"
)

var version = "development"

type SMSProvider interface {
    SendOTP(ctx context.Context, phone, code string) error
}

type stubSMS struct{}

func (s *stubSMS) SendOTP(ctx context.Context, phone, code string) error {
    logger.Infof("Stub SMS: sending OTP %s to %s", code, phone)
    return nil
}

// KMSAdapter implements KMSKeyProvider interface for JWT manager
type KMSAdapter struct {
    helper *security.Helper
}

func (k *KMSAdapter) GenerateDataKey(ctx context.Context, keySpec string) (interface{ GetPlaintext() []byte }, error) {
    // Convert string to kmstypes.DataKeySpec
    var spec types.DataKeySpec
    switch keySpec {
    case "AES_256":
        spec = types.DataKeySpecAes256
    case "AES_128":  
        spec = types.DataKeySpecAes128
    default:
        spec = types.DataKeySpecAes256
    }
    
    return k.helper.GenerateDataKey(ctx, spec)
}

// ComplianceKMSAdapter implements compliance.KMS interface
type ComplianceKMSAdapter struct {
    helper *security.Helper
}

func (k *ComplianceKMSAdapter) GenerateDataKey(ctx context.Context, keySpec string) (interface{ GetPlaintext() []byte }, error) {
    var spec types.DataKeySpec
    switch keySpec {
    case "AES_256":
        spec = types.DataKeySpecAes256
    case "AES_128":  
        spec = types.DataKeySpecAes128
    default:
        spec = types.DataKeySpecAes256
    }
    
    return k.helper.GenerateDataKey(ctx, spec)
}

func main() {
    // Load config
    configPath := "config/app-config.yaml"
    cfg, err := loader.LoadConfig(configPath)
    if err != nil {
        panic(fmt.Errorf("failed to load config: %w", err))
    }

    // Init logger
    logger.ReplaceGlobal(&logger.Config{
        Level:  cfg.Logger.Level,
        Format: cfg.Logger.Encoding,
    })
    defer logger.Sync()
    _, _ = logger.Init(logger.SlogConfig{
        Level:     cfg.Logger.Level,
        Encoding:  cfg.Logger.Encoding,
        Output:    cfg.Logger.Output,
        AddSource: cfg.Logger.AddSource,
    })

    // Redis using your custom client
    ropts, err := redis.ParseURL(cfg.RedisURL)
    if err != nil {
        logger.Fatalf("Invalid redis_url: %v", err)
    }
    rcli, err := client.NewRedisClient(context.Background(), client.RedisConfig{
        Address:      ropts.Addr,
        Password:     ropts.Password,
        DB:           ropts.DB,
        PoolSize:     200,
        MinIdleConns: 50,
    })
    if err != nil {
        logger.Fatalf("Redis init failed: %v", err)
    }
    defer rcli.Close()

    // DB
    db, err := sql.Open("postgres", cfg.DatabaseURL)
    if err != nil {
        logger.Fatalf("DB open error: %v", err)
    }
    defer db.Close()

    // Initialize KMS Helper
    kmsHelper, err := security.NewKMSHelper(context.Background(), security.KMSConfig{
        KeyID:             cfg.KMS.KeyID,
        Timeout:           time.Duration(cfg.KMS.TimeoutMS) * time.Millisecond,
        PublicKeyCacheTTL: time.Duration(cfg.KMS.PublicKeyCacheTTLMS) * time.Millisecond,
        EncryptionContext: cfg.KMS.EncryptionContext,
    })
    if err != nil {
        logger.Fatalf("Failed to initialize KMS helper: %v", err)
    }

    // Initialize Certificate Manager
    certManager, err := security.NewCertificateManager(rcli, kmsHelper, security.CertificateConfig{
        Enabled:              true, // Enable for production
        CertificateLifetime:  90 * 24 * time.Hour,      // 90 days
        RenewalThreshold:     30 * 24 * time.Hour,      // Renew 30 days before expiry
        KeySize:              4096,                     // Strong RSA keys
        Organization:         "ComUnity Auth Service",
        Country:              "US",
        Province:             "California", 
        City:                 "San Francisco",
        AutoRenew:            true,
        EnableOCSP:           false,
        CRLDistributionPoint: "http://crl.comunity.com/auth-service.crl",
        ServiceDomains: map[string][]string{
            "auth-service":     {"auth.comunity.com", "api.comunity.com"},
            "user-service":     {"users.comunity.com"},
            "community-service": {"communities.comunity.com"},
            "notification-service": {"notifications.comunity.com"},
            "billing-service":  {"billing.comunity.com"},
        },
        CAConfig: security.CAConfig{
            KeySize:      4096,
            Lifetime:     10 * 365 * 24 * time.Hour, // 10 years
            CommonName:   "ComUnity Root CA",
            Organization: "ComUnity",
            KeyUsage:     []string{"cert_sign", "crl_sign"},
            EnablePathLen: true,
            MaxPathLen:   2,
        },
    })
    if err != nil {
        logger.Fatalf("Failed to initialize certificate manager: %v", err)
    }

    // Initialize mTLS Manager
    mtlsManager, err := security.NewMTLSManager(security.MTLSConfig{
        Enabled:              true, // Enable for production
        RequireClientCert:    true,
        VerifyClientCert:     true,
        AllowedServices: map[string][]string{
            "auth-service": {
                "user-service.comunity.com", 
                "community-service.comunity.com",
                "notification-service.comunity.com",
                "billing-service.comunity.com",
            },
            "user-service":    {"auth-service.comunity.com"},
            "community-service": {"auth-service.comunity.com"},
            "notification-service": {"auth-service.comunity.com"},
            "billing-service": {"auth-service.comunity.com"},
        },
        ServicePorts: map[string]int{
            "auth-service":         8443,
            "user-service":         8444,
            "community-service":    8445,
            "notification-service": 8446,
            "billing-service":      8447,
        },
        CipherSuites: []string{
            "TLS_AES_256_GCM_SHA384", 
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
        },
        MinTLSVersion:        "1.3", // Force TLS 1.3
        MaxTLSVersion:        "1.3",
        EnableOCSP:           false,
        OCSPStapling:         false,
        SessionTimeout:       300 * time.Second,
        RenegotiationSupport: "never",
    }, certManager)
    if err != nil {
        logger.Fatalf("Failed to initialize mTLS manager: %v", err)
    }

    // Issue initial certificate for auth service
    logger.Info("Issuing initial certificate for auth-service...")
    _, err = certManager.IssueCertificate(context.Background(), 
        "auth-service", 
        "auth.comunity.com", 
        []string{"auth.comunity.com", "api.comunity.com", "internal.comunity.com"})
    if err != nil {
        logger.Warn("Failed to issue auth service certificate", "error", err)
    } else {
        logger.Info("Auth service certificate issued successfully")
    }

    // Initialize repositories using your existing code
    roleRepo := repository.NewCockroachRoleRepository(db)
    userRepo := repository.NewCockroachUserRepository(db)
    communityRepo := repository.NewCockroachCommunityRepository(db)
    consentRepo := repository.NewCockroachConsentRepository(db)
    schoolRepo := repository.NewCockroachSchoolRepository(db)
    cacheRepo := repository.NewRedisCacheRepository(rcli)

    // Initialize JWT Manager using KMS adapter
    kmsAdapter := &KMSAdapter{helper: kmsHelper}
    jwtManager := util.NewJWTManager(
        util.JWTConfig{
            AccessTokenDuration:  15 * time.Minute,
            RefreshTokenDuration: 7 * 24 * time.Hour,
            IDTokenDuration:      1 * time.Hour,
            Issuer:               "auth.comunity.com",
            Audience:             []string{"comunity-app"},
            KMSKeyID:             cfg.KMS.KeyID,
            MaxCommunityRoles:    50, // Keep JWT size bounded for 100M users
        },
        kmsAdapter,  // Use the adapter instead of kmsHelper
        userRepo,
        roleRepo,
        cacheRepo,
    )

    // Initialize Session Encryptor
    sessionEncryptor := security.NewSessionEncryptor(rcli, *kmsHelper, security.SessionEncryptorConfig{
        Enabled:              true,
        SessionDuration:      24 * time.Hour,      // 24 hour sessions
        IdleTimeout:          2 * time.Hour,       // 2 hour idle timeout
        ExtendOnActivity:     true,                // Extend session on activity
        MaxSessions:          10,                  // Max 10 concurrent sessions per user
        RequireDeviceMatch:   true,                // Require device fingerprint match
        CookieName:           "auth_session",      // Session cookie name
        CookieDomain:         "",                  // Set your domain
        CookieSecure:         cfg.Env != "development", // Secure in production
        CookieHTTPOnly:       true,                // HTTP only cookies
        CookieSameSite:       "strict",            // CSRF protection
        EncryptionVersion:    1,                   // Current encryption version
    })

    // Initialize Token Rotator
    tokenRotator := security.NewTokenRotator(
        rcli,
        jwtManager,
        userRepo,
        roleRepo,
        security.TokenRotationConfig{
            Enabled:             true,
            RotationInterval:    6 * time.Hour,    // Rotate every 6 hours
            GracePeriod:         30 * time.Minute, // 30 minute grace period
            MaxActiveTokens:     10000,            // Max tokens to process per cycle
            BatchSize:           100,              // Process 100 tokens per batch
            WorkerCount:         5,                // 5 concurrent workers
            NotificationWebhook: "",               // Optional webhook for notifications
        },
    )

    // Start Token Rotator service
    go func() {
        if err := tokenRotator.Start(context.Background()); err != nil {
            logger.Error("Token rotator service failed", "error", err)
        }
    }()
    defer tokenRotator.Stop()

    // Initialize Compliance Systems

    // 1. Audit Exporter
    auditExporter := audit.NewAuditExporter(audit.ExportConfig{
        Enabled:          true,
        ESConfig:         cfg.Telemetry.ES,
        MaxBatchSize:     10000,
        MaxExportSize:    1 << 30, // 1GB
        ExportFormats:    []audit.ExportFormat{audit.FormatJSON, audit.FormatCSV},
        ComplianceStandards: []audit.ComplianceStandard{
            audit.StandardGDPR,
            audit.StandardCCPA,
            audit.StandardISO27001,
        },
        EncryptExports:   true,
        SignExports:      false,
        S3Config: audit.S3Config{
            Enabled:    false, // Enable if using S3
            Bucket:     "comunity-compliance-exports",
            Region:     "us-west-2",
            Prefix:     "audit-exports/",
            KMSKeyID:   cfg.KMS.KeyID,
        },
        RetentionPeriods: map[string]time.Duration{
            "audit_logs":      90 * 24 * time.Hour,
            "user_data":       3 * 365 * 24 * time.Hour,
            "session_data":    30 * 24 * time.Hour,
            "device_data":     180 * 24 * time.Hour,
            "otp_data":        7 * 24 * time.Hour,
        },
    }, rcli, kmsHelper)

    // 2. Data Retention Manager using compliance KMS adapter
    complianceKMSAdapter := &ComplianceKMSAdapter{helper: kmsHelper}
    retentionManager := compliance.NewDataRetentionManager(
        compliance.RetentionConfig{
            Enabled:              true,
            DefaultRetention:     90 * 24 * time.Hour,      // 90 days default
            MinRetention:         24 * time.Hour,           // 1 day minimum
            MaxRetention:         10 * 365 * 24 * time.Hour, // 10 years maximum
            ExecutionInterval:    24 * time.Hour,           // Daily execution
            BatchSize:            1000,
            MaxConcurrency:       5,
            DryRunDefault:        false, // Set to true for testing
            AuditRetention:       true,
            BackupBeforeDeletion: true,
            ESConfig: compliance.ESRetentionConfig{
                Endpoint:    cfg.Telemetry.ES.Endpoint,
                Username:    cfg.Telemetry.ES.Username,
                Password:    cfg.Telemetry.ES.Password,
                APIKey:      cfg.Telemetry.ES.APIKey,
                IndexPrefix: "audit",
            },
            CategoryPolicies: map[compliance.DataCategory]compliance.CategoryPolicy{
                compliance.CategoryAuditLogs: {
                    DefaultRetention: 90 * 24 * time.Hour,
                    MinRetention:     1 * 24 * time.Hour,
                    MaxRetention:     365 * 24 * time.Hour,
                    DeletionMethod:   compliance.MethodHardDelete,
                    RequireBackup:    false,
                    AuditRequired:    true,
                },
                compliance.CategoryUserData: {
                    DefaultRetention: 3 * 365 * 24 * time.Hour,
                    MinRetention:     30 * 24 * time.Hour,
                    MaxRetention:     10 * 365 * 24 * time.Hour,
                    DeletionMethod:   compliance.MethodAnonymize,
                    RequireBackup:    true,
                    AuditRequired:    true,
                },
                compliance.CategorySessionData: {
                    DefaultRetention: 30 * 24 * time.Hour,
                    MinRetention:     1 * 24 * time.Hour,
                    MaxRetention:     90 * 24 * time.Hour,
                    DeletionMethod:   compliance.MethodHardDelete,
                    RequireBackup:    false,
                    AuditRequired:    false,
                },
                compliance.CategoryDeviceData: {
                    DefaultRetention: 180 * 24 * time.Hour,
                    MinRetention:     30 * 24 * time.Hour,
                    MaxRetention:     365 * 24 * time.Hour,
                    DeletionMethod:   compliance.MethodSoftDelete,
                    RequireBackup:    false,
                    AuditRequired:    true,
                },
                compliance.CategoryOTPData: {
                    DefaultRetention: 7 * 24 * time.Hour,
                    MinRetention:     1 * 24 * time.Hour,
                    MaxRetention:     30 * 24 * time.Hour,
                    DeletionMethod:   compliance.MethodHardDelete,
                    RequireBackup:    false,
                    AuditRequired:    false,
                },
            },
            ComplianceSettings: compliance.ComplianceSettings{
                GDPR: compliance.GDPRSettings{
                    Enabled:                   true,
                    DefaultRetention:          3 * 365 * 24 * time.Hour,
                    UserDataRetention:         3 * 365 * 24 * time.Hour,
                    ConsentWithdrawalGrace:    72 * time.Hour,
                    RightToErasureEnabled:     true,
                    DataPortabilityEnabled:    true,
                    AutoDeleteInactiveUsers:   true,
                    InactiveUserThreshold:     2 * 365 * 24 * time.Hour,
                },
                CCPA: compliance.CCPASettings{
                    Enabled:                  true,
                    BusinessRecordsRetention: 3 * 365 * 24 * time.Hour,
                    ConsumerDataRetention:    365 * 24 * time.Hour,
                    RightToDeleteEnabled:     true,
                    SaleOptOutRetention:      2 * 365 * 24 * time.Hour,
                },
                HIPAA: compliance.HIPAASettings{
                    Enabled:                false, // Enable if handling health data
                    PHIRetention:           6 * 365 * 24 * time.Hour,
                    AuditLogRetention:      6 * 365 * 24 * time.Hour,
                    BackupRequirement:      true,
                    SecureDeletionRequired: true,
                },
            },
        },
        db, rcli, complianceKMSAdapter, userRepo, cacheRepo,
    )

    // 3. Incident Manager
    incidentManager := incident.NewIncidentManager(
        incident.IncidentConfig{
            Enabled:             true,
            AutoResponse:        true,
            MaxConcurrentEvents: 1000,
            EventBufferSize:     10000,
            DetectionInterval:   30 * time.Second,
            AlertThresholds: map[string]int{
                "auth_failures":     20,
                "otp_failures":      10,
                "high_risk_score":   1,
                "error_rate":        15,
                "performance_slow":  10,
            },
            SuspiciousThresholds: map[string]float64{
                "risk_score":     0.8,
                "failure_rate":   0.5,
                "error_rate":     0.1,
            },
            AutoContainment:    true,
            EscalationTimeout:  4 * time.Hour,
            MaxEscalationLevel: 3,
            NotificationChannels: []incident.NotificationChannel{
                {
                    Name: "security-alerts",
                    Type: "slack",
                    Config: map[string]string{
                        "webhook_url": "", // Set your Slack webhook
                        "channel":     "#security-alerts",
                    },
                    Severity:   []incident.IncidentSeverity{incident.SeverityCritical, incident.SeverityHigh},
                    Categories: []incident.IncidentCategory{
                        incident.CategoryDataBreach,
                        incident.CategorySecurityThreat,
                        incident.CategoryComplianceViolation,
                    },
                },
                {
                    Name: "ops-alerts",
                    Type: "email",
                    Config: map[string]string{
                        "smtp_server": "smtp.gmail.com",
                        "recipients":  "ops@comunity.com,security@comunity.com",
                    },
                    Severity:   []incident.IncidentSeverity{incident.SeverityCritical, incident.SeverityHigh, incident.SeverityMedium},
                    Categories: []incident.IncidentCategory{
                        incident.CategorySystemFailure,
                        incident.CategoryAuthFailure,
                        incident.CategorySuspiciousActivity,
                    },
                },
            },
            EscalationPaths: map[incident.IncidentSeverity][]string{
                incident.SeverityCritical: {"security-team", "engineering-manager", "cto"},
                incident.SeverityHigh:     {"security-team", "engineering-manager"},
                incident.SeverityMedium:   {"security-team"},
                incident.SeverityLow:      {"ops-team"},
            },
            ComplianceReporting: true,
            RegulatoryDeadlines: map[string]time.Duration{
                "GDPR_breach_notification": 72 * time.Hour,
                "CCPA_breach_notification": 24 * time.Hour,
            },
        },
        db, rcli, kmsHelper,
    )

    // Services/handlers
    sms := &stubSMS{}
    otpSvc := service.NewOTPService(rcli, cfg.OTP, sms)
    otpRepo := repository.NewCockroachOTPRepository(db)
    senderName := "sms"
    otpHandler := handler.NewOTPHandler(otpSvc, otpRepo, senderName)

    // Device fingerprinting
    fpCfg, err := middleware.BuildFingerprintConfigFromApp(cfg.Fingerprint)
    if err != nil {
        logger.Fatalf("Fingerprint config invalid: %v", err)
    }
    fpMW := middleware.DeviceFingerprintMiddleware(fpCfg)

    // RBAC services with JWT integration
    entChecker := service.NewEntitlementChecker()
    roleService := service.NewRoleService(roleRepo, userRepo, communityRepo, cacheRepo, entChecker, "1.0")

    // Initialize RBAC handler
    roleHandler := handler.NewRoleHandler(roleService)

    // Child Safety Repo + Service
    consentManager := service.NewConsentManager(consentRepo)
    childProfileHandler := handler.NewChildProfileHandler(consentManager)

    // School Repo + Service
    schoolValidator := service.NewSchoolValidator(schoolRepo)
    schoolHandler := handler.NewSchoolHandler(schoolValidator)

    // Router with session middleware
    r := chi.NewRouter()
    r.Use(fpMW) // Device fingerprinting first
    r.Use(sessionEncryptor.SessionMiddleware()) // Session handling second
    r.Use(chimw.RequestID, chimw.RealIP, chimw.Recoverer, chimw.Timeout(10*time.Second))
    r.Use(chimw.Logger)

    // Health - Fixed config pointer issue
    healthHandler := handler.NewHealthHandler(cfg, version)
    r.Handle("/health", healthHandler)
    r.HandleFunc("/ready", healthHandler.ReadinessHandler)
    r.HandleFunc("/live", healthHandler.LivenessHandler)

    // JWT Auth routes with session integration
    r.Route("/auth", func(rt chi.Router) {
        rt.Post("/login", LoginHandler(jwtManager, userRepo, roleRepo, sessionEncryptor, tokenRotator))
        rt.Post("/refresh", RefreshTokenHandler(jwtManager, tokenRotator))
        rt.Post("/logout", LogoutHandler(jwtManager, sessionEncryptor, tokenRotator))
        rt.Handle("/profile", JWTMiddleware(jwtManager, tokenRotator)(http.HandlerFunc(ProfileHandler)))
        
        // Session-specific routes
        rt.Post("/session/refresh", SessionRefreshHandler(sessionEncryptor))
        rt.Get("/session/info", SessionInfoHandler(sessionEncryptor))
        rt.Delete("/session/invalidate", InvalidateSessionHandler(sessionEncryptor))
        rt.Delete("/sessions/invalidate-all", InvalidateAllSessionsHandler(sessionEncryptor))
    })

        // Token rotation management routes (admin only)
		r.Route("/admin/tokens", func(rt chi.Router) {
			rt.Use(JWTMiddleware(jwtManager, tokenRotator))
			rt.Use(RequirePermission("admin:tokens:manage", roleService))
			
			rt.Get("/stats", TokenRotationStatsHandler(tokenRotator))
			rt.Post("/rotate/trigger", TriggerTokenRotationHandler(tokenRotator))
			rt.Get("/active", GetActiveTokensHandler(tokenRotator))
			rt.Delete("/revoke/{tokenID}", RevokeTokenHandler(tokenRotator))
		})
	
		// Certificate management admin routes
		r.Route("/admin/certificates", func(rt chi.Router) {
			rt.Use(JWTMiddleware(jwtManager, tokenRotator))
			rt.Use(RequirePermission("admin:certificates:manage", roleService))
			
			rt.Get("/stats", CertificateStatsHandler(certManager))
			rt.Post("/issue", IssueCertificateHandler(certManager))
			rt.Put("/{certId}/renew", RenewCertificateHandler(certManager))
			rt.Delete("/{certId}/revoke", RevokeCertificateHandler(certManager))
			rt.Get("/ca-bundle", CABundleHandler(certManager))
			rt.Get("/service/{serviceName}", GetServiceCertificateHandler(certManager))
		})
	
		// mTLS management admin routes
		r.Route("/admin/mtls", func(rt chi.Router) {
			rt.Use(JWTMiddleware(jwtManager, tokenRotator))
			rt.Use(RequirePermission("admin:mtls:manage", roleService))
			
			rt.Get("/stats", MTLSStatsHandler(mtlsManager))
			rt.Post("/validate-cert", ValidateCertificateHandler(certManager))
			rt.Get("/service-auth/{serviceName}", GetServiceAuthHandler())
		})
	
		// Compliance Management Admin Routes
		r.Route("/admin/compliance", func(rt chi.Router) {
			rt.Use(JWTMiddleware(jwtManager, tokenRotator))
			rt.Use(RequirePermission("admin:compliance:manage", roleService))
			
			// Audit Export Management
			rt.Route("/audit", func(art chi.Router) {
				art.Get("/stats", ComplianceAuditStatsHandler(auditExporter))
				art.Post("/export", CreateAuditExportHandler(auditExporter))
				art.Get("/export/{exportId}", GetAuditExportHandler(auditExporter))
				art.Get("/exports", ListAuditExportsHandler(auditExporter))
				art.Delete("/export/{exportId}", CancelAuditExportHandler(auditExporter))
			})
			
			// Data Retention Management
			rt.Route("/retention", func(rrt chi.Router) {
				rrt.Get("/stats", RetentionStatsHandler(retentionManager))
				rrt.Get("/policies", ListRetentionPoliciesHandler(retentionManager))
				rrt.Post("/policy", CreateRetentionPolicyHandler(retentionManager))
				rrt.Get("/policy/{policyId}", GetRetentionPolicyHandler(retentionManager))
				rrt.Put("/policy/{policyId}", UpdateRetentionPolicyHandler(retentionManager))
				rrt.Delete("/policy/{policyId}", DeleteRetentionPolicyHandler(retentionManager))
				rrt.Post("/policy/{policyId}/execute", ExecuteRetentionPolicyHandler(retentionManager))
				rrt.Get("/execution/{executionId}", GetRetentionExecutionHandler(retentionManager))
				rrt.Get("/executions", ListRetentionExecutionsHandler(retentionManager))
			})
			
			// Incident Management
			rt.Route("/incidents", func(irt chi.Router) {
				irt.Get("/stats", IncidentStatsHandler(incidentManager))
				irt.Get("/", ListIncidentsHandler(incidentManager))
				irt.Post("/", CreateIncidentHandler(incidentManager))
				irt.Get("/{incidentId}", GetIncidentHandler(incidentManager))
				irt.Put("/{incidentId}", UpdateIncidentHandler(incidentManager))
				irt.Post("/{incidentId}/close", CloseIncidentHandler(incidentManager))
				irt.Post("/{incidentId}/action", AddIncidentActionHandler(incidentManager))
				irt.Get("/{incidentId}/actions", GetIncidentActionsHandler(incidentManager))
			})
		})
	
		// GDPR/CCPA User Data Rights Routes
		r.Route("/privacy", func(prt chi.Router) {
			prt.Use(JWTMiddleware(jwtManager, tokenRotator))
			
			// User data export (GDPR Article 20 - Right to data portability)
			prt.Get("/export", UserDataExportHandler(auditExporter, retentionManager))
			prt.Get("/export/{exportId}/download", DownloadUserDataExportHandler(auditExporter))
			
			// User data deletion (GDPR Article 17 - Right to erasure)
			prt.Post("/delete", UserDataDeletionRequestHandler(retentionManager))
			prt.Get("/deletion-status", UserDataDeletionStatusHandler(retentionManager))
			
			// Data retention information (GDPR Article 13/14 - Information to be provided)
			prt.Get("/retention-info", UserRetentionInfoHandler(retentionManager))
		})
	
		// Internal service communication routes with mTLS
		r.Route("/internal", func(rt chi.Router) {
			rt.Use(mtlsManager.MTLSMiddleware("auth-service"))
			rt.Use(security.RequireServiceAuth("user-service", "community-service", "notification-service", "billing-service"))
			
			// Internal service endpoints
			rt.Get("/health", func(w http.ResponseWriter, r *http.Request) {
				if auth, ok := security.GetServiceAuthFromContext(r.Context()); ok {
					logger.Info("Internal health check", "from_service", auth.ServiceName)
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"ok","internal":true}`))
			})
			
			rt.Post("/validate-token", InternalTokenValidationHandler(jwtManager))
			rt.Post("/user-permissions", InternalUserPermissionsHandler(roleService))
			rt.Post("/rotate-tokens", InternalTokenRotationHandler(tokenRotator))
			rt.Get("/certificate/{serviceName}", InternalGetCertificateHandler(certManager))
			
			// Internal compliance endpoints for service coordination
			rt.Post("/compliance/incident", InternalIncidentReportHandler(incidentManager))
			rt.Post("/compliance/retention/user-deleted", InternalUserDeletedHandler(retentionManager))
		})
	
		// OTP routes
		indiaLimiter := middleware.NewIndiaOTPLimiter(rcli, cfg.IndiaOTPRateLimit)
		r.Group(func(rt chi.Router) {
			rt.With(indiaLimiter.Middleware).Post("/otp/send", otpHandler.SendOTP)
			rt.Post("/otp/verify", otpHandler.VerifyOTP)
		})
	
		// Child Safety Routes
		r.Route("/child", func(rt chi.Router) {
			rt.Use(JWTMiddleware(jwtManager, tokenRotator))
			rt.Post("/{childID}/request-consent/{parentID}", childProfileHandler.RequestConsent)
			rt.Post("/consent/approve", childProfileHandler.ApproveConsent)
			rt.Get("/{childID}/consent", childProfileHandler.CheckConsent)
		})
	
		// School Integration Routes
		r.Route("/school", func(rt chi.Router) {
			rt.Use(JWTMiddleware(jwtManager, tokenRotator))
			rt.Post("/register", schoolHandler.RegisterSchool)
			rt.Post("/{id}/validate", schoolHandler.ValidateSchool)
			rt.Get("/{id}/status", schoolHandler.GetSchoolStatus)
		})
	
		// RBAC routes
		r.Route("/rbac", func(r chi.Router) {
			// Apply JWT authentication middleware to all RBAC routes
			r.Use(JWTMiddleware(jwtManager, tokenRotator))
			
			// Role management
			r.Post("/role", roleHandler.CreateRole)
			r.Post("/role/assign", roleHandler.AssignRole)
			r.Post("/role/remove", roleHandler.RemoveRole)
			
			// Permission queries
			r.Get("/user/{userID}/community/{communityID}/permissions", roleHandler.GetUserPermissions)
			r.Get("/user/{userID}/community/{communityID}/roles", roleHandler.GetUserRoles)
			r.Get("/community/{communityID}/roles", roleHandler.GetCommunityRoles)
			r.Get("/role/{roleID}/permissions", roleHandler.GetRolePermissions)
			
			// User blocking
			r.Post("/block", roleHandler.BlockUser)
			r.Post("/unblock", roleHandler.UnblockUser)
			r.Get("/user/{userID}/blocks", roleHandler.GetUserBlocks)
			
			// User reporting
			r.Post("/report", roleHandler.ReportUser)
			// Comment out until UpdateReportStatus method is implemented
			// r.Put("/report/status", roleHandler.UpdateReportStatus)
			r.Get("/user/{userID}/reports", roleHandler.GetUserReports)
		})
	
		// Example protected routes with JWT + RBAC
		r.Route("/community/{communityID}", func(r chi.Router) {
			// Apply JWT authentication and community context middleware
			r.Use(JWTMiddleware(jwtManager, tokenRotator))
			r.Use(CommunityContextMiddleware)
			
			// Example: Class attendance route
			r.With(RBACMiddleware("attendance:mark:class", roleService, jwtManager)).
				Post("/class/{classID}/attendance", MarkAttendanceHandler)
			
			// Example: Government alert route
			r.With(RBACMiddleware("alert:broadcast:government", roleService, jwtManager)).
				Post("/alert", BroadcastAlertHandler)
			
			// Example: Billing route
			r.With(RBACMiddleware("billing:view", roleService, jwtManager)).
				Get("/billing", ViewBillingHandler)
			
			// Example: Content moderation route
			r.With(RBACMiddleware("content:moderate", roleService, jwtManager)).
				Post("/post/{postID}/moderate", ModerateContentHandler)
		})
	
		// Debug routes
		if cfg.Env == "development" {
			r.Get("/fp/debug", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if fp, ok := middleware.FromContext(r.Context()); ok {
					fmt.Fprintf(w, `{"ok":true,"device_key":"%s","platform":"%s","app_version":"%s","ip_bucket":"%s","ua_hash":"%s"}`,
						fp.DeviceKey, fp.Platform, fp.AppVersion, fp.IPBucket, fp.UAHash)
					return
				}
				fmt.Fprint(w, `{"ok":false}`)
			})
			
			// JWT debug route
			r.With(JWTMiddleware(jwtManager, tokenRotator)).Get("/jwt/debug", JWTDebugHandler)
			
			// Session debug route
			r.Get("/session/debug", SessionDebugHandler)
			
			// Token rotation debug routes
			r.With(JWTMiddleware(jwtManager, tokenRotator)).Get("/debug/tokens", func(w http.ResponseWriter, r *http.Request) {
				stats := tokenRotator.GetStats(r.Context())
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"rotation_stats": stats,
					"is_rotating":   tokenRotator.IsRotating(),
				})
			})
	
			// Certificate debug routes
			r.Get("/debug/certificates", func(w http.ResponseWriter, r *http.Request) {
				stats := certManager.GetStats()
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"certificate_stats": stats,
					"enabled":          true,
				})
			})
	
			// mTLS debug routes
			r.Get("/debug/mtls", func(w http.ResponseWriter, r *http.Request) {
				stats := mtlsManager.GetStats()
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"mtls_stats": stats,
					"enabled":    true,
				})
			})
	
			// Compliance debug routes
			r.Get("/debug/compliance", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"audit_exporter": map[string]interface{}{
						"enabled": true,
						"stats":   auditExporter.GetStats(),
					},
					"data_retention": map[string]interface{}{
						"enabled": true,
						"stats":   retentionManager.GetStats(),
					},
					"incident_manager": map[string]interface{}{
						"enabled": true,
						"stats":   incidentManager.GetStats(),
					},
				})
			})
	
			// Service certificate debug
			r.Get("/debug/service-cert/{serviceName}", func(w http.ResponseWriter, r *http.Request) {
				serviceName := chi.URLParam(r, "serviceName")
				cert, err := certManager.GetServiceCertificate(r.Context(), serviceName)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
	
				// Get certificate info without private key
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"service":    serviceName,
					"has_cert":   cert != nil,
					"leaf_cert":  cert.Leaf != nil,
				})
			})
		}
	
		// TLS headers
		tlsCfg := middleware.TLSConfig{
			HSTSMaxAge:            cfg.TLS.HSTSMaxAge,
			IncludeSubdomains:     cfg.TLS.IncludeSubdomains,
			Preload:               cfg.TLS.Preload,
			ContentSecurityPolicy: cfg.TLS.CSP,
			ExcludedPaths:         cfg.TLS.ExcludedPaths,
			ForceRedirect:         cfg.TLS.ForceRedirect,
			TrustProxyHeader:      cfg.TLS.TrustProxyHeader,
		}
		handlerChain := middleware.TLSEnhancer(tlsCfg)(r)
	
		// Build HTTP app via loader (keeps your existing builder behavior for non-audit parts)
		app, err := loader.BuildHTTPApp(context.Background(), *cfg, handlerChain)
		if err != nil {
			logger.Fatalf("app build failed: %v", err)
		}
	
		// Wire telemetry for audit:
		// 1) Kafka producer (publish from middlewares
		var kafkaShipper *telemetry.KafkaAuditShipper
		if cfg.Telemetry.Kafka.Enabled {
			kafkaShipper, err = telemetry.NewKafkaAuditShipper(cfg.Telemetry.Kafka)
			if err != nil {
				logger.Fatalf("kafka shipper init error: %v", err)
			}
			kafkaShipper.Start()
			defer kafkaShipper.Stop(context.Background())
		}
	
		// Create enhanced audit middleware that also feeds incident manager
		var enhancedDeviceAudit *EnhancedDeviceAuditMW
		var enhancedOTPAudit *EnhancedOTPAuditMW
	
		if kafkaShipper != nil {
			// Create enhanced middleware that publishes to both Kafka and incident manager
			enhancedDeviceAudit = NewEnhancedDeviceAuditMW(kafkaShipper, incidentManager)
			enhancedOTPAudit = NewEnhancedOTPAuditMW(kafkaShipper, incidentManager)
			
			app.Mux = enhancedDeviceAudit.Handler(app.Mux)
			app.Mux = enhancedOTPAudit.Handler(app.Mux)
		}
	
		// 3) In-process Kafka -> ES sink (consumer group
		var k2es *telemetry.KafkaToES
		if cfg.Telemetry.Kafka.Enabled && (cfg.Telemetry.DeviceAudit.Enabled || cfg.Telemetry.OTPAudit.Enabled || cfg.Telemetry.ES.Enabled) {
			esCfg := cfg.Telemetry.ES
			k2es = telemetry.NewKafkaToES(cfg.Telemetry.Kafka, esCfg)
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			k2es.Start(ctx)
			defer k2es.Stop(context.Background())
		}
	
		// Create TLS config for HTTPS server if certificates are enabled
		var tlsConfig *tls.Config
		if certManager != nil {
			tlsConfig, err = mtlsManager.CreateServerTLSConfig("auth-service")
			if err != nil {
				logger.Warn("Failed to create TLS config, falling back to HTTP", "error", err)
				tlsConfig = nil
			}
		}
	
		// HTTP server with optional TLS
		addr := fmt.Sprintf(":%d", cfg.Port)
		srv := &http.Server{
			Addr:         addr,
			Handler:      app.Mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
			TLSConfig:    tlsConfig,
		}
	
		// Shared signal context
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
	
		logger.Infof("Starting auth service v%s in %s on %s", version, cfg.Env, addr)
		logger.Info("Compliance systems enabled", 
			"audit_exporter", true,
			"data_retention", true,
			"incident_management", true)
			
		if tlsConfig != nil {
			logger.Info("TLS/mTLS enabled - using HTTPS")
		}
	
		go func() {
			var serverErr error
			if tlsConfig != nil {
				// Use custom TLS configuration
				serverErr = srv.ListenAndServeTLS("", "")
			} else {
				serverErr = srv.ListenAndServe()
			}
			
			if serverErr != nil && serverErr != http.ErrServerClosed {
				logger.Fatalf("HTTP server error: %v", serverErr)
			}
		}()
	
		<-ctx.Done()
		logger.Info("Shutting down...")
	
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
	
		// Stop HTTP server first
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Errorf("Shutdown error: %v", err)
		}
	
		// Stop any legacy shippers in app (commented out undefined fields)
		/*
		if app.DeviceShipper != nil {
			app.DeviceShipper.Stop(shutdownCtx)
		}
		if app.OTPShipper != nil {
			app.OTPShipper.Stop(shutdownCtx)
		}
		*/
		if app.Combined != nil {
			app.Combined.Stop(shutdownCtx)
		}
	}
	
	// Enhanced audit middleware that feeds both Kafka and incident manager
	type EnhancedDeviceAuditMW struct {
		shipper         *telemetry.KafkaAuditShipper
		incidentManager *incident.IncidentManager
	}
	
	func NewEnhancedDeviceAuditMW(shipper *telemetry.KafkaAuditShipper, incidentManager *incident.IncidentManager) *EnhancedDeviceAuditMW {
		return &EnhancedDeviceAuditMW{
			shipper:         shipper,
			incidentManager: incidentManager,
		}
	}
	
	func (m *EnhancedDeviceAuditMW) Handler(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &wrapWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(ww, r)
	
			fp, _ := middleware.FromContext(r.Context())
			
			auditEvent := telemetry.DeviceAuditEvent{
				Timestamp:  time.Now().UTC(),
				Method:     r.Method,
				Path:       r.URL.Path,
				Status:     ww.status,
				DurationMs: time.Since(start).Milliseconds(),
			}
			
			if fp != nil {
				auditEvent.DeviceKey = fp.DeviceKey
				auditEvent.Platform = fp.Platform
				auditEvent.AppVersion = fp.AppVersion
				auditEvent.IPBucket = fp.IPBucket
				auditEvent.UAHash = fp.UAHash
			}
	
			// Publish to Kafka
			if m.shipper != nil {
				m.shipper.Publish(auditEvent)
			}
			
			// Send to incident manager for analysis
			if m.incidentManager != nil {
				m.incidentManager.ProcessEvent(auditEvent)
			}
		})
	}
	
	type EnhancedOTPAuditMW struct {
		shipper         *telemetry.KafkaAuditShipper
		incidentManager *incident.IncidentManager
	}
	
	func NewEnhancedOTPAuditMW(shipper *telemetry.KafkaAuditShipper, incidentManager *incident.IncidentManager) *EnhancedOTPAuditMW {
		return &EnhancedOTPAuditMW{
			shipper:         shipper,
			incidentManager: incidentManager,
		}
	}
	
	func (m *EnhancedOTPAuditMW) Handler(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/otp/send" && r.URL.Path != "/otp/verify" {
				next.ServeHTTP(w, r)
				return
			}
			
			start := time.Now()
			ww := &wrapWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(ww, r)
	
			fp, _ := middleware.FromContext(r.Context())
			
			auditEvent := telemetry.OTPAuditEvent{
				Timestamp:  time.Now().UTC(),
				Route:      r.URL.Path,
				Method:     r.Method,
				Status:     ww.status,
				DurationMs: time.Since(start).Milliseconds(),
			}
			
			if fp != nil {
				auditEvent.DeviceKey = fp.DeviceKey
				auditEvent.Platform = fp.Platform
				auditEvent.AppVersion = fp.AppVersion
				auditEvent.IPBucket = fp.IPBucket
				auditEvent.UAHash = fp.UAHash
			}
	
			// Publish to Kafka
			if m.shipper != nil {
				m.shipper.Publish(auditEvent)
			}
			
			// Send to incident manager for analysis
			if m.incidentManager != nil {
				m.incidentManager.ProcessEvent(auditEvent)
			}
		})
	}
	
	type wrapWriter struct {
		http.ResponseWriter
		status int
	}
	
	func (w *wrapWriter) WriteHeader(code int) {
		w.status = code
		w.ResponseWriter.WriteHeader(code)
	}
	// ALL EXISTING HANDLERS

// Enhanced JWT-based authentication middleware with token rotation support
func JWTMiddleware(jwtManager *util.JWTManager, tokenRotator *security.TokenRotator) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Extract JWT from Authorization header
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "Missing authorization header", http.StatusUnauthorized)
                return
            }

            // Extract token from "Bearer <token>"
            tokenString := ""
            if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
                tokenString = authHeader[7:]
            } else {
                http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
                return
            }

            // Validate JWT token
            claims, err := jwtManager.ValidateToken(tokenString)
            if err != nil {
                http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
                return
            }

            // Check if token is revoked
            if tokenRotator.IsTokenRevoked(r.Context(), claims.TokenID) {
                // Check for rotation notification
                notification, rotErr := tokenRotator.GetRotationNotification(r.Context(), claims.UserContext.UserID, claims.TokenID)
                if rotErr == nil {
                    // Token was rotated, return new token
                    w.Header().Set("Content-Type", "application/json")
                    w.Header().Set("X-Token-Rotated", "true")
                    w.WriteHeader(http.StatusUpgradeRequired) // 426 status
                    json.NewEncoder(w).Encode(map[string]interface{}{
                        "error":     "token_rotated",
                        "message":   "Token has been rotated, use new token",
                        "new_token": notification["new_token"],
                    })
                    return
                }
                http.Error(w, "Token revoked", http.StatusUnauthorized)
                return
            }

            // Update token access time for rotation tracking
            tokenRotator.UpdateTokenAccess(r.Context(), claims.TokenID)

            // Add claims to context
            ctx := context.WithValue(r.Context(), "jwt_claims", claims)
            ctx = context.WithValue(ctx, "user_id", claims.UserContext.UserID)
            ctx = context.WithValue(ctx, "user_context", claims.UserContext)
            
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// CommunityContextMiddleware extracts community ID from URL and adds to context
func CommunityContextMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        communityIDStr := chi.URLParam(r, "communityID")
        if communityIDStr != "" {
            if communityID, err := uuid.Parse(communityIDStr); err == nil {
                ctx := context.WithValue(r.Context(), "community_id", communityID)
                r = r.WithContext(ctx)
            }
        }
        next.ServeHTTP(w, r)
    })
}

// RequirePermission creates a middleware that requires a specific permission
func RequirePermission(requiredPermission string, roleService service.RoleService) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
            if !ok {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // Create minimal auth context for global permissions
            authzCtx := &models.AuthzContext{}

            if !claims.HasPermission(requiredPermission, authzCtx) {
                http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

// RBACMiddleware creates a middleware that checks for specific permissions using JWT claims
func RBACMiddleware(requiredPermission string, roleService service.RoleService, jwtManager *util.JWTManager) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get JWT claims from context
            claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
            if !ok {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // Get community ID from context
            communityID, ok := r.Context().Value("community_id").(uuid.UUID)
            if !ok {
                http.Error(w, "Community ID required", http.StatusBadRequest)
                return
            }

            // Create authorization context
            authzCtx := &models.AuthzContext{
                CommunityID: communityID,
            }

            // First check JWT claims for quick permission check
            if claims.HasPermission(requiredPermission, authzCtx) {
                next.ServeHTTP(w, r)
                return
            }

            // If not found in JWT (could be overflow), check via service
            hasPermission, err := roleService.HasPermission(r.Context(), claims.UserContext.UserID, requiredPermission, authzCtx)
            if err != nil {
                logger.Error("Permission check failed", "error", err, "user_id", claims.UserContext.UserID, "permission", requiredPermission)
                http.Error(w, "Internal server error", http.StatusInternalServerError)
                return
            }

            if !hasPermission {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

// Enhanced Auth handlers with session and token rotation integration
func LoginHandler(jwtManager *util.JWTManager, userRepo repository.UserRepository, roleRepo repository.RoleRepository, sessionEncryptor *security.SessionEncryptor, tokenRotator *security.TokenRotator) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Parse login request
        var req struct {
            PhoneNumber string `json:"phone_number"`
            Password    string `json:"password"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        // Validate credentials (implement your validation logic)
        user, err := userRepo.GetByPhone(r.Context(), req.PhoneNumber)
        if err != nil {
            http.Error(w, "Invalid credentials", http.StatusUnauthorized)
            return
        }

        // UPDATE LAST LOGIN TIME - ADD THIS CODE
        now := time.Now()
        if err := userRepo.UpdateUserFields(r.Context(), user.ID, map[string]interface{}{
            "last_login_at": &now,
        }); err != nil {
            logger.Error("Failed to update last login time", "error", err)
            // Don't fail the login for this error, just log it
        }

        // Get user roles
        userRoles, err := roleRepo.GetAllUserRoles(r.Context(), user.ID)
        if err != nil {
            http.Error(w, "Failed to get user roles", http.StatusInternalServerError)
            return
        }

        // Extract device fingerprint from middleware
        deviceFingerprint := "unknown"
        if fp, ok := middleware.FromContext(r.Context()); ok {
            deviceFingerprint = fp.DeviceKey
        }
        
        sessionID := fmt.Sprintf("session-%d", time.Now().Unix())

        // Create tokens
        accessToken, err := jwtManager.CreateAccessToken(r.Context(), user, userRoles, deviceFingerprint, sessionID)
        if err != nil {
            http.Error(w, "Failed to create access token", http.StatusInternalServerError)
            return
        }

        refreshToken, err := jwtManager.CreateRefreshToken(r.Context(), user.ID, deviceFingerprint)
        if err != nil {
            http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
            return
        }

        // Parse access token to get claims for registration
        accessClaims, err := jwtManager.ValidateToken(accessToken)
        if err != nil {
            logger.Error("Failed to parse access token for registration", "error", err)
        } else {
            // Register token for rotation tracking
            tokenRotator.RegisterToken(r.Context(), accessClaims.TokenID, user.ID, 
                util.AccessToken, deviceFingerprint, sessionID,
                accessClaims.ExpiresAt.Time, len(accessClaims.UserContext.CommunityRoles))
        }

        // Create encrypted session
        sessionData := models.JSONMap{
            "login_time": time.Now(),
            "ip_address": r.RemoteAddr,
            "user_agent": r.UserAgent(),
        }
        
        encryptedSession, err := sessionEncryptor.CreateSession(r.Context(), user.ID, sessionData)
        if err != nil {
            logger.Error("Failed to create encrypted session", "error", err)
            // Continue without session - not critical
        } else {
            // Set session cookie
            sessionCookie := sessionEncryptor.CreateSessionCookie(encryptedSession)
            http.SetCookie(w, sessionCookie)
        }

        // Response
        response := map[string]interface{}{
            "access_token":  accessToken,
            "refresh_token": refreshToken,
            "token_type":    "Bearer",
            "expires_in":    900, // 15 minutes
            "user": map[string]interface{}{
                "id":           user.ID,
                "phone":        user.PhoneNumber,
                "verified":     user.PhoneVerified,
                "setup_done":   user.SetupCompleted,
            },
        }

        if encryptedSession != nil {
            response["session_id"] = encryptedSession.SessionID
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    }
}

func RefreshTokenHandler(jwtManager *util.JWTManager, tokenRotator *security.TokenRotator) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req struct {
            RefreshToken string `json:"refresh_token"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        deviceFingerprint := "unknown"
        if fp, ok := middleware.FromContext(r.Context()); ok {
            deviceFingerprint = fp.DeviceKey
        }

        // Refresh access token
        newAccessToken, err := jwtManager.RefreshAccessToken(r.Context(), req.RefreshToken, deviceFingerprint)
        if err != nil {
            http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
            return
        }

        // Parse new token to register for rotation
        newClaims, err := jwtManager.ValidateToken(newAccessToken)
        if err != nil {
            logger.Error("Failed to parse new access token", "error", err)
        } else {
            // Register new token for rotation tracking
            tokenRotator.RegisterToken(r.Context(), newClaims.TokenID, newClaims.UserContext.UserID,
                util.AccessToken, deviceFingerprint, newClaims.SessionID,
                newClaims.ExpiresAt.Time, len(newClaims.UserContext.CommunityRoles))
        }

        response := map[string]interface{}{
            "access_token": newAccessToken,
            "token_type":   "Bearer",
            "expires_in":   900, // 15 minutes
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    }
}

func LogoutHandler(jwtManager *util.JWTManager, sessionEncryptor *security.SessionEncryptor, tokenRotator *security.TokenRotator) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Extract token and revoke it
        authHeader := r.Header.Get("Authorization")
        if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
            tokenString := authHeader[7:]
            claims, err := jwtManager.ValidateToken(tokenString)
            if err == nil {
                // Revoke token via rotator
                tokenRotator.RevokeUserToken(r.Context(), claims.UserContext.UserID, claims.TokenID)
            }
        }

        // Get user ID for session invalidation
        var userID uuid.UUID
        if claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims); ok {
            userID = claims.UserContext.UserID
            // Invalidate all user sessions
            sessionEncryptor.InvalidateAllUserSessions(r.Context(), userID)
        } else if sessionData, ok := security.GetSessionFromContext(r.Context()); ok {
            userID = sessionData.UserID
            // Invalidate all user sessions
            sessionEncryptor.InvalidateAllUserSessions(r.Context(), userID)
        }

        // Clear session cookie
        http.SetCookie(w, &http.Cookie{
            Name:     "auth_session",
            Value:    "",
            Path:     "/",
            Expires:  time.Unix(0, 0),
            MaxAge:   -1,
            HttpOnly: true,
        })

        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"message": "Logged out successfully"}`))
    }
}

// Session-specific handlers
func SessionRefreshHandler(sessionEncryptor *security.SessionEncryptor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        sessionData, ok := security.GetSessionFromContext(r.Context())
        if !ok {
            http.Error(w, "No active session", http.StatusUnauthorized)
            return
        }

        refreshedSession, err := sessionEncryptor.RefreshSession(r.Context(), sessionData.SessionID)
        if err != nil {
            http.Error(w, "Failed to refresh session", http.StatusInternalServerError)
            return
        }

        // Update session cookie
        sessionCookie := sessionEncryptor.CreateSessionCookie(refreshedSession)
        http.SetCookie(w, sessionCookie)

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "message":    "Session refreshed",
            "expires_at": refreshedSession.ExpiresAt,
        })
    }
}

func SessionInfoHandler(sessionEncryptor *security.SessionEncryptor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        sessionData, ok := security.GetSessionFromContext(r.Context())
        if !ok {
            http.Error(w, "No active session", http.StatusUnauthorized)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "session_id":     sessionData.SessionID,
            "user_id":        sessionData.UserID,
            "created_at":     sessionData.CreatedAt,
            "last_activity":  sessionData.LastActivity,
            "expires_at":     sessionData.ExpiresAt,
            "platform":       sessionData.Platform,
            "security_level": sessionData.SecurityLevel,
            "trust_score":    sessionData.TrustScore,
        })
    }
}

func InvalidateSessionHandler(sessionEncryptor *security.SessionEncryptor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        sessionData, ok := security.GetSessionFromContext(r.Context())
        if !ok {
            http.Error(w, "No active session", http.StatusUnauthorized)
            return
        }

        if err := sessionEncryptor.InvalidateSession(r.Context(), sessionData.SessionID, sessionData.UserID); err != nil {
            http.Error(w, "Failed to invalidate session", http.StatusInternalServerError)
            return
        }

        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"message": "Session invalidated"}`))
    }
}
// NEW COMPLIANCE HANDLERS

// Audit Export Handlers
func ComplianceAuditStatsHandler(auditExporter *audit.AuditExporter) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        stats := auditExporter.GetStats()
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(stats)
    }
}

func CreateAuditExportHandler(auditExporter *audit.AuditExporter) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
        if !ok {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        var req audit.ExportRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        req.RequestedBy = claims.UserContext.UserID
        
        export, err := auditExporter.CreateExport(r.Context(), &req)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to create export: %v", err), http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(export)
    }
}

func GetAuditExportHandler(auditExporter *audit.AuditExporter) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        exportID, err := uuid.Parse(chi.URLParam(r, "exportId"))
        if err != nil {
            http.Error(w, "Invalid export ID", http.StatusBadRequest)
            return
        }

        export, err := auditExporter.GetExportStatus(r.Context(), exportID)
        if err != nil {
            http.Error(w, "Export not found", http.StatusNotFound)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(export)
    }
}

func ListAuditExportsHandler(auditExporter *audit.AuditExporter) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
        if !ok {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        limit := 50 // Default limit
        exports, err := auditExporter.ListExports(r.Context(), claims.UserContext.UserID, limit)
        if err != nil {
            http.Error(w, "Failed to list exports", http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "exports": exports,
            "count":   len(exports),
        })
    }
}

func CancelAuditExportHandler(auditExporter *audit.AuditExporter) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
        if !ok {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        exportID, err := uuid.Parse(chi.URLParam(r, "exportId"))
        if err != nil {
            http.Error(w, "Invalid export ID", http.StatusBadRequest)
            return
        }

        err = auditExporter.CancelExport(r.Context(), exportID, claims.UserContext.UserID)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to cancel export: %v", err), http.StatusInternalServerError)
            return
        }

        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"message": "Export cancelled successfully"}`))
    }
}

// Data Retention Handlers
func RetentionStatsHandler(retentionManager *compliance.DataRetentionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        stats := retentionManager.GetStats()
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(stats)
    }
}

func ListRetentionPoliciesHandler(retentionManager *compliance.DataRetentionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        policies, err := retentionManager.ListPolicies(r.Context())
        if err != nil {
            http.Error(w, "Failed to list policies", http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "policies": policies,
            "count":    len(policies),
        })
    }
}

func CreateRetentionPolicyHandler(retentionManager *compliance.DataRetentionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
        if !ok {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        var policy compliance.RetentionPolicy
        if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        createdPolicy, err := retentionManager.CreatePolicy(r.Context(), &policy, claims.UserContext.UserID)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to create policy: %v", err), http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(createdPolicy)
    }
}

func GetRetentionPolicyHandler(retentionManager *compliance.DataRetentionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        policyID, err := uuid.Parse(chi.URLParam(r, "policyId"))
        if err != nil {
            http.Error(w, "Invalid policy ID", http.StatusBadRequest)
            return
        }

        policy, err := retentionManager.GetPolicy(r.Context(), policyID)
        if err != nil {
            http.Error(w, "Policy not found", http.StatusNotFound)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(policy)
    }
}

func UpdateRetentionPolicyHandler(retentionManager *compliance.DataRetentionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        policyID, err := uuid.Parse(chi.URLParam(r, "policyId"))
        if err != nil {
            http.Error(w, "Invalid policy ID", http.StatusBadRequest)
            return
        }

        var policy compliance.RetentionPolicy
        if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        policy.ID = policyID
        
        err = retentionManager.UpdatePolicy(r.Context(), &policy)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to update policy: %v", err), http.StatusInternalServerError)
            return
        }

        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"message": "Policy updated successfully"}`))
    }
}

func DeleteRetentionPolicyHandler(retentionManager *compliance.DataRetentionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        policyID, err := uuid.Parse(chi.URLParam(r, "policyId"))
        if err != nil {
            http.Error(w, "Invalid policy ID", http.StatusBadRequest)
            return
        }

        err = retentionManager.DeletePolicy(r.Context(), policyID)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to delete policy: %v", err), http.StatusInternalServerError)
            return
        }

        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"message": "Policy deleted successfully"}`))
    }
}

func ExecuteRetentionPolicyHandler(retentionManager *compliance.DataRetentionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        policyID, err := uuid.Parse(chi.URLParam(r, "policyId"))
        if err != nil {
            http.Error(w, "Invalid policy ID", http.StatusBadRequest)
            return
        }

        var req struct {
            DryRun bool `json:"dry_run"`
        }
        json.NewDecoder(r.Body).Decode(&req)

        execution, err := retentionManager.ExecutePolicy(r.Context(), policyID, req.DryRun)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to execute policy: %v", err), http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(execution)
    }
}

func GetRetentionExecutionHandler(retentionManager *compliance.DataRetentionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        executionID, err := uuid.Parse(chi.URLParam(r, "executionId"))
        if err != nil {
            http.Error(w, "Invalid execution ID", http.StatusBadRequest)
            return
        }

        execution, err := retentionManager.GetExecution(r.Context(), executionID)
        if err != nil {
            http.Error(w, "Execution not found", http.StatusNotFound)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(execution)
    }
}

func ListRetentionExecutionsHandler(retentionManager *compliance.DataRetentionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        limit := 50
        executions, err := retentionManager.ListExecutions(r.Context(), limit)
        if err != nil {
            http.Error(w, "Failed to list executions", http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "executions": executions,
            "count":      len(executions),
        })
    }
}

// Incident Management Handlers
func IncidentStatsHandler(incidentManager *incident.IncidentManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        stats := incidentManager.GetStats()
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(stats)
    }
}

func ListIncidentsHandler(incidentManager *incident.IncidentManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        filters := incident.IncidentFilters{
            Limit: 50,
        }
        
        // Parse query parameters
        if status := r.URL.Query().Get("status"); status != "" {
            filters.Status = incident.IncidentStatus(status)
        }
        if severity := r.URL.Query().Get("severity"); severity != "" {
            filters.Severity = incident.IncidentSeverity(severity)
        }
        
        incidents, err := incidentManager.ListIncidents(r.Context(), filters)
        if err != nil {
            http.Error(w, "Failed to list incidents", http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "incidents": incidents,
            "count":     len(incidents),
        })
    }
}

func CreateIncidentHandler(incidentManager *incident.IncidentManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var inc incident.Incident
        if err := json.NewDecoder(r.Body).Decode(&inc); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        createdIncident, err := incidentManager.CreateIncident(r.Context(), &inc)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to create incident: %v", err), http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(createdIncident)
    }
}

func GetIncidentHandler(incidentManager *incident.IncidentManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        incidentID, err := uuid.Parse(chi.URLParam(r, "incidentId"))
        if err != nil {
            http.Error(w, "Invalid incident ID", http.StatusBadRequest)
            return
        }

        inc, err := incidentManager.GetIncident(r.Context(), incidentID)
        if err != nil {
            http.Error(w, "Incident not found", http.StatusNotFound)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(inc)
    }
}

func UpdateIncidentHandler(incidentManager *incident.IncidentManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        incidentID, err := uuid.Parse(chi.URLParam(r, "incidentId"))
        if err != nil {
            http.Error(w, "Invalid incident ID", http.StatusBadRequest)
            return
        }

        var inc incident.Incident
        if err := json.NewDecoder(r.Body).Decode(&inc); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        inc.ID = incidentID
        
        err = incidentManager.UpdateIncident(r.Context(), &inc)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to update incident: %v", err), http.StatusInternalServerError)
            return
        }

        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"message": "Incident updated successfully"}`))
    }
}

func CloseIncidentHandler(incidentManager *incident.IncidentManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        incidentID, err := uuid.Parse(chi.URLParam(r, "incidentId"))
        if err != nil {
            http.Error(w, "Invalid incident ID", http.StatusBadRequest)
            return
        }

        var req struct {
            Resolution string `json:"resolution"`
            RootCause  string `json:"root_cause"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        err = incidentManager.CloseIncident(r.Context(), incidentID, req.Resolution, req.RootCause)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to close incident: %v", err), http.StatusInternalServerError)
            return
        }

        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"message": "Incident closed successfully"}`))
    }
}

func AddIncidentActionHandler(incidentManager *incident.IncidentManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
        if !ok {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        incidentID, err := uuid.Parse(chi.URLParam(r, "incidentId"))
        if err != nil {
            http.Error(w, "Invalid incident ID", http.StatusBadRequest)
            return
        }

        var action incident.ResponseAction
        if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        action.ExecutedBy = claims.UserContext.UserID.String()
        
        err = incidentManager.AddResponseAction(r.Context(), incidentID, &action)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to add action: %v", err), http.StatusInternalServerError)
            return
        }

        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"message": "Action added successfully"}`))
    }
}

func GetIncidentActionsHandler(incidentManager *incident.IncidentManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        incidentID, err := uuid.Parse(chi.URLParam(r, "incidentId"))
        if err != nil {
            http.Error(w, "Invalid incident ID", http.StatusBadRequest)
            return
        }

        inc, err := incidentManager.GetIncident(r.Context(), incidentID)
        if err != nil {
            http.Error(w, "Incident not found", http.StatusNotFound)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "incident_id": incidentID,
            "actions":     inc.ResponseActions,
            "count":       len(inc.ResponseActions),
        })
    }
}
// GDPR/CCPA User Data Rights Handlers
func UserDataExportHandler(auditExporter *audit.AuditExporter, retentionManager *compliance.DataRetentionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
        if !ok {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Create user data export request
        exportReq := &audit.ExportRequest{
            RequestedBy: claims.UserContext.UserID,
            EventTypes:  []string{"device_audit", "otp_audit"},
            StartTime:   time.Now().Add(-365 * 24 * time.Hour), // Last year
            EndTime:     time.Now(),
            Format:      audit.FormatJSON,
            Standard:    audit.StandardGDPR,
            Filters: audit.ExportFilters{
                UserIDs: []uuid.UUID{claims.UserContext.UserID},
            },
        }

        export, err := auditExporter.CreateExport(r.Context(), exportReq)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to create export: %v", err), http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "message":   "Data export requested",
            "export_id": export.ID,
            "status":    export.Status,
        })
    }
}

func DownloadUserDataExportHandler(auditExporter *audit.AuditExporter) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
        if !ok {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        exportID, err := uuid.Parse(chi.URLParam(r, "exportId"))
        if err != nil {
            http.Error(w, "Invalid export ID", http.StatusBadRequest)
            return
        }

        export, err := auditExporter.GetExportStatus(r.Context(), exportID)
        if err != nil {
            http.Error(w, "Export not found", http.StatusNotFound)
            return
        }

        if export.RequestedBy != claims.UserContext.UserID {
            http.Error(w, "Unauthorized to download this export", http.StatusForbidden)
            return
        }

        if export.Status != audit.StatusCompleted {
            http.Error(w, fmt.Sprintf("Export not ready: %s", export.Status), http.StatusBadRequest)
            return
        }

        // In a real implementation, you would serve the actual file
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`{"message": "Download would start here", "file_path": "` + export.FilePath + `"}`))
    }
}

func UserDataDeletionRequestHandler(retentionManager *compliance.DataRetentionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
        if !ok {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        var req struct {
            Reason string `json:"reason"`
        }
        json.NewDecoder(r.Body).Decode(&req)
        
        if req.Reason == "" {
            req.Reason = "User requested data deletion"
        }

        execution, err := retentionManager.RequestUserDataDeletion(r.Context(), claims.UserContext.UserID, req.Reason)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to request deletion: %v", err), http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "message":      "Data deletion requested",
            "execution_id": execution.ID,
            "status":       execution.Status,
        })
    }
}

func UserDataDeletionStatusHandler(retentionManager *compliance.DataRetentionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
        if !ok {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // This would check for user deletion executions
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "user_id":       claims.UserContext.UserID,
            "deletion_status": "not_requested", // Would be dynamic
            "message":       "No deletion requests found",
        })
    }
}

func UserRetentionInfoHandler(retentionManager *compliance.DataRetentionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
        if !ok {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        info, err := retentionManager.GetUserDataRetentionInfo(r.Context(), claims.UserContext.UserID)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to get retention info: %v", err), http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(info)
    }
}

// Internal Compliance Handlers
func InternalIncidentReportHandler(incidentManager *incident.IncidentManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var inc incident.Incident
        if err := json.NewDecoder(r.Body).Decode(&inc); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        createdIncident, err := incidentManager.CreateIncident(r.Context(), &inc)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to create incident: %v", err), http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(createdIncident)
    }
}

func InternalUserDeletedHandler(retentionManager *compliance.DataRetentionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req struct {
            UserID uuid.UUID `json:"user_id"`
            Reason string    `json:"reason"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        execution, err := retentionManager.RequestUserDataDeletion(r.Context(), req.UserID, req.Reason)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to process deletion: %v", err), http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(execution)
    }
}

// Existing handlers with session awareness
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    response := map[string]interface{}{
        "user":        claims.UserContext,
        "token_info":  claims.GetTokenInfo(),
        "communities": claims.GetUserCommunities(),
    }

    // Add session info if available
    if sessionData, sessionOk := security.GetSessionFromContext(r.Context()); sessionOk {
        response["session"] = map[string]interface{}{
            "session_id":     sessionData.SessionID,
            "created_at":     sessionData.CreatedAt,
            "last_activity":  sessionData.LastActivity,
            "security_level": sessionData.SecurityLevel,
            "trust_score":    sessionData.TrustScore,
        }
    }

    // Add service auth info if available (for internal calls)
    if serviceAuth, serviceOk := security.GetServiceAuthFromContext(r.Context()); serviceOk {
        response["service_auth"] = map[string]interface{}{
            "service_name":   serviceAuth.ServiceName,
            "common_name":    serviceAuth.CommonName,
            "authenticated_at": serviceAuth.AuthenticatedAt,
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func JWTDebugHandler(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        http.Error(w, "No claims found", http.StatusInternalServerError)
        return
    }

    response := map[string]interface{}{
        "valid":            true,
        "token_id":         claims.TokenID,
        "user_id":          claims.UserContext.UserID,
        "phone":            claims.UserContext.PhoneNumber,
        "communities":      len(claims.UserContext.CommunityRoles),
        "global_perms":     len(claims.UserContext.GlobalPermissions),
        "expires_at":       claims.ExpiresAt,
        "issued_at":        claims.IssuedAt,
        "device_fp":        claims.DeviceFingerprint,
        "session_id":       claims.SessionID,
    }

    // Add session debug info
    if sessionData, sessionOk := security.GetSessionFromContext(r.Context()); sessionOk {
        response["encrypted_session"] = map[string]interface{}{
            "session_id":     sessionData.SessionID,
            "platform":       sessionData.Platform,
            "security_level": sessionData.SecurityLevel,
            "trust_score":    sessionData.TrustScore,
        }
    }

    // Add service auth debug info
    if serviceAuth, serviceOk := security.GetServiceAuthFromContext(r.Context()); serviceOk {
        response["service_auth"] = map[string]interface{}{
            "service_name": serviceAuth.ServiceName,
            "common_name":  serviceAuth.CommonName,
            "fingerprint":  serviceAuth.Fingerprint,
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func SessionDebugHandler(w http.ResponseWriter, r *http.Request) {
    if sessionData, ok := security.GetSessionFromContext(r.Context()); ok {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "has_session":    true,
            "session_id":     sessionData.SessionID,
            "user_id":        sessionData.UserID,
            "device_key":     sessionData.DeviceKey,
            "platform":       sessionData.Platform,
            "created_at":     sessionData.CreatedAt,
            "last_activity":  sessionData.LastActivity,
            "expires_at":     sessionData.ExpiresAt,
            "security_level": sessionData.SecurityLevel,
            "trust_score":    sessionData.TrustScore,
        })
    } else {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "has_session": false,
        })
    }
}

// Existing placeholder handlers
func MarkAttendanceHandler(w http.ResponseWriter, r *http.Request) {
    claims := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "message": "Attendance marked",
        "user":    claims.UserContext.UserID,
        "class":   chi.URLParam(r, "classID"),
    })
}

func BroadcastAlertHandler(w http.ResponseWriter, r *http.Request) {
    claims := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "message":   "Alert broadcasted",
        "user":      claims.UserContext.UserID,
        "community": chi.URLParam(r, "communityID"),
    })
}

func ViewBillingHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(`{"message": "Billing data", "amount": 1500.00}`))
}

func ModerateContentHandler(w http.ResponseWriter, r *http.Request) {
    claims := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "message":   "Content moderated",
        "moderator": claims.UserContext.UserID,
        "post":      chi.URLParam(r, "postID"),
    })
}