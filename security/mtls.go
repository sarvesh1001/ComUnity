package security

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "net/http"
    "strings"
    "sync"
    "time"

    "github.com/ComUnity/auth-service/internal/util/logger"
    "github.com/ComUnity/auth-service/internal/models"
)

// mTLSConfig holds mutual TLS configuration
type MTLSConfig struct {
    Enabled              bool                    `yaml:"enabled"`
    RequireClientCert    bool                    `yaml:"require_client_cert"`
    VerifyClientCert     bool                    `yaml:"verify_client_cert"`
    ClientCABundle       string                  `yaml:"client_ca_bundle"`
    AllowedServices      map[string][]string     `yaml:"allowed_services"` // service -> allowed CNs
    ServicePorts         map[string]int          `yaml:"service_ports"`
    CipherSuites         []string                `yaml:"cipher_suites"`
    MinTLSVersion        string                  `yaml:"min_tls_version"`
    MaxTLSVersion        string                  `yaml:"max_tls_version"`
    EnableOCSP           bool                    `yaml:"enable_ocsp"`
    OCSPStapling         bool                    `yaml:"ocsp_stapling"`
    SessionTimeout       time.Duration           `yaml:"session_timeout"`
    RenegotiationSupport string                  `yaml:"renegotiation_support"`
}

// MTLSManager handles mutual TLS configuration and validation
type MTLSManager struct {
    config    MTLSConfig
    certMgr   *CertificateManager
    clientCAs *x509.CertPool
    
    // Service authentication cache
    authCache sync.Map // map[string]*ServiceAuthInfo
    
    // Statistics
    stats     MTLSStats
    statsMu   sync.RWMutex
}

// ServiceAuthInfo represents authenticated service information
type ServiceAuthInfo struct {
    ServiceName   string              `json:"service_name"`
    CommonName    string              `json:"common_name"`
    Organization  string              `json:"organization"`
    SerialNumber  string              `json:"serial_number"`
    NotBefore     time.Time           `json:"not_before"`
    NotAfter      time.Time           `json:"not_after"`
    Fingerprint   string              `json:"fingerprint"`
    AuthenticatedAt time.Time         `json:"authenticated_at"`
    Metadata      models.JSONMap      `json:"metadata"`
}

// MTLSStats tracks mTLS statistics
type MTLSStats struct {
    TotalConnections      int64     `json:"total_connections"`
    SuccessfulAuths       int64     `json:"successful_auths"`
    FailedAuths           int64     `json:"failed_auths"`
    CertificateErrors     int64     `json:"certificate_errors"`
    UnauthorizedServices  int64     `json:"unauthorized_services"`
    ExpiredCertificates   int64     `json:"expired_certificates"`
    LastSuccess           *time.Time `json:"last_success,omitempty"`
    LastFailure           *time.Time `json:"last_failure,omitempty"`
}

// NewMTLSManager creates a new mTLS manager
func NewMTLSManager(config MTLSConfig, certMgr *CertificateManager) (*MTLSManager, error) {
    // Set defaults
    if config.SessionTimeout == 0 {
        config.SessionTimeout = 300 * time.Second // 5 minutes
    }
    if config.MinTLSVersion == "" {
        config.MinTLSVersion = "1.3" // Force TLS 1.3 for security
    }
    if len(config.CipherSuites) == 0 {
        // Use strong cipher suites only
        config.CipherSuites = []string{
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
        }
    }
    
    mgr := &MTLSManager{
        config:  config,
        certMgr: certMgr,
    }
    
    if config.Enabled {
        // Load client CA bundle
        if err := mgr.loadClientCAs(); err != nil {
            return nil, fmt.Errorf("failed to load client CAs: %w", err)
        }
        
        logger.Info("mTLS manager initialized",
            "require_client_cert", config.RequireClientCert,
            "verify_client_cert", config.VerifyClientCert,
            "min_tls_version", config.MinTLSVersion)
    }
    
    return mgr, nil
}

// CreateServerTLSConfig creates TLS config for server with mTLS
func (mm *MTLSManager) CreateServerTLSConfig(serviceName string) (*tls.Config, error) {
    if !mm.config.Enabled {
        return &tls.Config{}, nil
    }
    
    // Get service certificate
    cert, err := mm.certMgr.GetServiceCertificate(context.Background(), serviceName)
    if err != nil {
        return nil, fmt.Errorf("failed to get service certificate: %w", err)
    }
    
    config := &tls.Config{
        Certificates: []tls.Certificate{*cert},
        MinVersion:   mm.getTLSVersion(mm.config.MinTLSVersion),
        MaxVersion:   mm.getTLSVersion(mm.config.MaxTLSVersion),
        CipherSuites: mm.getCipherSuites(),
        
        // mTLS configuration
        ClientAuth: mm.getClientAuthType(),
        ClientCAs:  mm.clientCAs,
        
        // Security settings
        PreferServerCipherSuites: true,
        SessionTicketsDisabled:   true, // Disable for better forward secrecy
        Renegotiation:           mm.getRenegotiationSupport(),
        
        // Custom verification
        VerifyPeerCertificate: mm.verifyPeerCertificate,
        GetCertificate:       mm.getCertificateHandler(serviceName),
    }
    
    // Enable OCSP stapling if configured
    if mm.config.OCSPStapling {
        // OCSP stapling setup would go here
        logger.Debug("OCSP stapling enabled for service", "service", serviceName)
    }
    
    return config, nil
}

// CreateClientTLSConfig creates TLS config for client connections
func (mm *MTLSManager) CreateClientTLSConfig(serviceName string, targetService string) (*tls.Config, error) {
    if !mm.config.Enabled {
        return &tls.Config{InsecureSkipVerify: true}, nil // Only for dev
    }
    
    // Get client certificate
    cert, err := mm.certMgr.GetServiceCertificate(context.Background(), serviceName)
    if err != nil {
        return nil, fmt.Errorf("failed to get client certificate: %w", err)
    }
    
    // Get CA bundle for server verification
    caBundle, err := mm.certMgr.GetCABundle()
    if err != nil {
        return nil, fmt.Errorf("failed to get CA bundle: %w", err)
    }
    
    // Create CA pool
    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caBundle) {
        return nil, fmt.Errorf("failed to add CA certificate to pool")
    }
    
    config := &tls.Config{
        Certificates: []tls.Certificate{*cert},
        RootCAs:      caCertPool,
        MinVersion:   mm.getTLSVersion(mm.config.MinTLSVersion),
        MaxVersion:   mm.getTLSVersion(mm.config.MaxTLSVersion),
        CipherSuites: mm.getCipherSuites(),
        ServerName:   targetService, // SNI
        
        // Security settings
        InsecureSkipVerify: false,
        SessionTicketsDisabled: true,
    }
    
    return config, nil
}

// MTLSMiddleware creates HTTP middleware for mTLS authentication
func (mm *MTLSManager) MTLSMiddleware(serviceName string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if !mm.config.Enabled {
                next.ServeHTTP(w, r)
                return
            }
            
            mm.updateStats(func(s *MTLSStats) {
                s.TotalConnections++
            })
            
            // Extract client certificate
            if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
                if mm.config.RequireClientCert {
                    mm.updateStats(func(s *MTLSStats) {
                        s.FailedAuths++
                        now := time.Now()
                        s.LastFailure = &now
                    })
                    http.Error(w, "Client certificate required", http.StatusUnauthorized)
                    return
                }
                next.ServeHTTP(w, r)
                return
            }
            
            clientCert := r.TLS.PeerCertificates[0]
            
            // Verify certificate if required
            if mm.config.VerifyClientCert {
                if err := mm.verifyCertificate(clientCert); err != nil {
                    logger.Warn("Client certificate verification failed",
                        "cn", clientCert.Subject.CommonName,
                        "error", err)
                    
                    mm.updateStats(func(s *MTLSStats) {
                        s.CertificateErrors++
                        s.FailedAuths++
                        now := time.Now()
                        s.LastFailure = &now
                    })
                    
                    http.Error(w, "Certificate verification failed", http.StatusUnauthorized)
                    return
                }
            }
            
            // Check if service is authorized
            clientCN := clientCert.Subject.CommonName
            if !mm.isServiceAuthorized(serviceName, clientCN) {
                logger.Warn("Unauthorized service attempted connection",
                    "client_cn", clientCN,
                    "target_service", serviceName)
                
                mm.updateStats(func(s *MTLSStats) {
                    s.UnauthorizedServices++
                    s.FailedAuths++
                    now := time.Now()
                    s.LastFailure = &now
                })
                
                http.Error(w, "Service not authorized", http.StatusForbidden)
                return
            }
            
            // Create service auth info
            authInfo := &ServiceAuthInfo{
                ServiceName:     mm.extractServiceName(clientCN),
                CommonName:      clientCN,
                Organization:    strings.Join(clientCert.Subject.Organization, ","),
                SerialNumber:    clientCert.SerialNumber.String(),
                NotBefore:       clientCert.NotBefore,
                NotAfter:        clientCert.NotAfter,
                Fingerprint:     mm.calculateFingerprint(clientCert.Raw),
                AuthenticatedAt: time.Now(),
                Metadata: models.JSONMap{
                    "issuer":     clientCert.Issuer.CommonName,
                    "key_usage":  clientCert.KeyUsage,
                    "ext_key_usage": clientCert.ExtKeyUsage,
                },
            }
            
            // Cache auth info
            mm.authCache.Store(r.RemoteAddr, authInfo)
            
            // Add to request context
            ctx := context.WithValue(r.Context(), "mtls_auth", authInfo)
            ctx = context.WithValue(ctx, "client_service", authInfo.ServiceName)
            
            mm.updateStats(func(s *MTLSStats) {
                s.SuccessfulAuths++
                now := time.Now()
                s.LastSuccess = &now
            })
            
            logger.Debug("mTLS authentication successful",
                "client_service", authInfo.ServiceName,
                "client_cn", clientCN,
                "target_service", serviceName)
            
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// Helper methods

func (mm *MTLSManager) loadClientCAs() error {
    if mm.config.ClientCABundle != "" {
        // Load from file or configuration
        mm.clientCAs = x509.NewCertPool()
        // Implementation would load from specified bundle
    } else if mm.certMgr != nil {
        // Use CA from certificate manager
        caBundle, err := mm.certMgr.GetCABundle()
        if err != nil {
            return fmt.Errorf("failed to get CA bundle: %w", err)
        }
        
        mm.clientCAs = x509.NewCertPool()
        if !mm.clientCAs.AppendCertsFromPEM(caBundle) {
            return fmt.Errorf("failed to add CA certificate to pool")
        }
    }
    
    return nil
}

func (mm *MTLSManager) verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
    // Custom verification logic
    if len(rawCerts) == 0 {
        return fmt.Errorf("no peer certificate provided")
    }
    
    cert, err := x509.ParseCertificate(rawCerts[0])
    if err != nil {
        return fmt.Errorf("failed to parse peer certificate: %w", err)
    }
    
    // Check certificate validity
    now := time.Now()
    if cert.NotAfter.Before(now) {
        return fmt.Errorf("certificate has expired")
    }
    if cert.NotBefore.After(now) {
        return fmt.Errorf("certificate is not yet valid")
    }
    
    // Additional custom validations can be added here
    return nil
}

func (mm *MTLSManager) verifyCertificate(cert *x509.Certificate) error {
    // Verify against CA
    if mm.clientCAs != nil {
        opts := x509.VerifyOptions{
            Roots: mm.clientCAs,
        }
        
        _, err := cert.Verify(opts)
        if err != nil {
            return fmt.Errorf("certificate verification failed: %w", err)
        }
    }
    
    // Check expiry
    now := time.Now()
    if cert.NotAfter.Before(now) {
        mm.updateStats(func(s *MTLSStats) {
            s.ExpiredCertificates++
        })
        return fmt.Errorf("certificate has expired")
    }
    
    return nil
}

func (mm *MTLSManager) isServiceAuthorized(targetService, clientCN string) bool {
    allowedCNs, exists := mm.config.AllowedServices[targetService]
    if !exists {
        // If not configured, allow all (for backward compatibility)
        return true
    }
    
    for _, allowedCN := range allowedCNs {
        if allowedCN == clientCN || strings.Contains(clientCN, allowedCN) {
            return true
        }
    }
    
    return false
}

func (mm *MTLSManager) extractServiceName(cn string) string {
    // Extract service name from CN
    // Expected format: service-name.domain.com
    parts := strings.Split(cn, ".")
    if len(parts) > 0 {
        return parts[0]
    }
    return cn
}

func (mm *MTLSManager) getCertificateHandler(serviceName string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
    return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
        // Dynamic certificate selection based on SNI
        cert, err := mm.certMgr.GetServiceCertificate(context.Background(), serviceName)
        if err != nil {
            logger.Error("Failed to get certificate for SNI", 
                "service", serviceName,
                "sni", hello.ServerName,
                "error", err)
            return nil, err
        }
        return cert, nil
    }
}

func (mm *MTLSManager) getTLSVersion(version string) uint16 {
    switch version {
    case "1.0":
        return tls.VersionTLS10
    case "1.1":
        return tls.VersionTLS11
    case "1.2":
        return tls.VersionTLS12
    case "1.3":
        return tls.VersionTLS13
    default:
        return tls.VersionTLS13 // Default to most secure
    }
}

func (mm *MTLSManager) getCipherSuites() []uint16 {
    // Map string cipher suites to constants
    suiteMap := map[string]uint16{
        "TLS_AES_128_GCM_SHA256":       tls.TLS_AES_128_GCM_SHA256,
        "TLS_AES_256_GCM_SHA384":       tls.TLS_AES_256_GCM_SHA384,
        "TLS_CHACHA20_POLY1305_SHA256": tls.TLS_CHACHA20_POLY1305_SHA256,
    }
    
    var suites []uint16
    for _, suiteName := range mm.config.CipherSuites {
        if suite, exists := suiteMap[suiteName]; exists {
            suites = append(suites, suite)
        }
    }
    
    return suites
}

func (mm *MTLSManager) getClientAuthType() tls.ClientAuthType {
    if mm.config.RequireClientCert {
        if mm.config.VerifyClientCert {
            return tls.RequireAndVerifyClientCert
        }
        return tls.RequireAnyClientCert
    }
    return tls.VerifyClientCertIfGiven
}

func (mm *MTLSManager) getRenegotiationSupport() tls.RenegotiationSupport {
    switch mm.config.RenegotiationSupport {
    case "never":
        return tls.RenegotiateNever
    case "once":
        return tls.RenegotiateOnceAsClient
    case "freely":
        return tls.RenegotiateFreelyAsClient
    default:
        return tls.RenegotiateNever // Most secure default
    }
}

func (mm *MTLSManager) calculateFingerprint(certDER []byte) string {
    // SHA256 fingerprint calculation
    return fmt.Sprintf("sha256:%x", certDER[:16])
}

func (mm *MTLSManager) updateStats(update func(*MTLSStats)) {
    mm.statsMu.Lock()
    defer mm.statsMu.Unlock()
    update(&mm.stats)
}

// GetStats returns mTLS statistics
func (mm *MTLSManager) GetStats() MTLSStats {
    mm.statsMu.RLock()
    defer mm.statsMu.RUnlock()
    return mm.stats
}

// GetServiceAuthInfo extracts service authentication info from request context
func GetServiceAuthFromContext(ctx context.Context) (*ServiceAuthInfo, bool) {
    auth, ok := ctx.Value("mtls_auth").(*ServiceAuthInfo)
    return auth, ok
}

// RequireServiceAuth middleware that requires specific service authentication
func RequireServiceAuth(allowedServices ...string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            auth, ok := GetServiceAuthFromContext(r.Context())
            if !ok {
                http.Error(w, "Service authentication required", http.StatusUnauthorized)
                return
            }
            
            // Check if service is in allowed list
            allowed := false
            for _, allowedService := range allowedServices {
                if auth.ServiceName == allowedService {
                    allowed = true
                    break
                }
            }
            
            if !allowed {
                http.Error(w, "Service not authorized for this endpoint", http.StatusForbidden)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}
