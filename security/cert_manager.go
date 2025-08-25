package security
import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/google/uuid"

	"github.com/ComUnity/auth-service/internal/client"
	"github.com/ComUnity/auth-service/internal/models"
	"github.com/ComUnity/auth-service/internal/util/logger"
)

////////////////////////////////////////////////////////////////////////////////
// Simple AWS-backed certificate loader (from your original cert_manager.go)
////////////////////////////////////////////////////////////////////////////////

const (
	certDir      = "/etc/authservice/certs"
	currentCert  = "current-cert.enc"
	currentKey   = "current-key.enc"
	expiryParam  = "/authservice/cert_expiry"
)

// CertManager handles certificate loading and rotation using AWS KMS + SSM
type CertManager struct {
	kmsClient *awskms.Client
	ssmClient *ssm.Client
	cert      *tls.Certificate
	expiry    time.Time
}

func NewCertManager(cfg aws.Config) *CertManager {
	return &CertManager{
		kmsClient: awskms.NewFromConfig(cfg),
		ssmClient: ssm.NewFromConfig(cfg),
	}
}

// LoadCertificate loads and decrypts the current certificate from disk via KMS
func (cm *CertManager) LoadCertificate(ctx context.Context) error {
	certPath := filepath.Join(certDir, currentCert)
	keyPath := filepath.Join(certDir, currentKey)

	certCiphertext, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("error reading cert: %w", err)
	}
	certDec, err := cm.kmsClient.Decrypt(ctx, &awskms.DecryptInput{
		CiphertextBlob: certCiphertext,
	})
	if err != nil {
		return fmt.Errorf("error decrypting cert: %w", err)
	}

	keyCiphertext, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("error reading key: %w", err)
	}
	keyDec, err := cm.kmsClient.Decrypt(ctx, &awskms.DecryptInput{
		CiphertextBlob: keyCiphertext,
	})
	if err != nil {
		return fmt.Errorf("error decrypting key: %w", err)
	}

	pair, err := tls.X509KeyPair(certDec.Plaintext, keyDec.Plaintext)
	if err != nil {
		return fmt.Errorf("error parsing key pair: %w", err)
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)
	}

	cm.cert = &pair
	cm.expiry = leaf.NotAfter

	_, err = cm.ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(expiryParam),
		Value:     aws.String(cm.expiry.Format(time.RFC3339)),
		Type:      "String",
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("error updating SSM parameter: %w", err)
	}
	return nil
}

func (cm *CertManager) GetCertificate() *tls.Certificate { return cm.cert }

func (cm *CertManager) ShouldRotate() bool {
	return time.Until(cm.expiry) < 1524*time.Hour
}

func (cm *CertManager) GetExpiry() time.Time { return cm.expiry }

////////////////////////////////////////////////////////////////////////////////
// Full-featured in-service CA-backed CertificateManager (from your copy)
////////////////////////////////////////////////////////////////////////////////

// CertificateConfig holds configuration for certificate management
type CertificateConfig struct {
	Enabled               bool              `yaml:"enabled"`
	CAConfig              CAConfig          `yaml:"ca_config"`
	CertificateLifetime   time.Duration     `yaml:"certificate_lifetime"`
	RenewalThreshold      time.Duration     `yaml:"renewal_threshold"`
	KeySize               int               `yaml:"key_size"`
	Organization          string            `yaml:"organization"`
	Country               string            `yaml:"country"`
	Province              string            `yaml:"province"`
	City                  string            `yaml:"city"`
	AutoRenew             bool              `yaml:"auto_renew"`
	EnableOCSP            bool              `yaml:"enable_ocsp"`
	CRLDistributionPoint  string            `yaml:"crl_distribution_point"`
	ServiceDomains        map[string][]string `yaml:"service_domains"`
}

// CAConfig holds Certificate Authority configuration
type CAConfig struct {
	KeySize        int           `yaml:"key_size"`
	Lifetime       time.Duration `yaml:"lifetime"`
	CommonName     string        `yaml:"common_name"`
	Organization   string        `yaml:"organization"`
	KeyUsage       []string      `yaml:"key_usage"`
	EnablePathLen  bool          `yaml:"enable_path_len"`
	MaxPathLen     int           `yaml:"max_path_len"`
}

// CertificateInfo represents stored certificate information
type CertificateInfo struct {
	ID             string        `json:"id"`
	CommonName     string        `json:"common_name"`
	SANs           []string      `json:"sans"`
	ServiceName    string        `json:"service_name"`
	CertificatePEM string        `json:"certificate_pem"`
	PrivateKeyPEM  string        `json:"private_key_pem"`
	IssuerCN       string        `json:"issuer_cn"`
	SerialNumber   string        `json:"serial_number"`
	NotBefore      time.Time     `json:"not_before"`
	NotAfter       time.Time     `json:"not_after"`
	IsCA           bool          `json:"is_ca"`
	KeyUsage       []string      `json:"key_usage"`
	Status         string        `json:"status"` // ACTIVE, EXPIRED, REVOKED
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
	Metadata       models.JSONMap `json:"metadata"`
	Fingerprint    string        `json:"fingerprint"`
	KeyID          string        `json:"key_id"` // KMS/data key id
}

// CAInfo represents Certificate Authority information
type CAInfo struct {
	CertificateInfo
	IsRoot        bool      `json:"is_root"`
	ParentCAID    string    `json:"parent_ca_id"`
	PathLength    int       `json:"path_length"`
	CRLNumber     int64     `json:"crl_number"`
	NextCRLUpdate time.Time `json:"next_crl_update"`
}

// CertificateManager handles certificate lifecycle management for mTLS
type CertificateManager struct {
	redis     *client.RedisClient
	kmsHelper *Helper
	config    CertificateConfig

	rootCA   *CAInfo
	caChain  []*CAInfo

	certCache sync.Map // map[string]*tls.Certificate

	renewalMu  sync.RWMutex
	renewalMap map[string]time.Time

	stats   CertManagerStats
	statsMu sync.RWMutex
}

// CertManagerStats tracks certificate management statistics
type CertManagerStats struct {
	TotalCertificates    int64      `json:"total_certificates"`
	ActiveCertificates   int64      `json:"active_certificates"`
	ExpiredCertificates  int64      `json:"expired_certificates"`
	RevokedCertificates  int64      `json:"revoked_certificates"`
	CertificatesIssued   int64      `json:"certificates_issued"`
	CertificatesRenewed  int64      `json:"certificates_renewed"`
	LastIssued          *time.Time `json:"last_issued,omitempty"`
	LastRenewal         *time.Time `json:"last_renewal,omitempty"`
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(redis *client.RedisClient, kmsHelper *Helper, config CertificateConfig) (*CertificateManager, error) {
	if config.CertificateLifetime == 0 {
		config.CertificateLifetime = 90 * 24 * time.Hour
	}
	if config.RenewalThreshold == 0 {
		config.RenewalThreshold = 30 * 24 * time.Hour
	}
	if config.KeySize == 0 {
		config.KeySize = 4096
	}
	if config.CAConfig.KeySize == 0 {
		config.CAConfig.KeySize = 4096
	}
	if config.CAConfig.Lifetime == 0 {
		config.CAConfig.Lifetime = 10 * 365 * 24 * time.Hour
	}

	cm := &CertificateManager{
		redis:      redis,
		kmsHelper:  kmsHelper,
		config:     config,
		renewalMap: make(map[string]time.Time),
	}

	if config.Enabled {
		if err := cm.initializeCA(); err != nil {
			return nil, fmt.Errorf("failed to initialize CA: %w", err)
		}
		go cm.renewalWorker()
		logger.Info("Certificate manager initialized",
			"ca_cn", cm.rootCA.CommonName,
			"auto_renew", config.AutoRenew)
	}
	return cm, nil
}

func (cm *CertificateManager) initializeCA() error {
	ca, err := cm.loadCA()
	if err != nil || ca == nil {
		logger.Info("Creating new Certificate Authority")
		ca, err = cm.createCA()
		if err != nil {
			return fmt.Errorf("failed to create CA: %w", err)
		}
	} else {
		logger.Info("Loaded existing Certificate Authority", "cn", ca.CommonName)
	}
	cm.rootCA = ca
	return nil
}

func (cm *CertificateManager) createCA() (*CAInfo, error) {
	caPrivKey, err := rsa.GenerateKey(rand.Reader, cm.config.CAConfig.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         cm.config.CAConfig.CommonName,
			Organization:       []string{cm.config.Organization},
			Country:            []string{cm.config.Country},
			Province:           []string{cm.config.Province},
			Locality:           []string{cm.config.City},
			OrganizationalUnit: []string{"Certificate Authority"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(cm.config.CAConfig.Lifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            cm.config.CAConfig.MaxPathLen,
		MaxPathLenZero:        !cm.config.CAConfig.EnablePathLen,
	}
	if cm.config.CRLDistributionPoint != "" {
		tmpl.CRLDistributionPoints = []string{cm.config.CRLDistributionPoint}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privDER, err := x509.MarshalPKCS8PrivateKey(caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CA key: %w", err)
	}

	encryptedKeyPEM, keyID, err := cm.encryptPrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt CA private key: %w", err)
	}

	now := time.Now()
	caInfo := &CAInfo{
		CertificateInfo: CertificateInfo{
			ID:             uuid.New().String(),
			CommonName:     caCert.Subject.CommonName,
			ServiceName:    "certificate-authority",
			CertificatePEM: string(certPEM),
			PrivateKeyPEM:  string(encryptedKeyPEM),
			IssuerCN:       caCert.Issuer.CommonName,
			SerialNumber:   caCert.SerialNumber.String(),
			NotBefore:      caCert.NotBefore,
			NotAfter:       caCert.NotAfter,
			IsCA:           true,
			Status:         "ACTIVE",
			CreatedAt:      now,
			UpdatedAt:      now,
			Fingerprint:    cm.calculateFingerprint(caCert.Raw),
			KeyID:          keyID,
		},
		IsRoot:        true,
		PathLength:    cm.config.CAConfig.MaxPathLen,
		CRLNumber:     1,
		NextCRLUpdate: time.Now().Add(24 * time.Hour),
	}

	if err := cm.storeCA(caInfo); err != nil {
		return nil, fmt.Errorf("failed to store CA: %w", err)
	}
	cm.updateStats(func(s *CertManagerStats) {
		s.TotalCertificates++
		s.ActiveCertificates++
		s.CertificatesIssued++
		s.LastIssued = &now
	})
	logger.Info("Certificate Authority created",
		"cn", caInfo.CommonName, "serial", caInfo.SerialNumber, "expires", caInfo.NotAfter)
	return caInfo, nil
}

// IssueCertificate issues a new service certificate
func (cm *CertificateManager) IssueCertificate(ctx context.Context, serviceName, commonName string, sans []string) (*CertificateInfo, error) {
	if !cm.config.Enabled {
		return nil, fmt.Errorf("certificate manager is disabled")
	}
	logger.Info("Issuing certificate", "service", serviceName, "cn", commonName, "sans", sans)

	privKey, err := rsa.GenerateKey(rand.Reader, cm.config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	caCert, caKey, err := cm.loadCAForSigning()
	if err != nil {
		return nil, fmt.Errorf("failed to load CA: %w", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(0).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to gen serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{cm.config.Organization},
			Country:      []string{cm.config.Country},
			Province:     []string{cm.config.Province},
			Locality:     []string{cm.config.City},
		},
		DNSNames:              sans,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(cm.config.CertificateLifetime),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if cm.config.EnableOCSP {
		tmpl.OCSPServer = []string{fmt.Sprintf("http://ocsp.%s/", cm.config.Organization)}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign cert: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}

	encKeyPEM, keyID, err := cm.encryptPrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	now := time.Now()
	info := &CertificateInfo{
		ID:             uuid.New().String(),
		CommonName:     cert.Subject.CommonName,
		SANs:           cert.DNSNames,
		ServiceName:    serviceName,
		CertificatePEM: string(certPEM),
		PrivateKeyPEM:  string(encKeyPEM),
		IssuerCN:       cert.Issuer.CommonName,
		SerialNumber:   cert.SerialNumber.String(),
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		IsCA:           false,
		Status:         "ACTIVE",
		CreatedAt:      now,
		UpdatedAt:      now,
		Fingerprint:    cm.calculateFingerprint(cert.Raw),
		KeyID:          keyID,
		Metadata: models.JSONMap{
			"issuer_id":     cm.rootCA.ID,
			"key_usage":     tmpl.KeyUsage,
			"ext_key_usage": tmpl.ExtKeyUsage,
		},
	}

	if err := cm.storeCertificate(info); err != nil {
		return nil, fmt.Errorf("failed to store certificate: %w", err)
	}

	cm.scheduleRenewal(info.ID, info.NotAfter.Add(-cm.config.RenewalThreshold))
	cm.updateStats(func(s *CertManagerStats) {
		s.TotalCertificates++
		s.ActiveCertificates++
		s.CertificatesIssued++
		s.LastIssued = &now
	})

	logger.Info("Certificate issued", "service", serviceName, "cn", commonName, "serial", info.SerialNumber, "expires", info.NotAfter)
	return info, nil
}

// GetServiceCertificate returns a cached TLS certificate for a service
func (cm *CertificateManager) GetServiceCertificate(ctx context.Context, serviceName string) (*tls.Certificate, error) {
	if !cm.config.Enabled {
		return nil, fmt.Errorf("certificate manager is disabled")
	}

	if cached, ok := cm.certCache.Load(serviceName); ok {
		return cached.(*tls.Certificate), nil
	}

	info, err := cm.loadServiceCertificate(serviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to load service certificate: %w", err)
	}

	if time.Until(info.NotAfter) < cm.config.RenewalThreshold {
		logger.Warn("Certificate expiring soon", "service", serviceName, "expires", info.NotAfter)
		if cm.config.AutoRenew {
			go cm.renewCertificate(ctx, info)
		}
	}

	privKey, err := cm.decryptPrivateKey([]byte(info.PrivateKeyPEM), info.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	tlsCert, err := tls.X509KeyPair([]byte(info.CertificatePEM), privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS pair: %w", err)
	}

	cm.certCache.Store(serviceName, &tlsCert)
	return &tlsCert, nil
}

func (cm *CertificateManager) RenewCertificate(ctx context.Context, certID string) (*CertificateInfo, error) {
	info, err := cm.loadCertificateByID(certID)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}
	return cm.renewCertificate(ctx, info)
}

func (cm *CertificateManager) renewCertificate(ctx context.Context, oldCert *CertificateInfo) (*CertificateInfo, error) {
	logger.Info("Renewing certificate", "service", oldCert.ServiceName, "cn", oldCert.CommonName, "old_expires", oldCert.NotAfter)
	newCert, err := cm.IssueCertificate(ctx, oldCert.ServiceName, oldCert.CommonName, oldCert.SANs)
	if err != nil {
		return nil, fmt.Errorf("failed to issue renewal: %w", err)
	}

	oldCert.Status = "EXPIRED"
	oldCert.UpdatedAt = time.Now()
	if err := cm.storeCertificate(oldCert); err != nil {
		logger.Warn("Failed to update old certificate status", "error", err)
	}

	cm.certCache.Delete(oldCert.ServiceName)
	cm.updateStats(func(s *CertManagerStats) {
		s.CertificatesRenewed++
		s.ExpiredCertificates++
		now := time.Now()
		s.LastRenewal = &now
	})
	logger.Info("Certificate renewed", "service", newCert.ServiceName, "cn", newCert.CommonName, "new_expires", newCert.NotAfter)
	return newCert, nil
}

func (cm *CertificateManager) RevokeCertificate(ctx context.Context, certID string, reason string) error {
	info, err := cm.loadCertificateByID(certID)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}
	info.Status = "REVOKED"
	info.UpdatedAt = time.Now()
	if info.Metadata == nil {
		info.Metadata = models.JSONMap{}
	}
	info.Metadata["revocation_reason"] = reason
	info.Metadata["revoked_at"] = time.Now()

	if err := cm.storeCertificate(info); err != nil {
		return fmt.Errorf("failed to update certificate: %w", err)
	}
	cm.certCache.Delete(info.ServiceName)
	cm.renewalMu.Lock()
	delete(cm.renewalMap, info.ID)
	cm.renewalMu.Unlock()
	cm.updateStats(func(s *CertManagerStats) {
		s.RevokedCertificates++
		s.ActiveCertificates--
	})
	logger.Info("Certificate revoked", "service", info.ServiceName, "cn", info.CommonName, "reason", reason)
	return nil
}

func (cm *CertificateManager) GetCABundle() ([]byte, error) {
	if cm.rootCA == nil {
		return nil, fmt.Errorf("CA not initialized")
	}
	return []byte(cm.rootCA.CertificatePEM), nil
}

func (cm *CertificateManager) ValidateCertificate(certPEM []byte) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to parse PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	caBundle, err := cm.GetCABundle()
	if err != nil {
		return fmt.Errorf("failed to get CA bundle: %w", err)
	}
	caBlock, _ := pem.Decode(caBundle)
	if caBlock == nil {
		return fmt.Errorf("failed to parse CA certificate")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots})
	return err
}

func (cm *CertificateManager) GetStats() CertManagerStats {
	cm.statsMu.RLock()
	defer cm.statsMu.RUnlock()
	return cm.stats
}

////////////////////////////////////////////////////////////////////////////////
// Storage and helpers for CertificateManager
////////////////////////////////////////////////////////////////////////////////

func (cm *CertificateManager) encryptPrivateKey(keyDER []byte) ([]byte, string, error) {
	dk, err := cm.kmsHelper.GenerateDataKey(context.Background(), "AES_256")
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate data key: %w", err)
	}
	defer Wipe(dk.Plaintext)

	encryptedKey, err := dk.Encrypt(keyDER, []byte("private_key"))
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt private key: %w", err)
	}

	encPEM := &pem.Block{
		Type: "ENCRYPTED PRIVATE KEY",
		Headers: map[string]string{
			"Data-Key": dk.CiphertextB64,
		},
		Bytes: encryptedKey,
	}
	return pem.EncodeToMemory(encPEM), dk.CiphertextB64, nil
}

func (cm *CertificateManager) decryptPrivateKey(encryptedPEM []byte, keyID string) ([]byte, error) {
	block, _ := pem.Decode(encryptedPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse encrypted PEM")
	}
	dataKeyB64, ok := block.Headers["Data-Key"]
	if !ok {
		return nil, fmt.Errorf("no data key in PEM headers")
	}

	plaintextKey, err := cm.kmsHelper.DecryptDataKey(context.Background(), dataKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %w", err)
	}
	defer Wipe(plaintextKey)

	dk := &DataKey{
		Plaintext:     plaintextKey,
		CiphertextB64: dataKeyB64,
	}
	keyDER, err := dk.Decrypt(block.Bytes, []byte("private_key"))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}
	return pem.EncodeToMemory(pemBlock), nil
}

func (cm *CertificateManager) calculateFingerprint(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	// Short representation as in your example
	return fmt.Sprintf("sha256:%x", sum[:8])
}

func (cm *CertificateManager) storeCA(ca *CAInfo) error {
	key := "ca:root"
	return cm.redis.SetJSON(context.Background(), key, ca, 0)
}

func (cm *CertificateManager) loadCA() (*CAInfo, error) {
	key := "ca:root"
	var ca CAInfo
	if err := cm.redis.GetJSON(context.Background(), key, &ca); err != nil {
		return nil, err
	}
	return &ca, nil
}

func (cm *CertificateManager) storeCertificate(cert *CertificateInfo) error {
	key := fmt.Sprintf("cert:%s", cert.ID)
	serviceKey := fmt.Sprintf("cert:service:%s", cert.ServiceName)
	if err := cm.redis.SetJSON(context.Background(), key, cert, 0); err != nil {
		return err
	}
	return cm.redis.SetJSON(context.Background(), serviceKey, cert, 0)
}

func (cm *CertificateManager) loadServiceCertificate(serviceName string) (*CertificateInfo, error) {
	key := fmt.Sprintf("cert:service:%s", serviceName)
	var cert CertificateInfo
	if err := cm.redis.GetJSON(context.Background(), key, &cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

func (cm *CertificateManager) loadCertificateByID(certID string) (*CertificateInfo, error) {
	key := fmt.Sprintf("cert:%s", certID)
	var cert CertificateInfo
	if err := cm.redis.GetJSON(context.Background(), key, &cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

func (cm *CertificateManager) loadCAForSigning() (*x509.Certificate, interface{}, error) {
	caBlock, _ := pem.Decode([]byte(cm.rootCA.CertificatePEM))
	if caBlock == nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caKeyPEM, err := cm.decryptPrivateKey([]byte(cm.rootCA.PrivateKeyPEM), cm.rootCA.KeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt CA private key: %w", err)
	}
	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key PEM")
	}
	caKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}
	return caCert, caKey, nil
}

func (cm *CertificateManager) scheduleRenewal(certID string, renewalTime time.Time) {
	cm.renewalMu.Lock()
	defer cm.renewalMu.Unlock()
	cm.renewalMap[certID] = renewalTime
}

func (cm *CertificateManager) renewalWorker() {
	if !cm.config.AutoRenew {
		return
	}
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		cm.renewalMu.RLock()
		var toRenew []string
		for certID, rt := range cm.renewalMap {
			if now.After(rt) {
				toRenew = append(toRenew, certID)
			}
		}
		cm.renewalMu.RUnlock()

		for _, id := range toRenew {
			go func(cid string) {
				if _, err := cm.RenewCertificate(context.Background(), cid); err != nil {
					logger.Error("Auto-renewal failed", "cert_id", cid, "error", err)
				} else {
					cm.renewalMu.Lock()
					delete(cm.renewalMap, cid)
					cm.renewalMu.Unlock()
				}
			}(id)
		}
	}
}

func (cm *CertificateManager) updateStats(update func(*CertManagerStats)) {
	cm.statsMu.Lock()
	defer cm.statsMu.Unlock()
	update(&cm.stats)
}

////////////////////////////////////////////////////////////////////////////////
// Minimal Helper/DataKey/Wipe placeholders (only if not already defined)
// If your package already defines these, remove this section.
////////////////////////////////////////////////////////////////////////////////
