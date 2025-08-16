package security

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Interfaces

type KMSClient interface {
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyRotationStatus(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
}

// Config

type KMSConfig struct {
	KeyID             string
	EncryptionContext map[string]string
	Timeout           time.Duration

	// Public key cache TTL (for Verify path). Defaults to 24h.
	PublicKeyCacheTTL time.Duration
}

// Helper

type Helper struct {
	client KMSClient
	cfg    KMSConfig

	pubKeyParsed   crypto.PublicKey
	pubKeyFetched  bool
	pubKeyFetchedAt time.Time
}

// Constructors

func NewKMSHelper(ctx context.Context, cfg KMSConfig, optFns ...func(*awscfg.LoadOptions) error) (*Helper, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.PublicKeyCacheTTL <= 0 {
		cfg.PublicKeyCacheTTL = 24 * time.Hour
	}
	awsCfg, err := awscfg.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &Helper{
		client: kms.NewFromConfig(awsCfg),
		cfg:    cfg,
	}, nil
}

func WithClient(client KMSClient, cfg KMSConfig) *Helper {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.PublicKeyCacheTTL <= 0 {
		cfg.PublicKeyCacheTTL = 24 * time.Hour
	}
	return &Helper{client: client, cfg: cfg}
}

// Direct small payload encryption (<=4KB)

func (h *Helper) EncryptSmall(ctx context.Context, plaintext []byte) ([]byte, error) {
	if h.cfg.KeyID == "" {
		return nil, errors.New("kms: KeyID required for Encrypt")
	}
	cctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	defer cancel()

	in := &kms.EncryptInput{
		KeyId:     aws.String(h.cfg.KeyID),
		Plaintext: plaintext,
	}
	if len(h.cfg.EncryptionContext) > 0 {
		in.EncryptionContext = h.cfg.EncryptionContext
	}
	out, err := h.client.Encrypt(cctx, in)
	if err != nil {
		return nil, fmt.Errorf("kms Encrypt: %w", err)
	}
	return out.CiphertextBlob, nil
}

func (h *Helper) DecryptSmall(ctx context.Context, ciphertext []byte) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	defer cancel()

	in := &kms.DecryptInput{CiphertextBlob: ciphertext}
	if len(h.cfg.EncryptionContext) > 0 {
		in.EncryptionContext = h.cfg.EncryptionContext
	}
	out, err := h.client.Decrypt(cctx, in)
	if err != nil {
		return nil, fmt.Errorf("kms Decrypt: %w", err)
	}
	return out.Plaintext, nil
}

// Envelope encryption

type DataKey struct {
	Plaintext     []byte // caller must wipe after use
	CiphertextB64 string // safe to store
}

// Generate a symmetric data key (e.g., AES-256) for envelope encryption.
func (h *Helper) GenerateDataKey(ctx context.Context, keySpec kmstypes.DataKeySpec) (*DataKey, error) {
	if h.cfg.KeyID == "" {
		return nil, errors.New("kms: KeyID required for GenerateDataKey")
	}
	cctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	defer cancel()

	in := &kms.GenerateDataKeyInput{
		KeyId:   aws.String(h.cfg.KeyID),
		KeySpec: keySpec,
	}
	if len(h.cfg.EncryptionContext) > 0 {
		in.EncryptionContext = h.cfg.EncryptionContext
	}
	out, err := h.client.GenerateDataKey(cctx, in)
	if err != nil {
		return nil, fmt.Errorf("kms GenerateDataKey: %w", err)
	}
	return &DataKey{
		Plaintext:     out.Plaintext,
		CiphertextB64: base64.StdEncoding.EncodeToString(out.CiphertextBlob),
	}, nil
}

// Decrypt a stored data key back into plaintext (remember to wipe).
func (h *Helper) DecryptDataKey(ctx context.Context, ciphertextB64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("kms DecryptDataKey: base64: %w", err)
	}
	cctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	defer cancel()

	in := &kms.DecryptInput{CiphertextBlob: raw}
	if len(h.cfg.EncryptionContext) > 0 {
		in.EncryptionContext = h.cfg.EncryptionContext
	}
	out, err := h.client.Decrypt(cctx, in)
	if err != nil {
		return nil, fmt.Errorf("kms DecryptDataKey: %w", err)
	}
	return out.Plaintext, nil
}

// AES-GCM helpers using a DataKey’s plaintext.
// Ciphertext format: nonce || gcm-sealed-bytes
func (dk *DataKey) Encrypt(plaintext []byte, aad []byte) ([]byte, error) {
	if len(dk.Plaintext) == 0 {
		return nil, errors.New("kms: empty data key")
	}
	block, err := aes.NewCipher(dk.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, aad)
	return ciphertext, nil
}

func (dk *DataKey) Decrypt(ciphertext []byte, aad []byte) ([]byte, error) {
	if len(dk.Plaintext) == 0 {
		return nil, errors.New("kms: empty data key")
	}
	block, err := aes.NewCipher(dk.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:ns], ciphertext[ns:]
	plain, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("gcm.Open: %w", err)
	}
	return plain, nil
}

// Signing and verification

func (h *Helper) Sign(ctx context.Context, message []byte, alg kmstypes.SigningAlgorithmSpec) ([]byte, error) {
	if h.cfg.KeyID == "" {
		return nil, errors.New("kms: KeyID required for Sign")
	}
	cctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	defer cancel()

	in := &kms.SignInput{
		KeyId:            aws.String(h.cfg.KeyID),
		Message:          message,
		MessageType:      kmstypes.MessageTypeRaw, // change to Digest if you pass a pre-hash
		SigningAlgorithm: alg,
	}
	out, err := h.client.Sign(cctx, in)
	if err != nil {
		return nil, fmt.Errorf("kms Sign: %w", err)
	}
	return out.Signature, nil
}

func (h *Helper) GetPublicKey(ctx context.Context) (crypto.PublicKey, error) {
	// Soft TTL: refresh after TTL or on rotation enabled
	if h.pubKeyFetched && time.Since(h.pubKeyFetchedAt) < h.cfg.PublicKeyCacheTTL && h.pubKeyParsed != nil {
		return h.pubKeyParsed, nil
	}

	// If TTL expired, and rotation is enabled, force refresh
	if h.pubKeyFetched && time.Since(h.pubKeyFetchedAt) >= h.cfg.PublicKeyCacheTTL {
		rotEnabled, err := h.isKeyRotationEnabled(ctx)
		if err == nil && rotEnabled {
			h.pubKeyParsed = nil
			h.pubKeyFetched = false
		}
	}

	cctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	defer cancel()

	out, err := h.client.GetPublicKey(cctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(h.cfg.KeyID),
	})
	if err != nil {
		return nil, fmt.Errorf("kms GetPublicKey: %w", err)
	}
	if out.PublicKey == nil {
		return nil, errors.New("kms: GetPublicKey returned nil")
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("kms parse public key: %w", err)
	}
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
	default:
		return nil, fmt.Errorf("kms: unsupported public key type %T", pub)
	}
	h.pubKeyParsed = pub
	h.pubKeyFetched = true
	h.pubKeyFetchedAt = time.Now()
	return pub, nil
}

func (h *Helper) Verify(ctx context.Context, message []byte, signature []byte, alg kmstypes.SigningAlgorithmSpec) error {
	pub, err := h.GetPublicKey(ctx)
	if err != nil {
		return err
	}

	switch p := pub.(type) {
	case *rsa.PublicKey:
		switch alg {
		case kmstypes.SigningAlgorithmSpecRsassaPssSha256:
			sum, hash, pssOpts := sha256Sum(message), crypto.SHA256, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
			if err := rsa.VerifyPSS(p, hash, sum, signature, pssOpts); err != nil {
				return fmt.Errorf("rsa pss verify failed: %w", err)
			}
			return nil
		case kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
			sum, hash := sha256Sum(message), crypto.SHA256
			if err := rsa.VerifyPKCS1v15(p, hash, sum, signature); err != nil {
				return fmt.Errorf("rsa pkcs1v15 verify failed: %w", err)
			}
			return nil
		default:
			return fmt.Errorf("unsupported RSA signing algorithm: %s", alg)
		}
	case *ecdsa.PublicKey:
		switch alg {
		case kmstypes.SigningAlgorithmSpecEcdsaSha256:
			sum := sha256Sum(message)
			if ok := ecdsaVerifyASN1(p, sum, signature); !ok {
				return errors.New("ecdsa verify failed")
			}
			return nil
		default:
			return fmt.Errorf("unsupported ECDSA signing algorithm: %s", alg)
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// Health and rotation

func (h *Helper) KeyHealth(ctx context.Context) (string, error) {
	if h.cfg.KeyID == "" {
		return "unconfigured", nil
	}
	cctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	defer cancel()

	out, err := h.client.DescribeKey(cctx, &kms.DescribeKeyInput{
		KeyId: aws.String(h.cfg.KeyID),
	})
	if err != nil {
		return "unavailable", err
	}
	if out.KeyMetadata == nil {
		return "unknown", nil
	}

	switch out.KeyMetadata.KeyState {
	case kmstypes.KeyStateEnabled:
		return "healthy", nil
	case kmstypes.KeyStatePendingDeletion:
		return "pending_deletion", nil
	default:
		return string(out.KeyMetadata.KeyState), nil
	}
}

func (h *Helper) isKeyRotationEnabled(ctx context.Context) (bool, error) {
	if h.cfg.KeyID == "" {
		return false, nil
	}
	cctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	defer cancel()

	out, err := h.client.GetKeyRotationStatus(cctx, &kms.GetKeyRotationStatusInput{
		KeyId: aws.String(h.cfg.KeyID),
	})
	if err != nil {
		return false, err
	}
	return out.KeyRotationEnabled, nil
}

// Helpers

func sha256Sum(b []byte) []byte {
	h := crypto.SHA256.New()
	_, _ = h.Write(b)
	return h.Sum(nil)
}

// Separate to avoid importing x/crypto for now.
func ecdsaVerifyASN1(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	return ecdsa.VerifyASN1(pub, hash, sig)
}

// Wipe zeros a byte slice in place.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
