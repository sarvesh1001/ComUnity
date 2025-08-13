package config

import (
	"context"
	"fmt"

	"github.com/ComUnity/auth-service/internal/util/logger"
	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// SecretsManagerClient defines a minimal interface for AWS Secrets Manager
type SecretsManagerClient interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// AWSSecretsLoader loads secrets from AWS Secrets Manager
type AWSSecretsLoader struct {
	client SecretsManagerClient
}

// NewAWSSecretsLoader creates a new loader with default AWS config
func NewAWSSecretsLoader() (*AWSSecretsLoader, error) {
	cfg, err := awscfg.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &AWSSecretsLoader{
		client: secretsmanager.NewFromConfig(cfg),
	}, nil
}

// GetSecret retrieves a secret value from AWS Secrets Manager
func (l *AWSSecretsLoader) GetSecret(secretName string) (string, error) {
	logger.Infof("[SecretsLoader] Retrieving secret: %s", secretName)

	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	}

	result, err := l.client.GetSecretValue(context.TODO(), input)
	if err != nil {
		logger.Errorf("[SecretsLoader] Failed to get secret %s: %v", secretName, err)
		return "", fmt.Errorf("failed to get secret: %w", err)
	}

	if result.SecretString == nil {
		logger.Errorf("[SecretsLoader] Secret value is nil: %s", secretName)
		return "", fmt.Errorf("secret value is nil")
	}

	logger.Infof("[SecretsLoader] Retrieved secret: %s", secretName)
	return *result.SecretString, nil
}
