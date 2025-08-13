package config

import (
	"context"
	"fmt"

	"github.com/ComUnity/auth-service/internal/util/logger"
	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// SSMParameterStoreClient defines an interface for AWS SSM client
type SSMParameterStoreClient interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// SSMLoader loads parameters from AWS Systems Manager Parameter Store
type SSMLoader struct {
	client SSMParameterStoreClient
}

// NewSSMLoader creates a new loader with default AWS config
func NewSSMLoader() (*SSMLoader, error) {
	cfg, err := awscfg.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &SSMLoader{
		client: ssm.NewFromConfig(cfg),
	}, nil
}

// GetParameter retrieves a parameter from SSM
func (l *SSMLoader) GetParameter(paramName string, decrypt bool) (string, error) {
	logger.Infof("[SSMLoader] Retrieving parameter: %s", paramName)

	input := &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(decrypt),
	}

	result, err := l.client.GetParameter(context.TODO(), input)
	if err != nil {
		logger.Errorf("[SSMLoader] Failed to get parameter %s: %v", paramName, err)
		return "", fmt.Errorf("failed to get parameter: %w", err)
	}

	if result.Parameter == nil || result.Parameter.Value == nil {
		logger.Errorf("[SSMLoader] Parameter value is nil: %s", paramName)
		return "", fmt.Errorf("parameter value is nil")
	}

	logger.Infof("[SSMLoader] Retrieved parameter: %s", paramName)
	return *result.Parameter.Value, nil
}
