// internal/service/entitlement.go
package service

import (
	"context"

	"github.com/google/uuid"
)

type EntChecker struct{}

func NewEntitlementChecker() *EntChecker {
	return &EntChecker{}
}

func (e *EntChecker) CheckLicense(ctx context.Context, communityID uuid.UUID, feature string) (bool, error) {
	// TODO: Check against billing/plan DB
	return true, nil
}

func (e *EntChecker) CheckVerification(ctx context.Context, userID uuid.UUID, level string) (bool, error) {
	// TODO: Check if user has verification tick
	return true, nil
}
