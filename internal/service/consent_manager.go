package service

import (
	"context"
	"errors"
	"github.com/ComUnity/auth-service/internal/repository"
	"github.com/ComUnity/auth-service/internal/models"
	"github.com/google/uuid"
)

// Remove the ConsentManager interface declaration - it's already in services.go

type consentManager struct {
	repo repository.ConsentRepository
}

func NewConsentManager(repo repository.ConsentRepository) ConsentManager {
	return &consentManager{repo: repo}
}

func (m *consentManager) RequestChildConsent(ctx context.Context, childID, parentID uuid.UUID) error {
	consent := &models.Consent{
		ChildUserID:  childID,
		ParentUserID: parentID,
		Status:       "PENDING",
	}
	return m.repo.CreateConsent(ctx, consent)
}

func (m *consentManager) ApproveConsent(ctx context.Context, parentID, consentID uuid.UUID) error {
	consent, err := m.repo.GetConsentByID(ctx, consentID)
	if err != nil {
		return err
	}
	if consent.ParentUserID != parentID {
		return errors.New("only the parent can approve")
	}
	return m.repo.UpdateConsentStatus(ctx, consentID, "APPROVED")
}

func (m *consentManager) CheckConsent(ctx context.Context, childID uuid.UUID) (bool, error) {
	c, err := m.repo.GetConsentByChild(ctx, childID)
	if err != nil {
		return false, err
	}
	return c.Status == "APPROVED", nil
}