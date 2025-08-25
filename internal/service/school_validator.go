package service

import (
	"context"
	"errors"
	"github.com/ComUnity/auth-service/internal/models"
	"github.com/ComUnity/auth-service/internal/repository"
	"github.com/google/uuid"
)

// Remove the SchoolValidator interface declaration - it's already in services.go

type schoolValidator struct {
	repo repository.SchoolRepository
}

func NewSchoolValidator(repo repository.SchoolRepository) SchoolValidator {
	return &schoolValidator{repo: repo}
}

func (v *schoolValidator) RegisterSchool(ctx context.Context, name string, paid bool) (*models.School, error) {
	if !paid {
		return nil, errors.New("school must pay to register")
	}
	s := &models.School{Name: name, Paid: paid, Validated: false}
	if err := v.repo.RegisterSchool(ctx, s); err != nil {
		return nil, err
	}
	return s, nil
}

func (v *schoolValidator) ValidateSchool(ctx context.Context, schoolID uuid.UUID) error {
	return v.repo.ValidateSchool(ctx, schoolID)
}

func (v *schoolValidator) IsSchoolValid(ctx context.Context, schoolID uuid.UUID) (bool, error) {
	s, err := v.repo.GetSchoolByID(ctx, schoolID)
	if err != nil {
		return false, err
	}
	return s.Paid && s.Validated, nil
}