package service

import (
    "context"
    "errors"
    "strings"
    "time"

    "github.com/ComUnity/auth-service/internal/models"
    "github.com/ComUnity/auth-service/internal/repository"
    "github.com/google/uuid"
)

var allowedCommunityTypes = map[string]bool{
    "SCHOOL": true, "COLLEGE": true, "GOVERNMENT": true,
    "NGO": true, "BUSINESS": true, "SOCIAL": true, "OTHERS": true,
}

type CommunityCoreService interface {
    CreateCommunity(ctx context.Context, creatorUserID uuid.UUID, in CreateCommunityInput) (*models.Community, error)
    UpdateCommunity(ctx context.Context, in UpdateCommunityInput) error
    GetCommunityByID(ctx context.Context, communityID uuid.UUID) (*models.Community, error)

    ListByType(ctx context.Context, t string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.Community, error)
    ListUserCommunities(ctx context.Context, userID uuid.UUID, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.Community, error)
}

type CreateCommunityInput struct {
    Name                  string
    Description           *string
    Type                  string
    IsPrivate             bool
    AutoApproveMembers    *bool
    AllowMemberPosts      *bool
    AllowMemberInvites    *bool
    RequireApprovalToPost *bool
    LocationData          models.JSONMap
}

type UpdateCommunityInput struct {
    ID                    uuid.UUID
    Name                  *string
    Description           *string
    Type                  *string
    IsPrivate             *bool
    HeadUserID            *uuid.UUID
    VerificationStatus    *string
    IsBlocked             *bool
    BlockReason           *string
    AutoApproveMembers    *bool
    AllowMemberPosts      *bool
    AllowMemberInvites    *bool
    RequireApprovalToPost *bool
    LocationData          *models.JSONMap
}

type communityCoreService struct {
    repo repository.CommunityCoreRepository
}

func NewCommunityCoreService(repo repository.CommunityCoreRepository) CommunityCoreService {
    return &communityCoreService{repo: repo}
}

func (s *communityCoreService) CreateCommunity(ctx context.Context, creatorUserID uuid.UUID, in CreateCommunityInput) (*models.Community, error) {
    if creatorUserID == uuid.Nil {
        return nil, errors.New("missing creator user ID")
    }

    // Normalize: trim + collapse multi-spaces to single-space (matches DB unique index)
    name := strings.Join(strings.Fields(in.Name), " ")
    if name == "" {
        return nil, errors.New("community name is required")
    }

    t := strings.ToUpper(strings.TrimSpace(in.Type))
    if !allowedCommunityTypes[t] {
        return nil, errors.New("invalid community type")
    }

    c := &models.Community{
        Name:                  name,
        Description:           in.Description,
        Type:                  t,
        IsPrivate:             in.IsPrivate,
        HeadUserID:            creatorUserID,
        AutoApproveMembers:    true,  // defaults; DB trigger may override for private
        AllowMemberPosts:      true,
        AllowMemberInvites:    false,
        RequireApprovalToPost: false,
        LocationData:          in.LocationData,
    }
    if in.AutoApproveMembers != nil {
        c.AutoApproveMembers = *in.AutoApproveMembers
    }
    if in.AllowMemberPosts != nil {
        c.AllowMemberPosts = *in.AllowMemberPosts
    }
    if in.AllowMemberInvites != nil {
        c.AllowMemberInvites = *in.AllowMemberInvites
    }
    if in.RequireApprovalToPost != nil {
        c.RequireApprovalToPost = *in.RequireApprovalToPost
    }

    if err := s.repo.CreateCommunity(ctx, c); err != nil {
        return nil, err
    }
    return c, nil
}

func (s *communityCoreService) UpdateCommunity(ctx context.Context, in UpdateCommunityInput) error {
    if in.ID == uuid.Nil {
        return errors.New("missing community ID")
    }
    c, err := s.repo.GetByID(ctx, in.ID)
    if err != nil {
        return err
    }

    if in.Name != nil {
        // Normalize on update as well (consistent with DB unique index)
        n := strings.Join(strings.Fields(*in.Name), " ")
        if n == "" {
            return errors.New("name cannot be empty")
        }
        c.Name = n
    }
    if in.Description != nil {
        c.Description = in.Description
    }
    if in.Type != nil {
        t := strings.ToUpper(strings.TrimSpace(*in.Type))
        if !allowedCommunityTypes[t] {
            return errors.New("invalid community type")
        }
        c.Type = t
    }
    if in.IsPrivate != nil {
        c.IsPrivate = *in.IsPrivate
        if c.IsPrivate {
            c.AutoApproveMembers = false
        }
    }
    if in.HeadUserID != nil {
        c.HeadUserID = *in.HeadUserID
    }
    if in.VerificationStatus != nil {
        c.VerificationStatus = *in.VerificationStatus
    }
    if in.IsBlocked != nil {
        c.IsBlocked = *in.IsBlocked
    }
    if in.BlockReason != nil {
        c.BlockReason = in.BlockReason
    }
    if in.AutoApproveMembers != nil {
        c.AutoApproveMembers = *in.AutoApproveMembers
    }
    if in.AllowMemberPosts != nil {
        c.AllowMemberPosts = *in.AllowMemberPosts
    }
    if in.AllowMemberInvites != nil {
        c.AllowMemberInvites = *in.AllowMemberInvites
    }
    if in.RequireApprovalToPost != nil {
        c.RequireApprovalToPost = *in.RequireApprovalToPost
    }
    if in.LocationData != nil {
        c.LocationData = *in.LocationData
    }
    return s.repo.UpdateCommunity(ctx, c)
}

func (s *communityCoreService) GetCommunityByID(ctx context.Context, communityID uuid.UUID) (*models.Community, error) {
    return s.repo.GetByID(ctx, communityID)
}

func (s *communityCoreService) ListByType(ctx context.Context, t string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.Community, error) {
    tt := strings.ToUpper(strings.TrimSpace(t))
    if !allowedCommunityTypes[tt] {
        return nil, errors.New("invalid community type")
    }
    return s.repo.ListByType(ctx, tt, afterCreatedAt, afterID, limit)
}

func (s *communityCoreService) ListUserCommunities(ctx context.Context, userID uuid.UUID, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.Community, error) {
    if userID == uuid.Nil {
        return nil, errors.New("missing user ID")
    }
    return s.repo.ListUserCommunities(ctx, userID, afterCreatedAt, afterID, limit)
}
