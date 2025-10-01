package service

import (
    "context"
    "errors"
    "time"

    "github.com/ComUnity/auth-service/internal/models"
    "github.com/ComUnity/auth-service/internal/repository"
    "github.com/google/uuid"
)

type CommunityMembershipService interface {
    RequestJoin(ctx context.Context, communityID, userID uuid.UUID, message *string) (uuid.UUID, error)
    ReviewJoin(ctx context.Context, requestID, reviewerUserID uuid.UUID, approve bool, response *string) error

    ChangeMemberRole(ctx context.Context, communityID, userID uuid.UUID, newRole string, assignedBy uuid.UUID) error
    RemoveMember(ctx context.Context, communityID, userID uuid.UUID, status string, reason *string) error

    ListMembers(ctx context.Context, communityID uuid.UUID, roleFilter *string, statusFilter *string, afterJoinedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.CommunityMember, error)

    Invite(ctx context.Context, communityID, inviterUserID uuid.UUID, inviteeUserID *uuid.UUID, inviteePhone *string, suggestedRole string, message *string, expiresAt time.Time) (uuid.UUID, error)
    AcceptInvitation(ctx context.Context, invitationID, inviteeUserID uuid.UUID) error
    DeclineInvitation(ctx context.Context, invitationID, inviteeUserID uuid.UUID) error
}

type communityMembershipService struct {
    repo repository.CommunityMembershipRepository
}

func NewCommunityMembershipService(repo repository.CommunityMembershipRepository) CommunityMembershipService {
    return &communityMembershipService{repo: repo}
}

func (s *communityMembershipService) RequestJoin(ctx context.Context, communityID, userID uuid.UUID, message *string) (uuid.UUID, error) {
    if communityID == uuid.Nil || userID == uuid.Nil {
        return uuid.Nil, errors.New("missing identifiers")
    }
    return s.repo.CreateJoinRequest(ctx, communityID, userID, message)
}

func (s *communityMembershipService) ReviewJoin(ctx context.Context, requestID, reviewerUserID uuid.UUID, approve bool, response *string) error {
    if requestID == uuid.Nil || reviewerUserID == uuid.Nil {
        return errors.New("missing identifiers")
    }
    return s.repo.ReviewJoinRequest(ctx, requestID, reviewerUserID, approve, response)
}

func (s *communityMembershipService) ChangeMemberRole(ctx context.Context, communityID, userID uuid.UUID, newRole string, assignedBy uuid.UUID) error {
    if communityID == uuid.Nil || userID == uuid.Nil || assignedBy == uuid.Nil {
        return errors.New("missing identifiers")
    }
    switch newRole {
    case "OWNER", "ADMIN", "MODERATOR", "MEMBER":
    default:
        return errors.New("invalid role")
    }
    return s.repo.UpsertMemberRole(ctx, communityID, userID, newRole, assignedBy)
}

func (s *communityMembershipService) RemoveMember(ctx context.Context, communityID, userID uuid.UUID, status string, reason *string) error {
    if communityID == uuid.Nil || userID == uuid.Nil {
        return errors.New("missing identifiers")
    }
    switch status {
    case "SUSPENDED", "BANNED", "LEFT":
    default:
        return errors.New("invalid removal status")
    }
    return s.repo.RemoveMember(ctx, communityID, userID, status, reason)
}

func (s *communityMembershipService) ListMembers(ctx context.Context, communityID uuid.UUID, roleFilter *string, statusFilter *string, afterJoinedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.CommunityMember, error) {
    if communityID == uuid.Nil { return nil, errors.New("missing community ID") }
    if roleFilter != nil {
        rf := *roleFilter
        if rf != "OWNER" && rf != "ADMIN" && rf != "MODERATOR" && rf != "MEMBER" {
            return nil, errors.New("invalid role filter")
        }
    }
    if statusFilter != nil {
        sf := *statusFilter
        switch sf {
        case "PENDING", "ACTIVE", "SUSPENDED", "BANNED", "LEFT":
        default:
            return nil, errors.New("invalid status filter")
        }
    }
    return s.repo.ListMembers(ctx, communityID, roleFilter, statusFilter, afterJoinedAt, afterID, limit)
}

func (s *communityMembershipService) Invite(ctx context.Context, communityID, inviterUserID uuid.UUID, inviteeUserID *uuid.UUID, inviteePhone *string, suggestedRole string, message *string, expiresAt time.Time) (uuid.UUID, error) {
    if communityID == uuid.Nil || inviterUserID == uuid.Nil {
        return uuid.Nil, errors.New("missing identifiers")
    }
    switch suggestedRole {
    case "ADMIN", "MODERATOR", "MEMBER":
    default:
        return uuid.Nil, errors.New("invalid suggested role")
    }
    if inviteeUserID == nil && (inviteePhone == nil || *inviteePhone == "") {
        return uuid.Nil, errors.New("invitee user or phone is required")
    }
    return s.repo.CreateInvitation(ctx, communityID, inviterUserID, inviteeUserID, inviteePhone, suggestedRole, message, expiresAt)
}

func (s *communityMembershipService) AcceptInvitation(ctx context.Context, invitationID, inviteeUserID uuid.UUID) error {
    if invitationID == uuid.Nil || inviteeUserID == uuid.Nil {
        return errors.New("missing identifiers")
    }
    return s.repo.AcceptInvitation(ctx, invitationID, inviteeUserID)
}

func (s *communityMembershipService) DeclineInvitation(ctx context.Context, invitationID, inviteeUserID uuid.UUID) error {
    if invitationID == uuid.Nil || inviteeUserID == uuid.Nil {
        return errors.New("missing identifiers")
    }
    return s.repo.DeclineInvitation(ctx, invitationID, inviteeUserID)
}
