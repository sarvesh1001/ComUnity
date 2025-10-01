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

type CommunityAdminService interface {
    SubmitVerification(ctx context.Context, req models.CommunityVerificationRequest) (uuid.UUID, error)
    DecideVerification(ctx context.Context, requestID, adminUserID uuid.UUID, approve bool, notes *string, rejectionReason *string, additionalInfo *string) error
    ListPendingVerifications(ctx context.Context, reqType *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.CommunityVerificationRequest, error)

    BlockCommunity(ctx context.Context, communityID, adminUserID uuid.UUID, reason string, severity string, durationDays *int) (uuid.UUID, error)
    UnblockCommunity(ctx context.Context, communityID, adminUserID uuid.UUID, reason string) (uuid.UUID, error)

    LogAdminAction(ctx context.Context, a models.CommunityAdminAction) (uuid.UUID, error)
    ListAdminActions(ctx context.Context, communityID *uuid.UUID, adminUserID *uuid.UUID, actionType *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.CommunityAdminAction, error)

    CreateSystemReport(ctx context.Context, r models.SystemReport) (uuid.UUID, error)
    UpdateSystemReport(ctx context.Context, reportID uuid.UUID, updates map[string]interface{}) error
    ListSystemReports(ctx context.Context, reportType *string, status *string, severity *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.SystemReport, error)
}

type communityAdminService struct {
    repo repository.CommunityAdminRepository
}

func NewCommunityAdminService(repo repository.CommunityAdminRepository) CommunityAdminService {
    return &communityAdminService{repo: repo}
}

func (s *communityAdminService) SubmitVerification(ctx context.Context, req models.CommunityVerificationRequest) (uuid.UUID, error) {
    if req.CommunityID == uuid.Nil || req.RequestedByUserID == uuid.Nil {
        return uuid.Nil, errors.New("missing identifiers")
    }
    rt := strings.ToUpper(strings.TrimSpace(req.RequestType))
    if rt != "GOVERNMENT" && rt != "NGO" {
        return uuid.Nil, errors.New("request_type must be GOVERNMENT or NGO")
    }
    if strings.TrimSpace(req.OrganizationName) == "" {
        return uuid.Nil, errors.New("organization_name required")
    }
    // optional: basic phone/email/addr validation could be added here
    req.RequestType = rt
    return s.repo.CreateVerificationRequest(ctx, &req)
}

func (s *communityAdminService) DecideVerification(ctx context.Context, requestID, adminUserID uuid.UUID, approve bool, notes *string, rejectionReason *string, additionalInfo *string) error {
    if requestID == uuid.Nil || adminUserID == uuid.Nil {
        return errors.New("missing identifiers")
    }
    return s.repo.ReviewVerificationRequest(ctx, requestID, adminUserID, approve, notes, rejectionReason, additionalInfo)
}

func (s *communityAdminService) ListPendingVerifications(ctx context.Context, reqType *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.CommunityVerificationRequest, error) {
    if reqType != nil {
        rt := strings.ToUpper(strings.TrimSpace(*reqType))
        if rt != "GOVERNMENT" && rt != "NGO" {
            return nil, errors.New("invalid request_type filter")
        }
        reqType = &rt
    }
    if limit <= 0 || limit > 200 { limit = 50 }
    return s.repo.ListPendingVerifications(ctx, reqType, afterCreatedAt, afterID, limit)
}

func (s *communityAdminService) BlockCommunity(ctx context.Context, communityID, adminUserID uuid.UUID, reason string, severity string, durationDays *int) (uuid.UUID, error) {
    if communityID == uuid.Nil || adminUserID == uuid.Nil {
        return uuid.Nil, errors.New("missing identifiers")
    }
    sev := strings.ToUpper(strings.TrimSpace(severity))
    if sev == "" { sev = "MEDIUM" }
    switch sev {
    case "LOW", "MEDIUM", "HIGH", "CRITICAL":
    default:
        return uuid.Nil, errors.New("invalid severity")
    }
    reason = strings.TrimSpace(reason)
    if reason == "" {
        return uuid.Nil, errors.New("reason required")
    }
    return s.repo.BlockCommunity(ctx, communityID, adminUserID, reason, sev, durationDays)
}

func (s *communityAdminService) UnblockCommunity(ctx context.Context, communityID, adminUserID uuid.UUID, reason string) (uuid.UUID, error) {
    if communityID == uuid.Nil || adminUserID == uuid.Nil {
        return uuid.Nil, errors.New("missing identifiers")
    }
    reason = strings.TrimSpace(reason)
    if reason == "" {
        reason = "Unblocked by admin"
    }
    return s.repo.UnblockCommunity(ctx, communityID, adminUserID, reason)
}

func (s *communityAdminService) LogAdminAction(ctx context.Context, a models.CommunityAdminAction) (uuid.UUID, error) {
    if a.CommunityID == uuid.Nil || a.AdminUserID == uuid.Nil {
        return uuid.Nil, errors.New("missing identifiers")
    }
    at := strings.ToUpper(strings.TrimSpace(a.ActionType))
    if at == "" {
        return uuid.Nil, errors.New("action_type required")
    }
    a.ActionType = at
    return s.repo.LogAdminAction(ctx, &a)
}

func (s *communityAdminService) ListAdminActions(ctx context.Context, communityID *uuid.UUID, adminUserID *uuid.UUID, actionType *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.CommunityAdminAction, error) {
    if actionType != nil {
        at := strings.ToUpper(strings.TrimSpace(*actionType))
        actionType = &at
    }
    if limit <= 0 || limit > 200 { limit = 50 }
    return s.repo.ListAdminActions(ctx, communityID, adminUserID, actionType, afterCreatedAt, afterID, limit)
}

func (s *communityAdminService) CreateSystemReport(ctx context.Context, r models.SystemReport) (uuid.UUID, error) {
    if strings.TrimSpace(r.ReportType) == "" || strings.TrimSpace(r.Title) == "" || strings.TrimSpace(r.Description) == "" {
        return uuid.Nil, errors.New("report_type, title, description are required")
    }
    rt := strings.ToUpper(strings.TrimSpace(r.ReportType))
    switch rt {
    case "COMMUNITY_ABUSE", "USER_ABUSE", "CONTENT_VIOLATION", "SECURITY_INCIDENT", "SYSTEM_ISSUE":
    default:
        return uuid.Nil, errors.New("invalid report_type")
    }
    if r.Severity == "" { r.Severity = "MEDIUM" }
    sv := strings.ToUpper(strings.TrimSpace(r.Severity))
    switch sv {
    case "LOW", "MEDIUM", "HIGH", "CRITICAL":
    default:
        return uuid.Nil, errors.New("invalid severity")
    }
    if r.Status == "" { r.Status = "OPEN" }
    st := strings.ToUpper(strings.TrimSpace(r.Status))
    switch st {
    case "OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED", "DISMISSED":
    default:
        return uuid.Nil, errors.New("invalid status")
    }
    r.ReportType = rt
    r.Severity = sv
    r.Status = st
    return s.repo.CreateSystemReport(ctx, &r)
}

func (s *communityAdminService) UpdateSystemReport(ctx context.Context, reportID uuid.UUID, updates map[string]interface{}) error {
    if reportID == uuid.Nil {
        return errors.New("missing report ID")
    }
    if updates == nil || len(updates) == 0 {
        return nil
    }
    // Normalize enums if present
    if v, ok := updates["report_type"]; ok {
        if sv, ok2 := v.(string); ok2 {
            sv = strings.ToUpper(strings.TrimSpace(sv))
            updates["report_type"] = sv
        }
    }
    if v, ok := updates["severity"]; ok {
        if sv, ok2 := v.(string); ok2 {
            sv = strings.ToUpper(strings.TrimSpace(sv))
            updates["severity"] = sv
        }
    }
    if v, ok := updates["status"]; ok {
        if sv, ok2 := v.(string); ok2 {
            sv = strings.ToUpper(strings.TrimSpace(sv))
            updates["status"] = sv
        }
    }
    // If evidence/tags provided as maps/slices, repository will marshal to JSON
    // Ensure time types are valid if providing resolved_at
    if v, ok := updates["resolved_at"]; ok {
        switch v.(type) {
        case time.Time, *time.Time, nil:
        default:
            // attempt RFC3339 parse if string
            if s, ok2 := v.(string); ok2 {
                if t, err := time.Parse(time.RFC3339, s); err == nil {
                    updates["resolved_at"] = t
                }
            }
        }
    }
    return s.repo.UpdateSystemReport(ctx, reportID, updates)
}

func (s *communityAdminService) ListSystemReports(ctx context.Context, reportType *string, status *string, severity *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.SystemReport, error) {
    norm := func(p *string) *string {
        if p == nil { return nil }
        v := strings.ToUpper(strings.TrimSpace(*p))
        return &v
    }
    return s.repo.ListSystemReports(ctx, norm(reportType), norm(status), norm(severity), afterCreatedAt, afterID, limit)
}
