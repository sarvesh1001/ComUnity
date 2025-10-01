package repository

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "strings"
    "time"

    "github.com/ComUnity/auth-service/internal/models"
    "github.com/google/uuid"
)

type CommunityAdminRepository interface {
    CreateVerificationRequest(ctx context.Context, r *models.CommunityVerificationRequest) (uuid.UUID, error)
    ReviewVerificationRequest(ctx context.Context, requestID, adminUserID uuid.UUID, approve bool, notes *string, rejectionReason *string, additionalInfo *string) error

    BlockCommunity(ctx context.Context, communityID, adminUserID uuid.UUID, reason string, severity string, durationDays *int) (uuid.UUID, error)
    UnblockCommunity(ctx context.Context, communityID, adminUserID uuid.UUID, reason string) (uuid.UUID, error)

    ListPendingVerifications(ctx context.Context, reqType *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.CommunityVerificationRequest, error)

    LogAdminAction(ctx context.Context, a *models.CommunityAdminAction) (uuid.UUID, error)
    ListAdminActions(ctx context.Context, communityID *uuid.UUID, adminUserID *uuid.UUID, actionType *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.CommunityAdminAction, error)

    CreateSystemReport(ctx context.Context, r *models.SystemReport) (uuid.UUID, error)
    UpdateSystemReport(ctx context.Context, reportID uuid.UUID, updates map[string]interface{}) error
    ListSystemReports(ctx context.Context, reportType *string, status *string, severity *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.SystemReport, error)
}

type CockroachCommunityAdminRepository struct {
    db *sql.DB
}

func NewCockroachCommunityAdminRepository(db *sql.DB) CommunityAdminRepository {
    return &CockroachCommunityAdminRepository{db: db}
}

func (r *CockroachCommunityAdminRepository) CreateVerificationRequest(ctx context.Context, req *models.CommunityVerificationRequest) (uuid.UUID, error) {
    const q = `
        INSERT INTO community_verification_requests (
            community_id, requested_by_user_id, request_type, organization_name, registration_number,
            contact_person_name, contact_person_designation, contact_phone, contact_email,
            address_line1, address_line2, city, state, pincode,
            documents, supporting_info
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
        RETURNING id, created_at, updated_at
    `
    var docs, sup string
    if req.Documents != nil {
        b, _ := json.Marshal(req.Documents)
        docs = string(b)
    } else { docs = "[]" }
    if req.SupportingInfo != nil {
        b, _ := json.Marshal(req.SupportingInfo)
        sup = string(b)
    } else { sup = "{}" }

    var id uuid.UUID
    err := r.db.QueryRowContext(ctx, q,
        req.CommunityID, req.RequestedByUserID, req.RequestType, req.OrganizationName, req.RegistrationNumber,
        req.ContactPersonName, req.ContactPersonDesignation, req.ContactPhone, req.ContactEmail,
        req.AddressLine1, req.AddressLine2, req.City, req.State, req.Pincode,
        docs, sup,
    ).Scan(&id, &req.CreatedAt, &req.UpdatedAt)
    return id, err
}

func (r *CockroachCommunityAdminRepository) ReviewVerificationRequest(ctx context.Context, requestID, adminUserID uuid.UUID, approve bool, notes *string, rejectionReason *string, additionalInfo *string) error {
    status := "REJECTED"
    if approve { status = "APPROVED" }
    const q = `
        UPDATE community_verification_requests
           SET status = $2,
               reviewed_by_admin_id = $3,
               reviewed_at = NOW(),
               admin_notes = $4,
               rejection_reason = $5,
               additional_info_requested = $6,
               updated_at = NOW()
         WHERE id = $1
    `
    _, err := r.db.ExecContext(ctx, q, requestID, status, adminUserID, notes, rejectionReason, additionalInfo)
    return err
}

func (r *CockroachCommunityAdminRepository) BlockCommunity(ctx context.Context, communityID, adminUserID uuid.UUID, reason string, severity string, durationDays *int) (uuid.UUID, error) {
    const q = `
        INSERT INTO community_admin_actions (community_id, admin_user_id, action_type, reason, severity, duration_days)
        VALUES ($1,$2,'BLOCK',$3,$4,$5)
        RETURNING id, created_at, updated_at
    `
    var id uuid.UUID
    var dd interface{}
    if durationDays != nil { dd = *durationDays }
    err := r.db.QueryRowContext(ctx, q, communityID, adminUserID, reason, severity, dd).Scan(&id, new(time.Time), new(time.Time))
    return id, err
}

func (r *CockroachCommunityAdminRepository) UnblockCommunity(ctx context.Context, communityID, adminUserID uuid.UUID, reason string) (uuid.UUID, error) {
    const q = `
        INSERT INTO community_admin_actions (community_id, admin_user_id, action_type, reason, severity)
        VALUES ($1,$2,'UNBLOCK',$3,'LOW')
        RETURNING id, created_at, updated_at
    `
    var id uuid.UUID
    err := r.db.QueryRowContext(ctx, q, communityID, adminUserID, reason).Scan(&id, new(time.Time), new(time.Time))
    return id, err
}

func (r *CockroachCommunityAdminRepository) ListPendingVerifications(ctx context.Context, reqType *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.CommunityVerificationRequest, error) {
    if limit <= 0 || limit > 200 { limit = 50 }
    base := `
        SELECT id, community_id, requested_by_user_id, request_type, organization_name, registration_number,
               contact_person_name, contact_person_designation, contact_phone, contact_email,
               address_line1, address_line2, city, state, pincode,
               documents, supporting_info, status, reviewed_by_admin_id, reviewed_at, admin_notes,
               rejection_reason, additional_info_requested, is_resubmission, original_request_id, resubmission_count,
               created_at, updated_at
          FROM community_verification_requests
         WHERE status IN ('PENDING','UNDER_REVIEW')
    `
    args := []interface{}{}
    idx := 1
    if reqType != nil {
        base += fmt.Sprintf(" AND request_type = $%d", idx)
        args = append(args, *reqType)
        idx++
    }
    if afterCreatedAt != nil && afterID != nil {
        base += fmt.Sprintf(" AND (created_at, id) < ($%d, $%d)", idx, idx+1)
        args = append(args, *afterCreatedAt, *afterID)
        idx += 2
    }
    base += fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d", idx)
    args = append(args, limit)

    rows, err := r.db.QueryContext(ctx, base, args...)
    if err != nil { return nil, err }
    defer rows.Close()

    var out []models.CommunityVerificationRequest
    for rows.Next() {
        var v models.CommunityVerificationRequest
        var regNum, cpd, email, addr2, docs, sup, notes, rej, addInfo sql.NullString
        var revBy, orig sql.NullString
        var revAt sql.NullTime
        if err := rows.Scan(
            &v.ID, &v.CommunityID, &v.RequestedByUserID, &v.RequestType, &v.OrganizationName, &regNum,
            &v.ContactPersonName, &cpd, &v.ContactPhone, &email,
            &v.AddressLine1, &addr2, &v.City, &v.State, &v.Pincode,
            &docs, &sup, &v.Status, &revBy, &revAt, &notes,
            &rej, &addInfo, &v.IsResubmission, &orig, &v.ResubmissionCount,
            &v.CreatedAt, &v.UpdatedAt,
        ); err != nil {
            return nil, err
        }
        if regNum.Valid { s := regNum.String; v.RegistrationNumber = &s }
        if cpd.Valid { s := cpd.String; v.ContactPersonDesignation = &s }
        if email.Valid { s := email.String; v.ContactEmail = &s }
        if addr2.Valid { s := addr2.String; v.AddressLine2 = &s }
        if docs.Valid && docs.String != "" { var m models.JSONMap; _ = json.Unmarshal([]byte(docs.String), &m); v.Documents = m }
        if sup.Valid && sup.String != "" { var m models.JSONMap; _ = json.Unmarshal([]byte(sup.String), &m); v.SupportingInfo = m }
        if notes.Valid { s := notes.String; v.AdminNotes = &s }
        if rej.Valid { s := rej.String; v.RejectionReason = &s }
        if addInfo.Valid { s := addInfo.String; v.AdditionalInfoRequested = &s }
        if revBy.Valid { if u, e := uuid.Parse(revBy.String); e == nil { v.ReviewedByAdminID = &u } }
        if revAt.Valid { t := revAt.Time; v.ReviewedAt = &t }
        if orig.Valid { if u, e := uuid.Parse(orig.String); e == nil { v.OriginalRequestID = &u } }
        out = append(out, v)
    }
    return out, nil
}

func (r *CockroachCommunityAdminRepository) LogAdminAction(ctx context.Context, a *models.CommunityAdminAction) (uuid.UUID, error) {
    const q = `
        INSERT INTO community_admin_actions (
            community_id, admin_user_id, action_type, reason, severity, duration_days,
            evidence_attachments, internal_notes, public_reason, affected_members_count, notification_sent,
            is_reversed, reversed_by_admin_id, reversed_at, reversal_reason
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
        RETURNING id, created_at, updated_at
    `
    var ev string
    if a.EvidenceAttachments != nil {
        b, _ := json.Marshal(a.EvidenceAttachments)
        ev = string(b)
    } else { ev = "[]" }

    var id uuid.UUID
    var createdAt, updatedAt time.Time
    err := r.db.QueryRowContext(ctx, q,
        a.CommunityID, a.AdminUserID, a.ActionType, a.Reason, a.Severity, a.DurationDays,
        ev, a.InternalNotes, a.PublicReason, a.AffectedMembersCount, a.NotificationSent,
        a.IsReversed, a.ReversedByAdminID, a.ReversedAt, a.ReversalReason,
    ).Scan(&id, &createdAt, &updatedAt)
    return id, err
}

func (r *CockroachCommunityAdminRepository) ListAdminActions(ctx context.Context, communityID *uuid.UUID, adminUserID *uuid.UUID, actionType *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.CommunityAdminAction, error) {
    if limit <= 0 || limit > 200 { limit = 50 }
    base := `
        SELECT id, community_id, admin_user_id, action_type, reason, severity, duration_days,
               expires_at, evidence_attachments, internal_notes, public_reason, affected_members_count,
               notification_sent, is_reversed, reversed_by_admin_id, reversed_at, reversal_reason,
               created_at, updated_at
          FROM community_admin_actions
         WHERE 1=1
    `
    args := []interface{}{}
    idx := 1
    if communityID != nil {
        base += fmt.Sprintf(" AND community_id = $%d", idx)
        args = append(args, *communityID); idx++
    }
    if adminUserID != nil {
        base += fmt.Sprintf(" AND admin_user_id = $%d", idx)
        args = append(args, *adminUserID); idx++
    }
    if actionType != nil {
        base += fmt.Sprintf(" AND action_type = $%d", idx)
        args = append(args, *actionType); idx++
    }
    if afterCreatedAt != nil && afterID != nil {
        base += fmt.Sprintf(" AND (created_at, id) < ($%d, $%d)", idx, idx+1)
        args = append(args, *afterCreatedAt, *afterID); idx += 2
    }
    base += fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d", idx)
    args = append(args, limit)

    rows, err := r.db.QueryContext(ctx, base, args...)
    if err != nil { return nil, err }
    defer rows.Close()

    var out []models.CommunityAdminAction
    for rows.Next() {
        var a models.CommunityAdminAction
        var ev, inote, preason, revBy sql.NullString
        var expires, revAt sql.NullTime
        if err := rows.Scan(
            &a.ID, &a.CommunityID, &a.AdminUserID, &a.ActionType, &a.Reason, &a.Severity, &a.DurationDays,
            &expires, &ev, &inote, &preason, &a.AffectedMembersCount,
            &a.NotificationSent, &a.IsReversed, &revBy, &revAt, &a.ReversalReason,
            &a.CreatedAt, &a.UpdatedAt,
        ); err != nil {
            return nil, err
        }
        if expires.Valid { t := expires.Time; a.ExpiresAt = &t }
        if ev.Valid && ev.String != "" { var m models.JSONMap; _ = json.Unmarshal([]byte(ev.String), &m); a.EvidenceAttachments = m }
        if inote.Valid { s := inote.String; a.InternalNotes = &s }
        if preason.Valid { s := preason.String; a.PublicReason = &s }
        if revBy.Valid { if u, e := uuid.Parse(revBy.String); e == nil { a.ReversedByAdminID = &u } }
        if revAt.Valid { t := revAt.Time; a.ReversedAt = &t }
        out = append(out, a)
    }
    return out, nil
}

func (r *CockroachCommunityAdminRepository) CreateSystemReport(ctx context.Context, rep *models.SystemReport) (uuid.UUID, error) {
    const q = `
        INSERT INTO system_reports (
            report_type, title, description, severity, status,
            reported_community_id, reported_user_id, reporter_user_id,
            evidence, tags, assigned_admin_id
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        RETURNING id, created_at, updated_at
    `
    var ev, tags string
    if rep.Evidence != nil { b, _ := json.Marshal(rep.Evidence); ev = string(b) } else { ev = "[]" }
    if rep.Tags != nil { b, _ := json.Marshal(rep.Tags); tags = string(b) } else { tags = "[]" }

    var id uuid.UUID
    err := r.db.QueryRowContext(ctx, q,
        rep.ReportType, rep.Title, rep.Description, rep.Severity, rep.Status,
        rep.ReportedCommunityID, rep.ReportedUserID, rep.ReporterUserID,
        ev, tags, rep.AssignedAdminID,
    ).Scan(&id, &rep.CreatedAt, &rep.UpdatedAt)
    return id, err
}

func (r *CockroachCommunityAdminRepository) UpdateSystemReport(ctx context.Context, reportID uuid.UUID, updates map[string]interface{}) error {
    if len(updates) == 0 {
        return nil
    }
    // Whitelist fields
    allowed := map[string]bool{
        "report_type": true, "title": true, "description": true, "severity": true, "status": true,
        "reported_community_id": true, "reported_user_id": true, "reporter_user_id": true,
        "evidence": true, "tags": true, "assigned_admin_id": true,
        "resolved_by_admin_id": true, "resolved_at": true, "resolution_notes": true, "action_taken": true,
    }
    sets := []string{}
    args := []interface{}{}
    i := 1
    for k, v := range updates {
        if !allowed[k] { continue }
        // Marshal JSON fields
        if k == "evidence" || k == "tags" {
            if v != nil {
                if b, err := json.Marshal(v); err == nil {
                    v = string(b)
                }
            }
        }
        sets = append(sets, fmt.Sprintf("%s = $%d", k, i))
        args = append(args, v)
        i++
    }
    if len(sets) == 0 {
        return nil
    }
    sets = append(sets, fmt.Sprintf("updated_at = NOW()"))
    query := "UPDATE system_reports SET " + strings.Join(sets, ", ") + fmt.Sprintf(" WHERE id = $%d", i)
    args = append(args, reportID)
    _, err := r.db.ExecContext(ctx, query, args...)
    return err
}

func (r *CockroachCommunityAdminRepository) ListSystemReports(ctx context.Context, reportType *string, status *string, severity *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.SystemReport, error) {
    if limit <= 0 || limit > 200 { limit = 50 }
    base := `
        SELECT id, report_type, title, description, severity, status,
               reported_community_id, reported_user_id, reporter_user_id,
               evidence, tags, assigned_admin_id, resolved_by_admin_id, resolved_at, resolution_notes, action_taken,
               created_at, updated_at
          FROM system_reports
         WHERE 1=1
    `
    args := []interface{}{}
    idx := 1
    if reportType != nil {
        base += fmt.Sprintf(" AND report_type = $%d", idx)
        args = append(args, *reportType); idx++
    }
    if status != nil {
        base += fmt.Sprintf(" AND status = $%d", idx)
        args = append(args, *status); idx++
    }
    if severity != nil {
        base += fmt.Sprintf(" AND severity = $%d", idx)
        args = append(args, *severity); idx++
    }
    if afterCreatedAt != nil && afterID != nil {
        base += fmt.Sprintf(" AND (created_at, id) < ($%d, $%d)", idx, idx+1)
        args = append(args, *afterCreatedAt, *afterID); idx += 2
    }
    base += fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d", idx)
    args = append(args, limit)

    rows, err := r.db.QueryContext(ctx, base, args...)
    if err != nil { return nil, err }
    defer rows.Close()

    var out []models.SystemReport
    for rows.Next() {
        var s models.SystemReport
        var ev, tags, resNotes, action sql.NullString
        var repComm, repUser, reporter, assigned, resolvedBy sql.NullString
        var resolvedAt sql.NullTime
        if err := rows.Scan(
            &s.ID, &s.ReportType, &s.Title, &s.Description, &s.Severity, &s.Status,
            &repComm, &repUser, &reporter,
            &ev, &tags, &assigned, &resolvedBy, &resolvedAt, &resNotes, &action,
            &s.CreatedAt, &s.UpdatedAt,
        ); err != nil {
            return nil, err
        }
        if repComm.Valid { if u, e := uuid.Parse(repComm.String); e == nil { s.ReportedCommunityID = &u } }
        if repUser.Valid { if u, e := uuid.Parse(repUser.String); e == nil { s.ReportedUserID = &u } }
        if reporter.Valid { if u, e := uuid.Parse(reporter.String); e == nil { s.ReporterUserID = &u } }
        if ev.Valid && ev.String != "" { var m models.JSONMap; _ = json.Unmarshal([]byte(ev.String), &m); s.Evidence = m }
        if tags.Valid && tags.String != "" { var m models.JSONMap; _ = json.Unmarshal([]byte(tags.String), &m); s.Tags = m }
        if assigned.Valid { if u, e := uuid.Parse(assigned.String); e == nil { s.AssignedAdminID = &u } }
        if resolvedBy.Valid { if u, e := uuid.Parse(resolvedBy.String); e == nil { s.ResolvedByAdminID = &u } }
        if resolvedAt.Valid { t := resolvedAt.Time; s.ResolvedAt = &t }
        if resNotes.Valid { s2 := resNotes.String; s.ResolutionNotes = &s2 }
        if action.Valid { s2 := action.String; s.ActionTaken = &s2 }
        out = append(out, s)
    }
    return out, nil
}
