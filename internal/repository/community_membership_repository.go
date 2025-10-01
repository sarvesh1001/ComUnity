// internal/repository/community_membership_repository.go
package repository

import (
    "context"
    "database/sql"
    "time"
	"encoding/json"

    "github.com/ComUnity/auth-service/internal/models"
    "github.com/google/uuid"
)

type CommunityMembershipRepository interface {
    CreateJoinRequest(ctx context.Context, communityID, userID uuid.UUID, message *string) (uuid.UUID, error)
    ReviewJoinRequest(ctx context.Context, requestID, reviewerUserID uuid.UUID, approve bool, response *string) error
    UpsertMemberRole(ctx context.Context, communityID, userID uuid.UUID, role string, assignedBy uuid.UUID) error
    RemoveMember(ctx context.Context, communityID, userID uuid.UUID, status string, reason *string) error
    ListMembers(ctx context.Context, communityID uuid.UUID, roleFilter *string, statusFilter *string, afterJoinedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.CommunityMember, error)
    CreateInvitation(ctx context.Context, communityID, inviterUserID uuid.UUID, inviteeUserID *uuid.UUID, inviteePhone *string, suggestedRole string, message *string, expiresAt time.Time) (uuid.UUID, error)
    AcceptInvitation(ctx context.Context, invitationID, inviteeUserID uuid.UUID) error
    DeclineInvitation(ctx context.Context, invitationID, inviteeUserID uuid.UUID) error
}

type CockroachCommunityMembershipRepository struct {
    db *sql.DB
}

func NewCockroachCommunityMembershipRepository(db *sql.DB) CommunityMembershipRepository {
    return &CockroachCommunityMembershipRepository{db: db}
}

func (r *CockroachCommunityMembershipRepository) CreateJoinRequest(ctx context.Context, communityID, userID uuid.UUID, message *string) (uuid.UUID, error) {
    const q = `
        INSERT INTO community_join_requests (community_id, user_id, request_message)
        VALUES ($1, $2, $3)
        ON CONFLICT (community_id, user_id) DO UPDATE SET
            request_message = EXCLUDED.request_message,
            status = 'PENDING',
            updated_at = NOW()
        RETURNING id
    `
    var id uuid.UUID
    err := r.db.QueryRowContext(ctx, q, communityID, userID, message).Scan(&id)
    return id, err
}

// Approve: mark request APPROVED and ensure ACTIVE membership row exists; Reject: mark REJECTED with admin_response.
func (r *CockroachCommunityMembershipRepository) ReviewJoinRequest(ctx context.Context, requestID, reviewerUserID uuid.UUID, approve bool, response *string) error {
    tx, err := r.db.BeginTx(ctx, nil)
    if err != nil { return err }
    defer func() { _ = tx.Rollback() }()

    // Load request
    var communityID, userID uuid.UUID
    const sel = `SELECT community_id, user_id FROM community_join_requests WHERE id = $1`
    if err := tx.QueryRowContext(ctx, sel, requestID).Scan(&communityID, &userID); err != nil {
        return err
    }

    if approve {
        const upd = `
            UPDATE community_join_requests
               SET status = 'APPROVED', reviewed_by_user_id = $2, reviewed_at = NOW(), admin_response = $3
             WHERE id = $1
        `
        if _, err := tx.ExecContext(ctx, upd, requestID, reviewerUserID, response); err != nil {
            return err
        }
        const upsertMember = `
            INSERT INTO community_members (community_id, user_id, status, joined_at, approved_at, role_in_community, role_assigned_at, approved_by_user_id)
            VALUES ($1, $2, 'ACTIVE', NOW(), NOW(), 'MEMBER', NOW(), $3)
            ON CONFLICT (community_id, user_id) DO UPDATE SET
                status = 'ACTIVE',
                approved_at = NOW(),
                updated_at = NOW()
        `
        if _, err := tx.ExecContext(ctx, upsertMember, communityID, userID, reviewerUserID); err != nil {
            return err
        }
    } else {
        const upd = `
            UPDATE community_join_requests
               SET status = 'REJECTED', reviewed_by_user_id = $2, reviewed_at = NOW(), admin_response = $3
             WHERE id = $1
        `
        if _, err := tx.ExecContext(ctx, upd, requestID, reviewerUserID, response); err != nil {
            return err
        }
    }

    return tx.Commit()
}

func (r *CockroachCommunityMembershipRepository) UpsertMemberRole(ctx context.Context, communityID, userID uuid.UUID, role string, assignedBy uuid.UUID) error {
    const q = `
        INSERT INTO community_members (community_id, user_id, status, joined_at, approved_at, role_in_community, role_assigned_by, role_assigned_at)
        VALUES ($1, $2, 'ACTIVE', NOW(), NOW(), $3, $4, NOW())
        ON CONFLICT (community_id, user_id) DO UPDATE SET
            role_in_community = EXCLUDED.role_in_community,
            role_assigned_by = EXCLUDED.role_assigned_by,
            role_assigned_at = NOW(),
            updated_at = NOW()
    `
    _, err := r.db.ExecContext(ctx, q, communityID, userID, role, assignedBy)
    return err
}

// status should be one of: SUSPENDED, BANNED, LEFT to remain consistent with model.
func (r *CockroachCommunityMembershipRepository) RemoveMember(ctx context.Context, communityID, userID uuid.UUID, status string, reason *string) error {
    const q = `
        UPDATE community_members
           SET status = $3, updated_at = NOW(), rejection_reason = COALESCE($4, rejection_reason)
         WHERE community_id = $1 AND user_id = $2
    `
    _, err := r.db.ExecContext(ctx, q, communityID, userID, status, reason)
    return err
}

func (r *CockroachCommunityMembershipRepository) ListMembers(ctx context.Context, communityID uuid.UUID, roleFilter *string, statusFilter *string, afterJoinedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.CommunityMember, error) {
    if limit <= 0 || limit > 500 {
        limit = 100
    }
    base := `
        SELECT id, community_id, user_id, status, joined_at, approved_at, approved_by_user_id,
               role_in_community, role_assigned_by, role_assigned_at,
               join_requested_at, join_message, rejection_reason,
               last_activity_at, notification_settings, created_at, updated_at
          FROM community_members
         WHERE community_id = $1
    `
    args := []interface{}{communityID}
    idx := 2
    if roleFilter != nil {
        base += ` AND role_in_community = $` + itoa(idx)
        args = append(args, *roleFilter)
        idx++
    }
    if statusFilter != nil {
        base += ` AND status = $` + itoa(idx)
        args = append(args, *statusFilter)
        idx++
    }
    if afterJoinedAt != nil && afterID != nil {
        base += ` AND (joined_at, id) < ($` + itoa(idx) + `, $` + itoa(idx+1) + `)`
        args = append(args, *afterJoinedAt, *afterID)
        idx += 2
    }
    base += ` ORDER BY joined_at DESC, id DESC LIMIT $` + itoa(idx)
    args = append(args, limit)

    rows, err := r.db.QueryContext(ctx, base, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var out []models.CommunityMember
    for rows.Next() {
        var m models.CommunityMember
        var approvedAt, roleAssignedAt, joinRequestedAt, lastActivityAt sql.NullTime
        var approvedBy, roleAssignedBy sql.NullString
        var joinMsg, rejectReason sql.NullString
        var notifJSON sql.NullString

        if err := rows.Scan(
            &m.ID, &m.CommunityID, &m.UserID, &m.Status, &m.JoinedAt, &approvedAt, &approvedBy,
            &m.RoleInCommunity, &roleAssignedBy, &roleAssignedAt,
            &joinRequestedAt, &joinMsg, &rejectReason,
            &lastActivityAt, &notifJSON, &m.CreatedAt, &m.UpdatedAt,
        ); err != nil {
            return nil, err
        }
        if approvedAt.Valid { t := approvedAt.Time; m.ApprovedAt = &t }
        if approvedBy.Valid {
            if u, e := uuid.Parse(approvedBy.String); e == nil { m.ApprovedByUserID = &u }
        }
        if roleAssignedAt.Valid { t := roleAssignedAt.Time; m.RoleAssignedAt = &t }
        if roleAssignedBy.Valid {
            if u, e := uuid.Parse(roleAssignedBy.String); e == nil { m.RoleAssignedBy = &u }
        }
        if joinRequestedAt.Valid { t := joinRequestedAt.Time; m.JoinRequestedAt = &t }
        if joinMsg.Valid { s := joinMsg.String; m.JoinMessage = &s }
        if rejectReason.Valid { s := rejectReason.String; m.RejectionReason = &s }
        if lastActivityAt.Valid { t := lastActivityAt.Time; m.LastActivityAt = &t }
        if notifJSON.Valid && notifJSON.String != "" {
            var mm models.JSONMap
            _ = json.Unmarshal([]byte(notifJSON.String), &mm)
            m.NotificationConfig = mm
        }
        out = append(out, m)
    }
    return out, nil
}

func (r *CockroachCommunityMembershipRepository) CreateInvitation(ctx context.Context, communityID, inviterUserID uuid.UUID, inviteeUserID *uuid.UUID, inviteePhone *string, suggestedRole string, message *string, expiresAt time.Time) (uuid.UUID, error) {
    const q = `
        INSERT INTO community_invitations (community_id, inviter_user_id, invitee_user_id, invitee_phone_number, suggested_role, message, expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        RETURNING id
    `
    var id uuid.UUID
    err := r.db.QueryRowContext(ctx, q, communityID, inviterUserID, inviteeUserID, inviteePhone, suggestedRole, message, expiresAt).Scan(&id)
    return id, err
}

func (r *CockroachCommunityMembershipRepository) AcceptInvitation(ctx context.Context, invitationID, inviteeUserID uuid.UUID) error {
    tx, err := r.db.BeginTx(ctx, nil)
    if err != nil { return err }
    defer func() { _ = tx.Rollback() }()

    var communityID uuid.UUID
    const sel = `
        SELECT community_id FROM community_invitations
         WHERE id = $1 AND (invitee_user_id = $2 OR invitee_user_id IS NULL) AND status = 'PENDING'
           AND (expires_at IS NULL OR expires_at > NOW())
    `
    if err := tx.QueryRowContext(ctx, sel, invitationID, inviteeUserID).Scan(&communityID); err != nil {
        return err
    }

    const upd = `UPDATE community_invitations SET status = 'ACCEPTED', responded_at = NOW() WHERE id = $1`
    if _, err := tx.ExecContext(ctx, upd, invitationID); err != nil {
        return err
    }

    const upsertMember = `
        INSERT INTO community_members (community_id, user_id, status, joined_at, approved_at, role_in_community, role_assigned_at)
        SELECT community_id, $2, 'ACTIVE', NOW(), NOW(), suggested_role, NOW()
          FROM community_invitations WHERE id = $1
        ON CONFLICT (community_id, user_id) DO UPDATE SET
            status = 'ACTIVE',
            updated_at = NOW()
    `
    if _, err := tx.ExecContext(ctx, upsertMember, invitationID, inviteeUserID); err != nil {
        return err
    }

    return tx.Commit()
}

func (r *CockroachCommunityMembershipRepository) DeclineInvitation(ctx context.Context, invitationID, inviteeUserID uuid.UUID) error {
    const q = `
        UPDATE community_invitations
           SET status = 'DECLINED', responded_at = NOW()
         WHERE id = $1 AND (invitee_user_id = $2 OR invitee_user_id IS NULL) AND status = 'PENDING'
    `
    _, err := r.db.ExecContext(ctx, q, invitationID, inviteeUserID)
    return err
}
