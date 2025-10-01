// internal/repository/community_core_repository.go
package repository

import (
    "context"
    "database/sql"
    "encoding/json"
    "errors"
    "time"
    "github.com/lib/pq" // add

    "github.com/ComUnity/auth-service/internal/models"
    "github.com/google/uuid"
)

type CommunityCoreRepository interface {
    GetByID(ctx context.Context, communityID uuid.UUID) (*models.Community, error)
    CreateCommunity(ctx context.Context, c *models.Community) error
    UpdateCommunity(ctx context.Context, c *models.Community) error
    ListByType(ctx context.Context, communityType string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.Community, error)
    ListUserCommunities(ctx context.Context, userID uuid.UUID, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.Community, error)
}

// CockroachCommunityRepository satisfies the existing CommunityRepository interface and the new CommunityCoreRepository.
type CockroachCommunityRepository struct {
    db *sql.DB
}

func NewCockroachCommunityRepository(db *sql.DB) CommunityRepository {
    return &CockroachCommunityRepository{db: db}
}

// Optional: if other services want the extended methods explicitly.
func NewCockroachCommunityCoreRepository(db *sql.DB) CommunityCoreRepository {
    return &CockroachCommunityRepository{db: db}
}

// Existing interface method (compat). Wraps ListByType with default limit and no cursor.
func (r *CockroachCommunityRepository) GetCommunitiesByType(ctx context.Context, t string) ([]models.Community, error) {
    out, err := r.ListByType(ctx, t, nil, nil, 100)
    if err != nil {
        return nil, err
    }
    return out, nil
}

// Existing interface method (compat). Wraps ListUserCommunities with default limit and no cursor.
func (r *CockroachCommunityRepository) GetUserCommunities(ctx context.Context, userID uuid.UUID) ([]models.Community, error) {
    out, err := r.ListUserCommunities(ctx, userID, nil, nil, 100)
    if err != nil {
        return nil, err
    }
    return out, nil
}

func (r *CockroachCommunityRepository) GetByID(ctx context.Context, communityID uuid.UUID) (*models.Community, error) {
    const q = `
        SELECT
            id, name, description, type, is_private, head_user_id,
            verification_status, verification_requested_at, verified_at, verified_by_admin_id,
            is_blocked, blocked_at, blocked_by_admin_id, block_reason,
            member_limit, auto_approve_members, allow_member_posts, allow_member_invites, require_approval_to_post,
            location_data, created_at, updated_at
        FROM communities
        WHERE id = $1
    `
    var c models.Community
    var desc sql.NullString
    var vReqAt, vAt, blkAt sql.NullTime
    var vBy, blkBy sql.NullString
    var blkReason sql.NullString
    var memberLimit sql.NullInt64
    var locJSON sql.NullString

    err := r.db.QueryRowContext(ctx, q, communityID).Scan(
        &c.ID, &c.Name, &desc, &c.Type, &c.IsPrivate, &c.HeadUserID,
        &c.VerificationStatus, &vReqAt, &vAt, &vBy,
        &c.IsBlocked, &blkAt, &blkBy, &blkReason,
        &memberLimit, &c.AutoApproveMembers, &c.AllowMemberPosts, &c.AllowMemberInvites, &c.RequireApprovalToPost,
        &locJSON, &c.CreatedAt, &c.UpdatedAt,
    )
    if err != nil {
        return nil, err
    }
    if desc.Valid {
        d := desc.String
        c.Description = &d
    }
    if vReqAt.Valid {
        t := vReqAt.Time
        c.VerificationRequestedAt = &t
    }
    if vAt.Valid {
        t := vAt.Time
        c.VerifiedAt = &t
    }
    if vBy.Valid {
        if u, e := uuid.Parse(vBy.String); e == nil {
            c.VerifiedByAdminID = &u
        }
    }
    if blkAt.Valid {
        t := blkAt.Time
        c.BlockedAt = &t
    }
    if blkBy.Valid {
        if u, e := uuid.Parse(blkBy.String); e == nil {
            c.BlockedByAdminID = &u
        }
    }
    if blkReason.Valid {
        s := blkReason.String
        c.BlockReason = &s
    }
    if memberLimit.Valid {
        ml := int(memberLimit.Int64)
        c.MemberLimit = &ml
    }
    if locJSON.Valid && locJSON.String != "" {
        var m models.JSONMap
        _ = json.Unmarshal([]byte(locJSON.String), &m)
        c.LocationData = m
    }
    return &c, nil
}

func (r *CockroachCommunityRepository) CreateCommunity(ctx context.Context, c *models.Community) error {
    const q = `
        INSERT INTO communities (
            name, description, type, is_private, head_user_id,
            auto_approve_members, allow_member_posts, allow_member_invites, require_approval_to_post, location_data
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        RETURNING id, created_at, updated_at
    `
    var desc interface{}
    if c.Description != nil {
        desc = *c.Description
    }
    var loc interface{}
    if c.LocationData != nil {
        b, _ := json.Marshal(c.LocationData)
        loc = string(b)
    }

    err := r.db.QueryRowContext(ctx, q,
        c.Name, desc, c.Type, c.IsPrivate, c.HeadUserID,
        c.AutoApproveMembers, c.AllowMemberPosts, c.AllowMemberInvites, c.RequireApprovalToPost, loc,
    ).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt)

    if err != nil {
        if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
            return errors.New("conflict: community_name_conflict")
        }
        return err
    }
    return nil
}

func (r *CockroachCommunityRepository) UpdateCommunity(ctx context.Context, c *models.Community) error {
    if c.ID == uuid.Nil {
        return errors.New("missing community ID")
    }
    const q = `
        UPDATE communities SET
            name = $1,
            description = $2,
            type = $3,
            is_private = $4,
            head_user_id = $5,
            verification_status = $6,
            is_blocked = $7,
            block_reason = $8,
            auto_approve_members = $9,
            allow_member_posts = $10,
            allow_member_invites = $11,
            require_approval_to_post = $12,
            location_data = $13,
            updated_at = NOW()
        WHERE id = $14
    `
    var desc interface{}
    if c.Description != nil {
        desc = *c.Description
    }
    var loc interface{}
    if c.LocationData != nil {
        b, _ := json.Marshal(c.LocationData)
        loc = string(b)
    }
    _, err := r.db.ExecContext(ctx, q,
        c.Name, desc, c.Type, c.IsPrivate, c.HeadUserID,
        c.VerificationStatus, c.IsBlocked, c.BlockReason,
        c.AutoApproveMembers, c.AllowMemberPosts, c.AllowMemberInvites, c.RequireApprovalToPost,
        loc, c.ID,
    )
    return err
}

// Keyset pagination by created_at DESC, id DESC to avoid OFFSET scans.
func (r *CockroachCommunityRepository) ListByType(ctx context.Context, communityType string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.Community, error) {
    if limit <= 0 || limit > 200 {
        limit = 50
    }
    base := `
        SELECT id, name, description, type, is_private, head_user_id,
               verification_status, is_blocked, created_at, updated_at
        FROM communities
        WHERE type = $1
    `
    var args []interface{}
    args = append(args, communityType)
    idx := 2
    if afterCreatedAt != nil && afterID != nil {
        base += `
            AND (created_at, id) < ($2, $3)
        `
        args = append(args, *afterCreatedAt, *afterID)
        idx = 4
    }
    base += `
        ORDER BY created_at DESC, id DESC
        LIMIT $` + itoa(idx)
    args = append(args, limit)

    rows, err := r.db.QueryContext(ctx, base, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var out []models.Community
    for rows.Next() {
        var c models.Community
        var desc sql.NullString
        if err := rows.Scan(
            &c.ID, &c.Name, &desc, &c.Type, &c.IsPrivate, &c.HeadUserID,
            &c.VerificationStatus, &c.IsBlocked, &c.CreatedAt, &c.UpdatedAt,
        ); err != nil {
            return nil, err
        }
        if desc.Valid {
            d := desc.String
            c.Description = &d
        }
        out = append(out, c)
    }
    return out, nil
}

// Includes ACTIVE membership (community_members) and ACTIVE roles (user_roles) with validity windows.
func (r *CockroachCommunityRepository) ListUserCommunities(ctx context.Context, userID uuid.UUID, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.Community, error) {
    if limit <= 0 || limit > 200 {
        limit = 50
    }
    base := `
        SELECT DISTINCT
            c.id, c.name, c.description, c.type, c.is_private, c.head_user_id,
            c.verification_status, c.is_blocked, c.created_at, c.updated_at
        FROM communities c
        LEFT JOIN user_roles ur
            ON ur.community_id = c.id
           AND ur.user_id = $1
           AND ur.status = 'ACTIVE'
           AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
           AND (ur.not_before IS NULL OR ur.not_before <= NOW())
        LEFT JOIN community_members cm
            ON cm.community_id = c.id
           AND cm.user_id = $1
           AND cm.status = 'ACTIVE'
        WHERE (ur.user_id IS NOT NULL OR cm.user_id IS NOT NULL)
    `
    var args []interface{}
    args = append(args, userID)
    idx := 2
    if afterCreatedAt != nil && afterID != nil {
        base += `
            AND (c.created_at, c.id) < ($2, $3)
        `
        args = append(args, *afterCreatedAt, *afterID)
        idx = 4
    }
    base += `
        ORDER BY c.created_at DESC, c.id DESC
        LIMIT $` + itoa(idx)
    args = append(args, limit)

    rows, err := r.db.QueryContext(ctx, base, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var out []models.Community
    for rows.Next() {
        var c models.Community
        var desc sql.NullString
        if err := rows.Scan(
            &c.ID, &c.Name, &desc, &c.Type, &c.IsPrivate, &c.HeadUserID,
            &c.VerificationStatus, &c.IsBlocked, &c.CreatedAt, &c.UpdatedAt,
        ); err != nil {
            return nil, err
        }
        if desc.Valid {
            d := desc.String
            c.Description = &d
        }
        out = append(out, c)
    }
    return out, nil
}

// small helper to avoid fmt for constant building
func itoa(i int) string {
    switch i {
    case 1: return "1"
    case 2: return "2"
    case 3: return "3"
    case 4: return "4"
    case 5: return "5"
    case 6: return "6"
    case 7: return "7"
    case 8: return "8"
    case 9: return "9"
    default: return "10"
    }
}
