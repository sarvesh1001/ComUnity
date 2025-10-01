// internal/repository/community_content_repository.go
package repository

import (
    "context"
    "database/sql"
    "encoding/json"
    "time"

    "github.com/ComUnity/auth-service/internal/models"
    "github.com/google/uuid"
)

type ListPostsOptions struct {
    TypeFilter   *string  // POST, ANNOUNCEMENT, ALERT, EVENT, POLL
    StatusFilter *string  // DRAFT, PENDING, PUBLISHED, HIDDEN, REMOVED
    PinnedFirst  bool
    AfterCreatedAt *time.Time
    AfterID      *uuid.UUID
    Limit        int
}

type CommunityContentRepository interface {
    CreatePost(ctx context.Context, p *models.CommunityPost) error
    UpdatePostStatus(ctx context.Context, postID uuid.UUID, status string, moderatorID *uuid.UUID, reason *string) error
    ListPosts(ctx context.Context, communityID uuid.UUID, opt ListPostsOptions) ([]models.CommunityPost, error)

    AddComment(ctx context.Context, c *models.PostComment) error
    ListComments(ctx context.Context, postID uuid.UUID, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.PostComment, error)

    UpsertReaction(ctx context.Context, postID *uuid.UUID, commentID *uuid.UUID, userID uuid.UUID, reaction string) error

    UpsertEventRSVP(ctx context.Context, eventPostID uuid.UUID, userID uuid.UUID, status string, message *string) error
    ListEventAttendees(ctx context.Context, eventPostID uuid.UUID, status *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.EventAttendee, error)
}

type CockroachCommunityContentRepository struct {
    db *sql.DB
}

func NewCockroachCommunityContentRepository(db *sql.DB) CommunityContentRepository {
    return &CockroachCommunityContentRepository{db: db}
}

func (r *CockroachCommunityContentRepository) CreatePost(ctx context.Context, p *models.CommunityPost) error {
    const q = `
        INSERT INTO community_posts (
            community_id, author_user_id, title, content, post_type, media_attachments,
            is_pinned, is_featured, allow_comments, require_approval, status, priority,
            event_start_time, event_end_time, event_location, max_attendees
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
        RETURNING id, created_at, updated_at
    `
    var title interface{}
    if p.Title != nil { title = *p.Title }
    media := "[]"
    if p.MediaAttachments != nil {
        b, _ := json.Marshal(p.MediaAttachments)
        media = string(b)
    }
    var eventStart, eventEnd, eventLoc interface{}
    if p.EventStartTime != nil { eventStart = *p.EventStartTime }
    if p.EventEndTime != nil { eventEnd = *p.EventEndTime }
    if p.EventLocation != nil { eventLoc = *p.EventLocation }

    return r.db.QueryRowContext(ctx, q,
        p.CommunityID, p.AuthorUserID, title, p.Content, p.PostType, media,
        p.IsPinned, p.IsFeatured, p.AllowComments, p.RequireApproval, p.Status, p.Priority,
        eventStart, eventEnd, eventLoc, p.MaxAttendees,
    ).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
}

func (r *CockroachCommunityContentRepository) UpdatePostStatus(ctx context.Context, postID uuid.UUID, status string, moderatorID *uuid.UUID, reason *string) error {
    const q = `
        UPDATE community_posts
           SET status = $2,
               moderated_by_user_id = $3,
               moderated_at = NOW(),
               moderation_reason = $4,
               updated_at = NOW()
         WHERE id = $1
    `
    _, err := r.db.ExecContext(ctx, q, postID, status, moderatorID, reason)
    return err
}

func (r *CockroachCommunityContentRepository) ListPosts(ctx context.Context, communityID uuid.UUID, opt ListPostsOptions) ([]models.CommunityPost, error) {
    limit := opt.Limit
    if limit <= 0 || limit > 200 {
        limit = 50
    }

    base := `
        SELECT
            id, community_id, author_user_id, title, content, post_type, media_attachments,
            is_pinned, is_featured, allow_comments, require_approval, status, priority,
            event_start_time, event_end_time, event_location, max_attendees,
            likes_count, comments_count, shares_count, views_count,
            moderated_by_user_id, moderated_at, moderation_reason,
            created_at, updated_at
        FROM community_posts
        WHERE community_id = $1
    `
    args := []interface{}{communityID}
    idx := 2

    if opt.TypeFilter != nil {
        base += ` AND post_type = $` + itoa(idx)
        args = append(args, *opt.TypeFilter)
        idx++
    }
    if opt.StatusFilter != nil {
        base += ` AND status = $` + itoa(idx)
        args = append(args, *opt.StatusFilter)
        idx++
    }
    if opt.AfterCreatedAt != nil && opt.AfterID != nil {
        base += ` AND (is_pinned DESC, created_at, id) < (is_pinned DESC, $` + itoa(idx) + `, $` + itoa(idx+1) + `)`
        args = append(args, *opt.AfterCreatedAt, *opt.AfterID)
        idx += 2
    }
    base += ` ORDER BY `
    if opt.PinnedFirst {
        base += ` is_pinned DESC, `
    }
    base += ` created_at DESC, id DESC LIMIT $` + itoa(idx)
    args = append(args, limit)

    rows, err := r.db.QueryContext(ctx, base, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var out []models.CommunityPost
    for rows.Next() {
        var p models.CommunityPost
        var title, media, eventLoc, modReason sql.NullString
        var eventStart, eventEnd, modAt sql.NullTime
        var modBy sql.NullString
        if err := rows.Scan(
            &p.ID, &p.CommunityID, &p.AuthorUserID, &title, &p.Content, &p.PostType, &media,
            &p.IsPinned, &p.IsFeatured, &p.AllowComments, &p.RequireApproval, &p.Status, &p.Priority,
            &eventStart, &eventEnd, &eventLoc, &p.MaxAttendees,
            &p.LikesCount, &p.CommentsCount, &p.SharesCount, &p.ViewsCount,
            &modBy, &modAt, &modReason,
            &p.CreatedAt, &p.UpdatedAt,
        ); err != nil {
            return nil, err
        }
        if title.Valid { t := title.String; p.Title = &t }
        if media.Valid && media.String != "" {
            var m models.JSONMap
            _ = json.Unmarshal([]byte(media.String), &m)
            p.MediaAttachments = m
        }
        if eventStart.Valid { t := eventStart.Time; p.EventStartTime = &t }
        if eventEnd.Valid { t := eventEnd.Time; p.EventEndTime = &t }
        if eventLoc.Valid { s := eventLoc.String; p.EventLocation = &s }
        if modBy.Valid {
            if u, e := uuid.Parse(modBy.String); e == nil { p.ModeratedByUserID = &u }
        }
        if modAt.Valid { t := modAt.Time; p.ModeratedAt = &t }
        if modReason.Valid { s := modReason.String; p.ModerationReason = &s }
        out = append(out, p)
    }
    return out, nil
}

func (r *CockroachCommunityContentRepository) AddComment(ctx context.Context, c *models.PostComment) error {
    const q = `
        INSERT INTO post_comments (post_id, author_user_id, parent_comment_id, content, media_attachments, status)
        VALUES ($1,$2,$3,$4,$5,$6)
        RETURNING id, created_at, updated_at
    `
    var media string
    if c.MediaAttachments != nil {
        b, _ := json.Marshal(c.MediaAttachments)
        media = string(b)
    } else {
        media = "[]"
    }
    return r.db.QueryRowContext(ctx, q,
        c.PostID, c.AuthorUserID, c.ParentCommentID, c.Content, media, c.Status,
    ).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt)
}

func (r *CockroachCommunityContentRepository) ListComments(ctx context.Context, postID uuid.UUID, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.PostComment, error) {
    if limit <= 0 || limit > 200 {
        limit = 50
    }
    base := `
        SELECT id, post_id, author_user_id, parent_comment_id, content, media_attachments,
               status, moderated_by_user_id, moderated_at, moderation_reason,
               likes_count, replies_count, created_at, updated_at
          FROM post_comments
         WHERE post_id = $1
    `
    args := []interface{}{postID}
    idx := 2
    if afterCreatedAt != nil && afterID != nil {
        base += ` AND (created_at, id) < ($` + itoa(idx) + `, $` + itoa(idx+1) + `)`
        args = append(args, *afterCreatedAt, *afterID)
        idx += 2
    }
    base += ` ORDER BY created_at DESC, id DESC LIMIT $` + itoa(idx)
    args = append(args, limit)

    rows, err := r.db.QueryContext(ctx, base, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var out []models.PostComment
    for rows.Next() {
        var c models.PostComment
        var parent sql.NullString
        var media, modReason sql.NullString
        var modBy sql.NullString
        var modAt sql.NullTime

        if err := rows.Scan(
            &c.ID, &c.PostID, &c.AuthorUserID, &parent, &c.Content, &media,
            &c.Status, &modBy, &modAt, &modReason,
            &c.LikesCount, &c.RepliesCount, &c.CreatedAt, &c.UpdatedAt,
        ); err != nil {
            return nil, err
        }
        if parent.Valid {
            if u, e := uuid.Parse(parent.String); e == nil { c.ParentCommentID = &u }
        }
        if media.Valid && media.String != "" {
            var m models.JSONMap
            _ = json.Unmarshal([]byte(media.String), &m)
            c.MediaAttachments = m
        }
        if modBy.Valid {
            if u, e := uuid.Parse(modBy.String); e == nil { c.ModeratedByUserID = &u }
        }
        if modAt.Valid { t := modAt.Time; c.ModeratedAt = &t }
        if modReason.Valid { s := modReason.String; c.ModerationReason = &s }
        out = append(out, c)
    }
    return out, nil
}

func (r *CockroachCommunityContentRepository) UpsertReaction(ctx context.Context, postID *uuid.UUID, commentID *uuid.UUID, userID uuid.UUID, reaction string) error {
    const q = `
        INSERT INTO post_reactions (post_id, comment_id, user_id, reaction_type)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (post_id, user_id) WHERE post_id IS NOT NULL DO UPDATE SET reaction_type = EXCLUDED.reaction_type
    `
    // Try post reaction path
    if postID != nil {
        if _, err := r.db.ExecContext(ctx, q, postID, nil, userID, reaction); err == nil {
            return nil
        }
    }
    // Fallback to comment reaction path
    const qc = `
        INSERT INTO post_reactions (post_id, comment_id, user_id, reaction_type)
        VALUES (NULL,$1,$2,$3)
        ON CONFLICT (comment_id, user_id) WHERE comment_id IS NOT NULL DO UPDATE SET reaction_type = EXCLUDED.reaction_type
    `
    _, err := r.db.ExecContext(ctx, qc, commentID, userID, reaction)
    return err
}

func (r *CockroachCommunityContentRepository) UpsertEventRSVP(ctx context.Context, eventPostID uuid.UUID, userID uuid.UUID, status string, message *string) error {
    const q = `
        INSERT INTO event_attendees (event_post_id, user_id, status, response_message)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (event_post_id, user_id) DO UPDATE SET
            status = EXCLUDED.status,
            response_message = EXCLUDED.response_message,
            updated_at = NOW()
    `
    _, err := r.db.ExecContext(ctx, q, eventPostID, userID, status, message)
    return err
}

func (r *CockroachCommunityContentRepository) ListEventAttendees(ctx context.Context, eventPostID uuid.UUID, status *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.EventAttendee, error) {
    if limit <= 0 || limit > 500 {
        limit = 100
    }
    base := `
        SELECT id, event_post_id, user_id, status, response_message, created_at, updated_at
          FROM event_attendees
         WHERE event_post_id = $1
    `
    args := []interface{}{eventPostID}
    idx := 2
    if status != nil {
        base += ` AND status = $` + itoa(idx)
        args = append(args, *status)
        idx++
    }
    if afterCreatedAt != nil && afterID != nil {
        base += ` AND (created_at, id) < ($` + itoa(idx) + `, $` + itoa(idx+1) + `)`
        args = append(args, *afterCreatedAt, *afterID)
        idx += 2
    }
    base += ` ORDER BY created_at DESC, id DESC LIMIT $` + itoa(idx)
    args = append(args, limit)

    rows, err := r.db.QueryContext(ctx, base, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var out []models.EventAttendee
    for rows.Next() {
        var a models.EventAttendee
        var msg sql.NullString
        if err := rows.Scan(
            &a.ID, &a.EventPostID, &a.UserID, &a.Status, &msg, &a.CreatedAt, &a.UpdatedAt,
        ); err != nil {
            return nil, err
        }
        if msg.Valid { s := msg.String; a.Message = &s }
        out = append(out, a)
    }
    return out, nil
}
