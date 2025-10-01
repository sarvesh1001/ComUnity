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

type CommunityContentService interface {
    CreatePost(ctx context.Context, authorID uuid.UUID, in CreatePostInput) (*models.CommunityPost, error)
    ModeratePost(ctx context.Context, postID uuid.UUID, moderatorID uuid.UUID, status string, reason *string) error
    ListPosts(ctx context.Context, communityID uuid.UUID, opt repository.ListPostsOptions) ([]models.CommunityPost, error)

    AddComment(ctx context.Context, authorID uuid.UUID, in AddCommentInput) (*models.PostComment, error)
    ListComments(ctx context.Context, postID uuid.UUID, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.PostComment, error)

    React(ctx context.Context, postID *uuid.UUID, commentID *uuid.UUID, userID uuid.UUID, reaction string) error

    RSVPEvent(ctx context.Context, eventPostID uuid.UUID, userID uuid.UUID, status string, message *string) error
    ListEventAttendees(ctx context.Context, eventPostID uuid.UUID, status *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.EventAttendee, error)
}

type CreatePostInput struct {
    CommunityID        uuid.UUID
    Title              *string
    Content            string
    PostType           string // POST, ANNOUNCEMENT, ALERT, EVENT, POLL
    MediaAttachments   models.JSONMap
    IsPinned           bool
    IsFeatured         bool
    AllowComments      bool
    RequireApproval    bool
    Priority           string  // LOW, NORMAL, HIGH, URGENT
    EventStartTime     *time.Time
    EventEndTime       *time.Time
    EventLocation      *string
    MaxAttendees       *int
}

type AddCommentInput struct {
    PostID            uuid.UUID
    ParentCommentID   *uuid.UUID
    Content           string
    MediaAttachments  models.JSONMap
    Status            string // PUBLISHED, HIDDEN, REMOVED
}

type communityContentService struct {
    repo repository.CommunityContentRepository
}

func NewCommunityContentService(repo repository.CommunityContentRepository) CommunityContentService {
    return &communityContentService{repo: repo}
}

func (s *communityContentService) CreatePost(ctx context.Context, authorID uuid.UUID, in CreatePostInput) (*models.CommunityPost, error) {
    if authorID == uuid.Nil || in.CommunityID == uuid.Nil {
        return nil, errors.New("missing identifiers")
    }
    ct := strings.TrimSpace(in.Content)
    if ct == "" {
        return nil, errors.New("content is required")
    }
    pt := strings.ToUpper(strings.TrimSpace(in.PostType))
    switch pt {
    case "POST", "ANNOUNCEMENT", "ALERT", "EVENT", "POLL":
    default:
        return nil, errors.New("invalid post type")
    }
    pr := strings.ToUpper(strings.TrimSpace(in.Priority))
    if pr == "" {
        pr = "NORMAL"
    }
    switch pr {
    case "LOW", "NORMAL", "HIGH", "URGENT":
    default:
        return nil, errors.New("invalid priority")
    }

    p := &models.CommunityPost{
        CommunityID:      in.CommunityID,
        AuthorUserID:     authorID,
        Title:            in.Title,
        Content:          ct,
        PostType:         pt,
        MediaAttachments: in.MediaAttachments,
        IsPinned:         in.IsPinned,
        IsFeatured:       in.IsFeatured,
        AllowComments:    in.AllowComments,
        RequireApproval:  in.RequireApproval,
        Status:           "PUBLISHED",
        Priority:         pr,
        EventStartTime:   in.EventStartTime,
        EventEndTime:     in.EventEndTime,
        EventLocation:    in.EventLocation,
        MaxAttendees:     in.MaxAttendees,
    }
    if pt == "EVENT" && in.EventStartTime == nil {
        return nil, errors.New("event_start_time required for EVENT posts")
    }
    if err := s.repo.CreatePost(ctx, p); err != nil {
        return nil, err
    }
    return p, nil
}

func (s *communityContentService) ModeratePost(ctx context.Context, postID uuid.UUID, moderatorID uuid.UUID, status string, reason *string) error {
    if postID == uuid.Nil || moderatorID == uuid.Nil {
        return errors.New("missing identifiers")
    }
    st := strings.ToUpper(strings.TrimSpace(status))
    switch st {
    case "DRAFT", "PENDING", "PUBLISHED", "HIDDEN", "REMOVED":
    default:
        return errors.New("invalid status")
    }
    return s.repo.UpdatePostStatus(ctx, postID, st, &moderatorID, reason)
}

func (s *communityContentService) ListPosts(ctx context.Context, communityID uuid.UUID, opt repository.ListPostsOptions) ([]models.CommunityPost, error) {
    if communityID == uuid.Nil { return nil, errors.New("missing community ID") }
    if opt.TypeFilter != nil {
        tf := strings.ToUpper(strings.TrimSpace(*opt.TypeFilter))
        if tf != "POST" && tf != "ANNOUNCEMENT" && tf != "ALERT" && tf != "EVENT" && tf != "POLL" {
            return nil, errors.New("invalid type filter")
        }
        opt.TypeFilter = &tf
    }
    if opt.StatusFilter != nil {
        sf := strings.ToUpper(strings.TrimSpace(*opt.StatusFilter))
        switch sf {
        case "DRAFT", "PENDING", "PUBLISHED", "HIDDEN", "REMOVED":
        default:
            return nil, errors.New("invalid status filter")
        }
        opt.StatusFilter = &sf
    }
    if opt.Limit <= 0 || opt.Limit > 200 {
        opt.Limit = 50
    }
    return s.repo.ListPosts(ctx, communityID, opt)
}

func (s *communityContentService) AddComment(ctx context.Context, authorID uuid.UUID, in AddCommentInput) (*models.PostComment, error) {
    if authorID == uuid.Nil || in.PostID == uuid.Nil {
        return nil, errors.New("missing identifiers")
    }
    c := strings.TrimSpace(in.Content)
    if c == "" {
        return nil, errors.New("comment content is required")
    }
    st := strings.ToUpper(strings.TrimSpace(in.Status))
    if st == "" { st = "PUBLISHED" }
    switch st {
    case "PUBLISHED", "HIDDEN", "REMOVED":
    default:
        return nil, errors.New("invalid comment status")
    }
    pc := &models.PostComment{
        PostID:           in.PostID,
        AuthorUserID:     authorID,
        ParentCommentID:  in.ParentCommentID,
        Content:          c,
        MediaAttachments: in.MediaAttachments,
        Status:           st,
    }
    if err := s.repo.AddComment(ctx, pc); err != nil {
        return nil, err
    }
    return pc, nil
}

func (s *communityContentService) ListComments(ctx context.Context, postID uuid.UUID, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.PostComment, error) {
    if postID == uuid.Nil { return nil, errors.New("missing post ID") }
    if limit <= 0 || limit > 200 { limit = 50 }
    return s.repo.ListComments(ctx, postID, afterCreatedAt, afterID, limit)
}

func (s *communityContentService) React(ctx context.Context, postID *uuid.UUID, commentID *uuid.UUID, userID uuid.UUID, reaction string) error {
    if userID == uuid.Nil {
        return errors.New("missing user ID")
    }
    if (postID == nil && commentID == nil) || (postID != nil && commentID != nil) {
        return errors.New("must react to either a post or a comment")
    }
    rt := strings.ToUpper(strings.TrimSpace(reaction))
    switch rt {
    case "LIKE", "LOVE", "LAUGH", "ANGRY", "SAD":
    default:
        return errors.New("invalid reaction")
    }
    return s.repo.UpsertReaction(ctx, postID, commentID, userID, rt)
}

func (s *communityContentService) RSVPEvent(ctx context.Context, eventPostID uuid.UUID, userID uuid.UUID, status string, message *string) error {
    if eventPostID == uuid.Nil || userID == uuid.Nil {
        return errors.New("missing identifiers")
    }
    st := strings.ToUpper(strings.TrimSpace(status))
    switch st {
    case "INTERESTED", "GOING", "NOT_GOING", "MAYBE":
    default:
        return errors.New("invalid RSVP status")
    }
    return s.repo.UpsertEventRSVP(ctx, eventPostID, userID, st, message)
}

func (s *communityContentService) ListEventAttendees(ctx context.Context, eventPostID uuid.UUID, status *string, afterCreatedAt *time.Time, afterID *uuid.UUID, limit int) ([]models.EventAttendee, error) {
    if eventPostID == uuid.Nil { return nil, errors.New("missing event post ID") }
    if status != nil {
        st := strings.ToUpper(strings.TrimSpace(*status))
        switch st {
        case "INTERESTED", "GOING", "NOT_GOING", "MAYBE":
        default:
            return nil, errors.New("invalid attendee status filter")
        }
        status = &st
    }
    if limit <= 0 || limit > 500 { limit = 100 }
    return s.repo.ListEventAttendees(ctx, eventPostID, status, afterCreatedAt, afterID, limit)
}
