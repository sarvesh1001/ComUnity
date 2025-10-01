package handler

import (
    "encoding/json"
    "net/http"
    "strconv"
    "time"

    "github.com/ComUnity/auth-service/internal/repository"
    "github.com/ComUnity/auth-service/internal/service"
    "github.com/ComUnity/auth-service/internal/util"
    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
)

type CommunityContentHandler struct {
    svc service.CommunityContentService
}

func NewCommunityContentHandler(svc service.CommunityContentService) *CommunityContentHandler {
    return &CommunityContentHandler{svc: svc}
}

func (h *CommunityContentHandler) CreatePost(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    communityID, err := uuid.Parse(chi.URLParam(r, "communityID"))
    if err != nil {
        http.Error(w, "invalid communityID", http.StatusBadRequest)
        return
    }
    var in service.CreatePostInput
    if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    in.CommunityID = communityID
    post, err := h.svc.CreatePost(r.Context(), claims.UserContext.UserID, in)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(post)
}

func (h *CommunityContentHandler) ListPosts(w http.ResponseWriter, r *http.Request) {
    communityID, err := uuid.Parse(chi.URLParam(r, "communityID"))
    if err != nil {
        http.Error(w, "invalid communityID", http.StatusBadRequest)
        return
    }
    opt := repository.ListPostsOptions{
        PinnedFirst: r.URL.Query().Get("pinned_first") == "true",
        Limit:       50,
    }
    if v := r.URL.Query().Get("type"); v != "" {
        opt.TypeFilter = &v
    }
    if v := r.URL.Query().Get("status"); v != "" {
        opt.StatusFilter = &v
    }
    if v := r.URL.Query().Get("after_created_at"); v != "" {
        if ts, err := time.Parse(time.RFC3339, v); err == nil {
            opt.AfterCreatedAt = &ts
        }
    }
    if v := r.URL.Query().Get("after_id"); v != "" {
        if id, err := uuid.Parse(v); err == nil {
            opt.AfterID = &id
        }
    }
    if v := r.URL.Query().Get("limit"); v != "" {
        if n, err := strconv.Atoi(v); err == nil {
            opt.Limit = n
        }
    }
    posts, err := h.svc.ListPosts(r.Context(), communityID, opt)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{
        "items": posts,
        "count": len(posts),
    })
}

func (h *CommunityContentHandler) ModeratePost(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    postID, err := uuid.Parse(chi.URLParam(r, "postID"))
    if err != nil {
        http.Error(w, "invalid postID", http.StatusBadRequest)
        return
    }
    var body struct {
        Status string  `json:"status"`
        Reason *string `json:"reason"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    if err := h.svc.ModeratePost(r.Context(), postID, claims.UserContext.UserID, body.Status, body.Reason); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func (h *CommunityContentHandler) AddComment(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    postID, err := uuid.Parse(chi.URLParam(r, "postID"))
    if err != nil {
        http.Error(w, "invalid postID", http.StatusBadRequest)
        return
    }
    var in service.AddCommentInput
    if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    in.PostID = postID
    c, err := h.svc.AddComment(r.Context(), claims.UserContext.UserID, in)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(c)
}

func (h *CommunityContentHandler) ListComments(w http.ResponseWriter, r *http.Request) {
    postID, err := uuid.Parse(chi.URLParam(r, "postID"))
    if err != nil {
        http.Error(w, "invalid postID", http.StatusBadRequest)
        return
    }
    var afterAtPtr *time.Time
    var afterIDPtr *uuid.UUID
    if v := r.URL.Query().Get("after_created_at"); v != "" {
        if ts, err := time.Parse(time.RFC3339, v); err == nil {
            afterAtPtr = &ts
        }
    }
    if v := r.URL.Query().Get("after_id"); v != "" {
        if id, err := uuid.Parse(v); err == nil {
            afterIDPtr = &id
        }
    }
    limit := 50
    if v := r.URL.Query().Get("limit"); v != "" {
        if n, err := strconv.Atoi(v); err == nil {
            limit = n
        }
    }
    list, err := h.svc.ListComments(r.Context(), postID, afterAtPtr, afterIDPtr, limit)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{
        "items": list,
        "count": len(list),
    })
}

func (h *CommunityContentHandler) ReactToPost(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    postID, err := uuid.Parse(chi.URLParam(r, "postID"))
    if err != nil {
        http.Error(w, "invalid postID", http.StatusBadRequest)
        return
    }
    var body struct{ Reaction string `json:"reaction"` }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    if err := h.svc.React(r.Context(), &postID, nil, claims.UserContext.UserID, body.Reaction); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func (h *CommunityContentHandler) ReactToComment(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    commentID, err := uuid.Parse(chi.URLParam(r, "commentID"))
    if err != nil {
        http.Error(w, "invalid commentID", http.StatusBadRequest)
        return
    }
    var body struct{ Reaction string `json:"reaction"` }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    if err := h.svc.React(r.Context(), nil, &commentID, claims.UserContext.UserID, body.Reaction); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func (h *CommunityContentHandler) RSVPEvent(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    postID, err := uuid.Parse(chi.URLParam(r, "postID"))
    if err != nil {
        http.Error(w, "invalid postID", http.StatusBadRequest)
        return
    }
    var body struct {
        Status  string  `json:"status"`
        Message *string `json:"message"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    if err := h.svc.RSVPEvent(r.Context(), postID, claims.UserContext.UserID, body.Status, body.Message); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func (h *CommunityContentHandler) ListEventAttendees(w http.ResponseWriter, r *http.Request) {
    postID, err := uuid.Parse(chi.URLParam(r, "postID"))
    if err != nil {
        http.Error(w, "invalid postID", http.StatusBadRequest)
        return
    }
    var status *string
    if v := r.URL.Query().Get("status"); v != "" {
        vv := v
        status = &vv
    }
    var afterAtPtr *time.Time
    var afterIDPtr *uuid.UUID
    if v := r.URL.Query().Get("after_created_at"); v != "" {
        if ts, err := time.Parse(time.RFC3339, v); err == nil {
            afterAtPtr = &ts
        }
    }
    if v := r.URL.Query().Get("after_id"); v != "" {
        if id, err := uuid.Parse(v); err == nil {
            afterIDPtr = &id
        }
    }
    limit := 100
    if v := r.URL.Query().Get("limit"); v != "" {
        if n, err := strconv.Atoi(v); err == nil {
            limit = n
        }
    }
    list, err := h.svc.ListEventAttendees(r.Context(), postID, status, afterAtPtr, afterIDPtr, limit)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{
        "items": list,
        "count": len(list),
    })
}
