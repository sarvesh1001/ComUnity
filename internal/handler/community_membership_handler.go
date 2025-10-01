package handler

import (
    "encoding/json"
    "net/http"
    "strconv"
    "time"

    "github.com/ComUnity/auth-service/internal/service"
    "github.com/ComUnity/auth-service/internal/util"
    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
)

type CommunityMembershipHandler struct {
    svc service.CommunityMembershipService
}

func NewCommunityMembershipHandler(svc service.CommunityMembershipService) *CommunityMembershipHandler {
    return &CommunityMembershipHandler{svc: svc}
}

func (h *CommunityMembershipHandler) RequestJoin(w http.ResponseWriter, r *http.Request) {
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
    var body struct {
        Message *string `json:"message"`
    }
    _ = json.NewDecoder(r.Body).Decode(&body)
    id, err := h.svc.RequestJoin(r.Context(), communityID, claims.UserContext.UserID, body.Message)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{"request_id": id})
}

func (h *CommunityMembershipHandler) ReviewJoin(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    reqID, err := uuid.Parse(chi.URLParam(r, "requestID"))
    if err != nil {
        http.Error(w, "invalid requestID", http.StatusBadRequest)
        return
    }
    var body struct {
        Approve bool    `json:"approve"`
        Note    *string `json:"note"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    if err := h.svc.ReviewJoin(r.Context(), reqID, claims.UserContext.UserID, body.Approve, body.Note); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func (h *CommunityMembershipHandler) ChangeMemberRole(w http.ResponseWriter, r *http.Request) {
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
    userID, err := uuid.Parse(chi.URLParam(r, "userID"))
    if err != nil {
        http.Error(w, "invalid userID", http.StatusBadRequest)
        return
    }
    var body struct {
        Role string `json:"role"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    if err := h.svc.ChangeMemberRole(r.Context(), communityID, userID, body.Role, claims.UserContext.UserID); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func (h *CommunityMembershipHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
    communityID, err := uuid.Parse(chi.URLParam(r, "communityID"))
    if err != nil {
        http.Error(w, "invalid communityID", http.StatusBadRequest)
        return
    }
    userID, err := uuid.Parse(chi.URLParam(r, "userID"))
    if err != nil {
        http.Error(w, "invalid userID", http.StatusBadRequest)
        return
    }
    var body struct {
        Status string  `json:"status"` // SUSPENDED/BANNED/LEFT
        Reason *string `json:"reason"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    if err := h.svc.RemoveMember(r.Context(), communityID, userID, body.Status, body.Reason); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func (h *CommunityMembershipHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
    communityID, err := uuid.Parse(chi.URLParam(r, "communityID"))
    if err != nil {
        http.Error(w, "invalid communityID", http.StatusBadRequest)
        return
    }
    var roleFilter, statusFilter *string
    if v := r.URL.Query().Get("role"); v != "" {
        vv := v
        roleFilter = &vv
    }
    if v := r.URL.Query().Get("status"); v != "" {
        vv := v
        statusFilter = &vv
    }
    var afterAtPtr *time.Time
    var afterIDPtr *uuid.UUID
    if v := r.URL.Query().Get("after_joined_at"); v != "" {
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
    members, err := h.svc.ListMembers(r.Context(), communityID, roleFilter, statusFilter, afterAtPtr, afterIDPtr, limit)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{
        "items": members,
        "count": len(members),
    })
}

func (h *CommunityMembershipHandler) CreateInvitation(w http.ResponseWriter, r *http.Request) {
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
    var body struct {
        InviteeUserID *uuid.UUID `json:"invitee_user_id"`
        InviteePhone  *string    `json:"invitee_phone"`
        SuggestedRole string     `json:"suggested_role"`
        Message       *string    `json:"message"`
        ExpiresAt     *time.Time `json:"expires_at"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    exp := time.Now().Add(7 * 24 * time.Hour)
    if body.ExpiresAt != nil {
        exp = *body.ExpiresAt
    }
    id, err := h.svc.Invite(r.Context(), communityID, claims.UserContext.UserID, body.InviteeUserID, body.InviteePhone, body.SuggestedRole, body.Message, exp)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{"invitation_id": id})
}

func (h *CommunityMembershipHandler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    invID, err := uuid.Parse(chi.URLParam(r, "invitationID"))
    if err != nil {
        http.Error(w, "invalid invitationID", http.StatusBadRequest)
        return
    }
    if err := h.svc.AcceptInvitation(r.Context(), invID, claims.UserContext.UserID); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func (h *CommunityMembershipHandler) DeclineInvitation(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    invID, err := uuid.Parse(chi.URLParam(r, "invitationID"))
    if err != nil {
        http.Error(w, "invalid invitationID", http.StatusBadRequest)
        return
    }
    if err := h.svc.DeclineInvitation(r.Context(), invID, claims.UserContext.UserID); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}
