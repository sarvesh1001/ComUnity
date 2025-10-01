package handler

import (
    "encoding/json"
    "net/http"
    "strconv"
    "time"

    "github.com/ComUnity/auth-service/internal/models"
    "github.com/ComUnity/auth-service/internal/service"
    "github.com/ComUnity/auth-service/internal/util"
    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
)

type CommunityAdminHandler struct {
    svc service.CommunityAdminService
}

func NewCommunityAdminHandler(svc service.CommunityAdminService) *CommunityAdminHandler {
    return &CommunityAdminHandler{svc: svc}
}

func (h *CommunityAdminHandler) SubmitVerification(w http.ResponseWriter, r *http.Request) {
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
    var req models.CommunityVerificationRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    req.CommunityID = communityID
    req.RequestedByUserID = claims.UserContext.UserID
    id, err := h.svc.SubmitVerification(r.Context(), req)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{"request_id": id})
}

func (h *CommunityAdminHandler) DecideVerification(w http.ResponseWriter, r *http.Request) {
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
        Approve         bool    `json:"approve"`
        Notes           *string `json:"notes"`
        RejectionReason *string `json:"rejection_reason"`
        AdditionalInfo  *string `json:"additional_info"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    if err := h.svc.DecideVerification(r.Context(), reqID, claims.UserContext.UserID, body.Approve, body.Notes, body.RejectionReason, body.AdditionalInfo); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func (h *CommunityAdminHandler) ListPendingVerifications(w http.ResponseWriter, r *http.Request) {
    var reqType *string
    if v := r.URL.Query().Get("type"); v != "" {
        vv := v
        reqType = &vv
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
    list, err := h.svc.ListPendingVerifications(r.Context(), reqType, afterAtPtr, afterIDPtr, limit)
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

func (h *CommunityAdminHandler) BlockCommunity(w http.ResponseWriter, r *http.Request) {
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
        Reason       string `json:"reason"`
        Severity     string `json:"severity"`
        DurationDays *int   `json:"duration_days"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    id, err := h.svc.BlockCommunity(r.Context(), communityID, claims.UserContext.UserID, body.Reason, body.Severity, body.DurationDays)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{"action_id": id})
}

func (h *CommunityAdminHandler) UnblockCommunity(w http.ResponseWriter, r *http.Request) {
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
    var body struct{ Reason string `json:"reason"` }
    _ = json.NewDecoder(r.Body).Decode(&body)
    id, err := h.svc.UnblockCommunity(r.Context(), communityID, claims.UserContext.UserID, body.Reason)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{"action_id": id})
}

func (h *CommunityAdminHandler) LogAdminAction(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    var a models.CommunityAdminAction
    if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    a.AdminUserID = claims.UserContext.UserID
    id, err := h.svc.LogAdminAction(r.Context(), a)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{"action_id": id})
}

func (h *CommunityAdminHandler) ListAdminActions(w http.ResponseWriter, r *http.Request) {
    var communityID, adminUserID *uuid.UUID
    var actionType *string
    if v := r.URL.Query().Get("community_id"); v != "" {
        if id, err := uuid.Parse(v); err == nil { communityID = &id }
    }
    if v := r.URL.Query().Get("admin_user_id"); v != "" {
        if id, err := uuid.Parse(v); err == nil { adminUserID = &id }
    }
    if v := r.URL.Query().Get("action_type"); v != "" {
        vv := v
        actionType = &vv
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
    list, err := h.svc.ListAdminActions(r.Context(), communityID, adminUserID, actionType, afterAtPtr, afterIDPtr, limit)
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

func (h *CommunityAdminHandler) CreateSystemReport(w http.ResponseWriter, r *http.Request) {
    var rep models.SystemReport
    if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    id, err := h.svc.CreateSystemReport(r.Context(), rep)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]any{"report_id": id})
}

func (h *CommunityAdminHandler) UpdateSystemReport(w http.ResponseWriter, r *http.Request) {
    reportID, err := uuid.Parse(chi.URLParam(r, "reportID"))
    if err != nil {
        http.Error(w, "invalid reportID", http.StatusBadRequest)
        return
    }
    var updates map[string]any
    if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    if err := h.svc.UpdateSystemReport(r.Context(), reportID, updates); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func (h *CommunityAdminHandler) ListSystemReports(w http.ResponseWriter, r *http.Request) {
    var reportType, status, severity *string
    if v := r.URL.Query().Get("report_type"); v != "" { vv := v; reportType = &vv }
    if v := r.URL.Query().Get("status"); v != "" { vv := v; status = &vv }
    if v := r.URL.Query().Get("severity"); v != "" { vv := v; severity = &vv }
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
    list, err := h.svc.ListSystemReports(r.Context(), reportType, status, severity, afterAtPtr, afterIDPtr, limit)
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
