package handler

import (
    "context"
    "encoding/json"
    "net/http"
    "strconv"
    "strings"
    "time"

    "github.com/ComUnity/auth-service/internal/service"
    "github.com/ComUnity/auth-service/internal/util"
    "github.com/ComUnity/auth-service/internal/util/logger"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
)

// PermissionChecker abstracts a global permission check for a user.
// Wire this to the same RBAC service the RequirePermission middleware uses.
type PermissionChecker interface {
    HasGlobalPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error)
}

type CommunityCoreHandler struct {
    svc   service.CommunityCoreService
    perms PermissionChecker
}

func NewCommunityCoreHandler(svc service.CommunityCoreService, perms PermissionChecker) *CommunityCoreHandler {
    return &CommunityCoreHandler{svc: svc, perms: perms}
}

func (h *CommunityCoreHandler) CreateCommunity(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    var in service.CreateCommunityInput
    if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }

    // Enforce permissions only for restricted types: GOVERNMENT and NGO
    t := strings.ToUpper(strings.TrimSpace(in.Type))
    switch t {
    case "GOVERNMENT":
        allowed, err := h.perms.HasGlobalPermission(r.Context(), claims.UserContext.UserID, "community:create:government")
        if err != nil {
            http.Error(w, "permission check failed", http.StatusForbidden)
            return
        }
        if !allowed {
            http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
            return
        }
    case "NGO":
        allowed, err := h.perms.HasGlobalPermission(r.Context(), claims.UserContext.UserID, "community:create:ngo")
        if err != nil {
            http.Error(w, "permission check failed", http.StatusForbidden)
            return
        }
        if !allowed {
            http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
            return
        }
    }

    c, err := h.svc.CreateCommunity(r.Context(), claims.UserContext.UserID, in)
    if err != nil {
        if strings.HasPrefix(err.Error(), "conflict: community_name_conflict") {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusConflict)
            _ = json.NewEncoder(w).Encode(map[string]string{
                "error":   "community_name_conflict",
                "message": "Community name already exists",
            })
            return
        }
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(c)
}

func (h *CommunityCoreHandler) GetCommunity(w http.ResponseWriter, r *http.Request) {
    id, err := uuid.Parse(chi.URLParam(r, "communityID"))
    if err != nil {
        http.Error(w, "invalid communityID", http.StatusBadRequest)
        return
    }
    c, err := h.svc.GetCommunityByID(r.Context(), id)
    if err != nil {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(c)
}
func (h *CommunityCoreHandler) UpdateCommunity(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // Extract userID for logging (omitted for brevity)…

    // Parse communityID
    rawID := chi.URLParam(r, "communityID")
    id, err := uuid.Parse(rawID)
    if err != nil {
        logger.Errorf("invalid communityID: %s error=%v", rawID, err)
        http.Error(w, "invalid communityID", http.StatusBadRequest)
        return
    }

    // Decode input
    var in service.UpdateCommunityInput
    if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
        logger.Errorf("failed to decode payload: %v", err)
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    in.ID = id

    // Perform update
    if err := h.svc.UpdateCommunity(ctx, in); err != nil {
        logger.Errorf("update failed: communityID=%s error=%v", id, err)
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Prepare success response
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)

    json.NewEncoder(w).Encode(map[string]interface{}{
        "message":     "community updated successfully",
        "communityID": id,
    })
}
func (h *CommunityCoreHandler) ListByType(w http.ResponseWriter, r *http.Request) {
    t := r.URL.Query().Get("type")
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
    list, err := h.svc.ListByType(r.Context(), t, afterAtPtr, afterIDPtr, limit)
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

func (h *CommunityCoreHandler) ListUserCommunities(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
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
    list, err := h.svc.ListUserCommunities(r.Context(), claims.UserContext.UserID, afterAtPtr, afterIDPtr, limit)
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
