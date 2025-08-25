package handler

import (
    "encoding/json"
    "net/http"
    "strings"
    "time"

    "github.com/ComUnity/auth-service/internal/models"
    "github.com/ComUnity/auth-service/internal/middleware"
    "github.com/ComUnity/auth-service/internal/service"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
)

// RoleHandler handles RBAC operations
type RoleHandler struct {
    roleService service.RoleService
}

func NewRoleHandler(roleService service.RoleService) *RoleHandler {
    return &RoleHandler{
        roleService: roleService,
    }
}

// CreateRoleRequest combines role properties and permissions in a single struct
type CreateRoleRequest struct {
    Name          string     `json:"name"`
    Description   string     `json:"description"`
    CommunityType string     `json:"communityType"`
    CommunityID   *uuid.UUID `json:"communityId"`
    Permissions   []string   `json:"permissions"`
}

func (h *RoleHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
    var req CreateRoleRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid request body")
        return
    }

    createdBy, ok := r.Context().Value(middleware.ContextUserID).(uuid.UUID)
    if !ok {
        writeJSONError(w, http.StatusUnauthorized, "unauthorized")
        return
    }

    role := &models.Role{
        Name:          req.Name,
        Description:   req.Description,
        CommunityType: req.CommunityType,
        CommunityID:   req.CommunityID,
        IsCustom:      true,
    }

    if err := h.roleService.CreateRole(r.Context(), role, req.Permissions, createdBy); err != nil {
        writeJSONError(w, http.StatusInternalServerError, err.Error())
        return
    }

    writeJSON(w, http.StatusCreated, role)
}

// AssignRoleRequest includes all assignment parameters
type AssignRoleRequest struct {
    UserID      uuid.UUID  `json:"userId"`
    RoleID      uuid.UUID  `json:"roleId"`
    CommunityID uuid.UUID  `json:"communityId"`
    SubScopeID  *uuid.UUID `json:"subScopeId"`
    ExpiresAt   *time.Time `json:"expiresAt"`
    NotBefore   *time.Time `json:"notBefore"`
}

func (h *RoleHandler) AssignRole(w http.ResponseWriter, r *http.Request) {
    var req AssignRoleRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid request body")
        return
    }

    assignedBy, ok := r.Context().Value(middleware.ContextUserID).(uuid.UUID)
    if !ok {
        writeJSONError(w, http.StatusUnauthorized, "unauthorized")
        return
    }

    authzCtx := &models.AuthzContext{
        CommunityID: req.CommunityID,
        SubScopeID:  req.SubScopeID,
    }

    if err := h.roleService.AssignRole(r.Context(), req.UserID, req.RoleID, authzCtx, assignedBy, req.ExpiresAt, req.NotBefore); err != nil {
        if strings.Contains(err.Error(), "permission") {
            writeJSONError(w, http.StatusForbidden, err.Error())
        } else if strings.Contains(err.Error(), "already has") {
            writeJSONError(w, http.StatusConflict, err.Error())
        } else {
            writeJSONError(w, http.StatusInternalServerError, err.Error())
        }
        return
    }

    writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (h *RoleHandler) GetUserPermissions(w http.ResponseWriter, r *http.Request) {
    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid user ID")
        return
    }

    communityIDStr := chi.URLParam(r, "communityID")
    communityID, err := uuid.Parse(communityIDStr)
    if err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid community ID")
        return
    }

    var subScopeID *uuid.UUID
    if subScopeIDStr := r.URL.Query().Get("subScopeID"); subScopeIDStr != "" {
        if parsedID, err := uuid.Parse(subScopeIDStr); err == nil {
            subScopeID = &parsedID
        }
    }

    authzCtx := &models.AuthzContext{
        CommunityID: communityID,
        SubScopeID:  subScopeID,
    }

    permissions, err := h.roleService.GetUserPermissions(r.Context(), userID, authzCtx)
    if err != nil {
        writeJSONError(w, http.StatusInternalServerError, err.Error())
        return
    }

    writeJSON(w, http.StatusOK, permissions)
}

func (h *RoleHandler) GetUserRoles(w http.ResponseWriter, r *http.Request) {
    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid user ID")
        return
    }

    communityIDStr := chi.URLParam(r, "communityID")
    communityID, err := uuid.Parse(communityIDStr)
    if err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid community ID")
        return
    }

    authzCtx := &models.AuthzContext{
        CommunityID: communityID,
    }

    roles, err := h.roleService.GetUserRoles(r.Context(), userID, authzCtx)
    if err != nil {
        writeJSONError(w, http.StatusInternalServerError, err.Error())
        return
    }

    writeJSON(w, http.StatusOK, roles)
}

func (h *RoleHandler) GetCommunityRoles(w http.ResponseWriter, r *http.Request) {
    communityIDStr := chi.URLParam(r, "communityID")
    communityID, err := uuid.Parse(communityIDStr)
    if err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid community ID")
        return
    }

    roles, err := h.roleService.GetCommunityRoles(r.Context(), communityID)
    if err != nil {
        writeJSONError(w, http.StatusInternalServerError, err.Error())
        return
    }

    writeJSON(w, http.StatusOK, roles)
}

// RemoveRoleRequest includes removal parameters
type RemoveRoleRequest struct {
    UserID      uuid.UUID `json:"userId"`
    RoleID      uuid.UUID `json:"roleId"`
    CommunityID uuid.UUID `json:"communityId"`
}

func (h *RoleHandler) RemoveRole(w http.ResponseWriter, r *http.Request) {
    var req RemoveRoleRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid request body")
        return
    }

    removedBy, ok := r.Context().Value(middleware.ContextUserID).(uuid.UUID)
    if !ok {
        writeJSONError(w, http.StatusUnauthorized, "unauthorized")
        return
    }

    authzCtx := &models.AuthzContext{
        CommunityID: req.CommunityID,
    }

    if err := h.roleService.RemoveRole(r.Context(), req.UserID, req.RoleID, authzCtx, removedBy); err != nil {
        writeJSONError(w, http.StatusForbidden, err.Error())
        return
    }

    writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (h *RoleHandler) GetRolePermissions(w http.ResponseWriter, r *http.Request) {
    roleIDStr := chi.URLParam(r, "roleID")
    roleID, err := uuid.Parse(roleIDStr)
    if err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid role ID")
        return
    }

    permissions, err := h.roleService.GetRolePermissions(r.Context(), roleID)
    if err != nil {
        writeJSONError(w, http.StatusInternalServerError, err.Error())
        return
    }

    writeJSON(w, http.StatusOK, permissions)
}

// BlockUserRequest includes blocking parameters
type BlockUserRequest struct {
    BlockedUserID uuid.UUID  `json:"blockedUserId"`
    CommunityID   uuid.UUID  `json:"communityId"` // Use uuid.Nil for global blocks
    BlockType     string     `json:"blockType"`   // FULL, POST, MESSAGE, etc.
    Reason        string     `json:"reason"`
    ExpiresAt     *time.Time `json:"expiresAt"` // nil for permanent blocks
}

func (h *RoleHandler) BlockUser(w http.ResponseWriter, r *http.Request) {
    var req BlockUserRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid request body")
        return
    }

    blockerID, ok := r.Context().Value(middleware.ContextUserID).(uuid.UUID)
    if !ok {
        writeJSONError(w, http.StatusUnauthorized, "unauthorized")
        return
    }

    authzCtx := &models.AuthzContext{
        CommunityID: req.CommunityID,
    }

    if err := h.roleService.BlockUser(r.Context(), blockerID, req.BlockedUserID, authzCtx, req.BlockType, req.Reason, req.ExpiresAt); err != nil {
        if strings.Contains(err.Error(), "permission") {
            writeJSONError(w, http.StatusForbidden, err.Error())
        } else if strings.Contains(err.Error(), "already blocked") {
            writeJSONError(w, http.StatusConflict, err.Error())
        } else {
            writeJSONError(w, http.StatusInternalServerError, err.Error())
        }
        return
    }

    writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

// UnblockUserRequest includes unblocking parameters
type UnblockUserRequest struct {
    BlockID uuid.UUID `json:"blockId"`
}

func (h *RoleHandler) UnblockUser(w http.ResponseWriter, r *http.Request) {
    var req UnblockUserRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid request body")
        return
    }

    unblockerID, ok := r.Context().Value(middleware.ContextUserID).(uuid.UUID)
    if !ok {
        writeJSONError(w, http.StatusUnauthorized, "unauthorized")
        return
    }

    if err := h.roleService.UnblockUser(r.Context(), unblockerID, req.BlockID); err != nil {
        if strings.Contains(err.Error(), "permission") {
            writeJSONError(w, http.StatusForbidden, err.Error())
        } else {
            writeJSONError(w, http.StatusInternalServerError, err.Error())
        }
        return
    }

    writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

// ReportUserRequest includes reporting parameters
type ReportUserRequest struct {
    ReportedUserID uuid.UUID  `json:"reportedUserId"`
    CommunityID    uuid.UUID  `json:"communityId"` // Use uuid.Nil for global reports
    ContentID      *uuid.UUID `json:"contentId"`
    ContentType    string     `json:"contentType"` // POST, MESSAGE, COMMENT, PROFILE
    Reason         string     `json:"reason"`
    Category       string     `json:"category"` // SPAM, HARASSMENT, INAPPROPRIATE, etc.
}

func (h *RoleHandler) ReportUser(w http.ResponseWriter, r *http.Request) {
    var req ReportUserRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid request body")
        return
    }

    reporterID, ok := r.Context().Value(middleware.ContextUserID).(uuid.UUID)
    if !ok {
        writeJSONError(w, http.StatusUnauthorized, "unauthorized")
        return
    }

    authzCtx := &models.AuthzContext{
        CommunityID: req.CommunityID,
    }

    if err := h.roleService.ReportUser(r.Context(), reporterID, req.ReportedUserID, authzCtx, req.ContentID, req.ContentType, req.Reason, req.Category); err != nil {
        if strings.Contains(err.Error(), "permission") {
            writeJSONError(w, http.StatusForbidden, err.Error())
        } else {
            writeJSONError(w, http.StatusInternalServerError, err.Error())
        }
        return
    }

    writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (h *RoleHandler) GetUserBlocks(w http.ResponseWriter, r *http.Request) {
    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid user ID")
        return
    }

    blocks, err := h.roleService.GetUserBlocks(r.Context(), userID)
    if err != nil {
        writeJSONError(w, http.StatusInternalServerError, err.Error())
        return
    }

    writeJSON(w, http.StatusOK, blocks)
}

func (h *RoleHandler) GetUserReports(w http.ResponseWriter, r *http.Request) {
    userIDStr := chi.URLParam(r, "userID")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid user ID")
        return
    }

    reports, err := h.roleService.GetUserReports(r.Context(), userID)
    if err != nil {
        writeJSONError(w, http.StatusInternalServerError, err.Error())
        return
    }

    writeJSON(w, http.StatusOK, reports)
}
