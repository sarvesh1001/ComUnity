package handler

import (
    "encoding/json"
    "net/http"

    "github.com/ComUnity/auth-service/internal/service"
    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
)

type ChildProfileHandler struct {
    consent service.ConsentManager
}

func NewChildProfileHandler(cm service.ConsentManager) *ChildProfileHandler {
    return &ChildProfileHandler{consent: cm}
}

// POST /child/{childID}/request-consent/{parentID}
func (h *ChildProfileHandler) RequestConsent(w http.ResponseWriter, r *http.Request) {
    childIDStr := chi.URLParam(r, "childID")
    parentIDStr := chi.URLParam(r, "parentID")

    childID, err := uuid.Parse(childIDStr)
    if err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid childID")
        return
    }
    parentID, err := uuid.Parse(parentIDStr)
    if err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid parentID")
        return
    }

    if err := h.consent.RequestChildConsent(r.Context(), childID, parentID); err != nil {
        writeJSONError(w, http.StatusInternalServerError, err.Error())
        return
    }
    writeJSON(w, http.StatusOK, map[string]string{"status": "PENDING"})
}

// POST /child/consent/approve
func (h *ChildProfileHandler) ApproveConsent(w http.ResponseWriter, r *http.Request) {
    var input struct {
        ConsentID uuid.UUID `json:"consent_id"`
        ParentID  uuid.UUID `json:"parent_id"`
    }

    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid body")
        return
    }
    if err := h.consent.ApproveConsent(r.Context(), input.ParentID, input.ConsentID); err != nil {
        writeJSONError(w, http.StatusForbidden, err.Error())
        return
    }
    writeJSON(w, http.StatusOK, map[string]string{"status": "APPROVED"})
}

// GET /child/{childID}/consent
func (h *ChildProfileHandler) CheckConsent(w http.ResponseWriter, r *http.Request) {
    childIDStr := chi.URLParam(r, "childID")
    childID, err := uuid.Parse(childIDStr)
    if err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid childID")
        return
    }

    ok, err := h.consent.CheckConsent(r.Context(), childID)
    if err != nil {
        writeJSONError(w, http.StatusInternalServerError, err.Error())
        return
    }
    writeJSON(w, http.StatusOK, map[string]bool{"approved": ok})
}
