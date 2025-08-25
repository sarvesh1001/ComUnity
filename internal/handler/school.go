package handler

import (
    "encoding/json"
    "net/http"

    "github.com/ComUnity/auth-service/internal/service"
    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
)

type SchoolHandler struct {
    validator service.SchoolValidator
}

func NewSchoolHandler(validator service.SchoolValidator) *SchoolHandler {
    return &SchoolHandler{validator: validator}
}

// POST /school/register
func (h *SchoolHandler) RegisterSchool(w http.ResponseWriter, r *http.Request) {
    var input struct {
        Name string `json:"name"`
        Paid bool   `json:"paid"`
    }
    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid request body")
        return
    }

    school, err := h.validator.RegisterSchool(r.Context(), input.Name, input.Paid)
    if err != nil {
        writeJSONError(w, http.StatusInternalServerError, err.Error())
        return
    }
    writeJSON(w, http.StatusOK, school)
}

// POST /school/{id}/validate
func (h *SchoolHandler) ValidateSchool(w http.ResponseWriter, r *http.Request) {
    idStr := chi.URLParam(r, "id")
    schoolID, err := uuid.Parse(idStr)
    if err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid school ID")
        return
    }

    // Assuming the caller is authorized staff (add auth middleware)
    if err := h.validator.ValidateSchool(r.Context(), schoolID); err != nil {
        writeJSONError(w, http.StatusInternalServerError, err.Error())
        return
    }

    writeJSON(w, http.StatusOK, map[string]string{"status": "validated"})
}

// GET /school/{id}/status
func (h *SchoolHandler) GetSchoolStatus(w http.ResponseWriter, r *http.Request) {
    idStr := chi.URLParam(r, "id")
    schoolID, err := uuid.Parse(idStr)
    if err != nil {
        writeJSONError(w, http.StatusBadRequest, "invalid school ID")
        return
    }

    valid, err := h.validator.IsSchoolValid(r.Context(), schoolID)
    if err != nil {
        writeJSONError(w, http.StatusInternalServerError, err.Error())
        return
    }

    writeJSON(w, http.StatusOK, map[string]bool{"valid": valid})
}
