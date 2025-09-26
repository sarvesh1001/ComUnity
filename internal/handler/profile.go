package handler

import (
    "context"
    "encoding/json"
    "net/http"
    "strings"
    "time"

    "github.com/ComUnity/auth-service/internal/repository"
    "github.com/ComUnity/auth-service/internal/util"
    "github.com/ComUnity/auth-service/internal/util/logger"
)

// Handler type
type ProfileHandler struct {
    userRepo   repository.UserRepository
    jwtManager *util.JWTManager
}

func NewProfileHandler(userRepo repository.UserRepository, jwtManager *util.JWTManager) *ProfileHandler {
    return &ProfileHandler{userRepo: userRepo, jwtManager: jwtManager}
}

// DTOs
type ProfileSetupRequest struct {
    Username         string   `json:"username"`
    DisplayName      string   `json:"display_name"`
    Languages        []string `json:"languages"` // required array of allowed codes
    PublicVisibility *bool    `json:"public_visibility,omitempty"`
}

type ProfileStatusResponse struct {
    SetupCompleted     bool     `json:"setup_completed"`
    Username           *string  `json:"username,omitempty"`
    DisplayName        *string  `json:"display_name,omitempty"`
    PreferredLanguages []string `json:"preferred_languages"`  // array only
    VerificationStatus string   `json:"verification_status"`
    PhoneNumber        string   `json:"phone_number"`
    PublicVisibility   bool     `json:"public_visibility"`
    NeedsSetup         bool     `json:"needs_setup"`
}

// GET /auth/profile/status
func (h *ProfileHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        h.writeError(w, http.StatusUnauthorized, "Unauthorized")
        return
    }

    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()

    user, err := h.userRepo.GetByID(ctx, claims.UserContext.UserID)
    if err != nil || user == nil {
        h.writeError(w, http.StatusNotFound, "User not found")
        return
    }

    // After fetching user in GetStatus
    langs := user.PreferredLanguages
    if len(langs) == 0 {
        // Ensure at least one sensible value if legacy rows exist
        langs = []string{"en"}
    }

    resp := ProfileStatusResponse{
        SetupCompleted:     user.SetupCompleted,
        Username:           user.Username,
        DisplayName:        user.DisplayName,
        PreferredLanguages: langs,
        VerificationStatus: user.VerificationStatus,
        PhoneNumber:        user.PhoneNumber,
        PublicVisibility:   user.PublicVisibility,
        NeedsSetup:         !user.SetupCompleted,
    }

    h.writeJSON(w, http.StatusOK, resp)
}

// POST /auth/profile/setup
func (h *ProfileHandler) Setup(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
    if !ok {
        h.writeError(w, http.StatusUnauthorized, "Unauthorized")
        return
    }

    var req ProfileSetupRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.writeError(w, http.StatusBadRequest, "Invalid request")
        return
    }

    // Normalize and validate
    uname := normalizeUsername(req.Username)
    if uname == "" || !isValidUsername(uname) {
        h.writeError(w, http.StatusBadRequest, "Invalid username")
        return
    }
    disp := strings.TrimSpace(req.DisplayName)
    if len([]rune(disp)) < 2 || len([]rune(disp)) > 50 {
        h.writeError(w, http.StatusBadRequest, "Invalid display name")
        return
    }
    langs, okLangs := normalizeLanguagesOnlyArray(req.Languages)
    if !okLangs {
        h.writeError(w, http.StatusBadRequest, "Invalid languages")
        return
    }
    pubVis := false
    if req.PublicVisibility != nil {
        pubVis = *req.PublicVisibility
    }

    ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
    defer cancel()

    // Load current user
    user, err := h.userRepo.GetByID(ctx, claims.UserContext.UserID)
    if err != nil || user == nil {
        h.writeError(w, http.StatusNotFound, "User not found")
        return
    }
    if user.SetupCompleted {
        h.writeError(w, http.StatusConflict, "Profile setup already completed")
        return
    }

    // Enforce username uniqueness
    if existing, _ := h.userRepo.GetByUsername(ctx, uname); existing != nil && existing.ID != user.ID {
        h.writeError(w, http.StatusConflict, "Username already taken")
        return
    }

    // Always set verification_status to "NONE"
    vs := "NONE"

    // Build updates preserving repository’s expected fields; array-only languages
    updates := map[string]interface{}{
        "phone_number":        user.PhoneNumber,
        "username":            uname,
        "phone_verified":      user.PhoneVerified,
        "public_visibility":   pubVis,
        "last_login_at":       user.LastLoginAt,
        "primary_device_id":   user.PrimaryDeviceID,
        "verification_status": vs,

        "display_name":         disp,
        "preferred_languages":  langs,   // array only; repo wraps pq.Array
        "setup_completed":      true,
        "updated_at":           time.Now(),
    }

    if err := h.userRepo.UpdateUser(ctx, user.ID, updates); err != nil {
        logger.Errorf("Failed to update user profile: %v", err)
        h.writeError(w, http.StatusInternalServerError, "Failed to update profile")
        return
    }

    // Re-read saved row to return persisted values
    saved, err := h.userRepo.GetByID(ctx, user.ID)
    if err != nil || saved == nil {
        h.writeError(w, http.StatusInternalServerError, "Failed to load updated profile")
        return
    }
    respLangs := saved.PreferredLanguages
    if len(respLangs) == 0 {
        respLangs = langs
    }

    h.writeJSON(w, http.StatusOK, map[string]interface{}{
        "message":             "Profile setup completed successfully",
        "setup_completed":     saved.SetupCompleted,
        "username":            uname,
        "display_name":        disp,
        "preferred_languages": respLangs,
        "public_visibility":   pubVis,
        "verification_status": saved.VerificationStatus,
        "needs_token_refresh": true,
    })
}

// helpers
func (h *ProfileHandler) writeJSON(w http.ResponseWriter, status int, v interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    _ = json.NewEncoder(w).Encode(v)
}
func (h *ProfileHandler) writeError(w http.ResponseWriter, status int, msg string) {
    h.writeJSON(w, status, map[string]string{"error": msg})
}

func normalizeUsername(s string) string {
    s = strings.TrimSpace(strings.ToLower(s))
    return s
}
func isValidUsername(s string) bool {
    if len(s) < 3 || len(s) > 30 {
        return false
    }
    for _, r := range s {
        if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '.' {
            continue
        }
        return false
    }
    if s[0] == '.' || s[0] == '_' || s[len(s)-1] == '.' || s[len(s)-1] == '_' {
        return false
    }
    return true
}
func isValidLanguage(lang string) bool {
    switch lang {
    case "hi", "en", "ta", "te", "bn", "mr", "gu", "kn", "ml", "or", "pa", "as":
        return true
    default:
        return false
    }
}
func normalizeLanguagesOnlyArray(in []string) ([]string, bool) {
    if len(in) == 0 {
        return nil, false
    }
    seen := make(map[string]struct{}, len(in))
    out := make([]string, 0, len(in))
    for _, v := range in {
        lang := strings.ToLower(strings.TrimSpace(v))
        if !isValidLanguage(lang) {
            return nil, false
        }
        if _, ok := seen[lang]; ok {
            continue
        }
        seen[lang] = struct{}{}
        out = append(out, lang)
        if len(out) == 3 { // cap at 3
            break
        }
    }
    if len(out) == 0 {
        return nil, false
    }
    return out, true
}
