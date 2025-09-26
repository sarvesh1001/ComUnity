package middleware

import (
    "encoding/json"
    "net/http"

    "github.com/ComUnity/auth-service/internal/util"
)

func RequireSetupCompleted(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims, ok := r.Context().Value("jwt_claims").(*util.AuthzClaims)
        if !ok {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        if !claims.UserContext.SetupCompleted {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusPreconditionRequired) // 428
            json.NewEncoder(w).Encode(map[string]interface{}{
                "error": "setup_required",
                "message": "Profile setup must be completed before accessing this feature",
                "setup_completed": false,
            })
            return
        }

        next.ServeHTTP(w, r)
    })
}
