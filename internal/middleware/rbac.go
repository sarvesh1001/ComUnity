package middleware

import (
	"context"
	"net/http"

	"github.com/ComUnity/auth-service/internal/models"
	"github.com/ComUnity/auth-service/internal/service"

	"github.com/google/uuid"
	"github.com/go-chi/chi/v5"
)

type contextKey string

const (
	ContextUserID     contextKey = "userID"
	ContextCommunityID contextKey = "communityID"
	ContextAuthzInfo  contextKey = "authzInfo"
)

// RBAC middleware checks for specific permissions
func RBAC(requiredPermission string, roleService service.RoleService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			
			// Get user ID from context (set by auth middleware)
			userIDVal := ctx.Value(ContextUserID)
			if userIDVal == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			
			userID, ok := userIDVal.(uuid.UUID)
			if !ok {
				http.Error(w, "Invalid user ID", http.StatusUnauthorized)
				return
			}
			
			// Extract authorization context from request
			authzCtx := extractAuthzContext(r)
			
			// Check permission with full context
			hasPermission, err := roleService.HasPermission(ctx, userID, requiredPermission, authzCtx)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			
			if !hasPermission {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			
			// Inject authorization context for downstream handlers
			ctx = context.WithValue(ctx, ContextAuthzInfo, authzCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractAuthzContext extracts all authorization context from the request
func extractAuthzContext(r *http.Request) *models.AuthzContext {
	authzCtx := &models.AuthzContext{
		Attributes: make(map[string]interface{}),
	}
	
	// Extract from URL parameters (using chi router)
	if commIDStr := chi.URLParam(r, "communityID"); commIDStr != "" {
		if communityID, err := uuid.Parse(commIDStr); err == nil {
			authzCtx.CommunityID = communityID
		}
	}
	
	if subScopeIDStr := chi.URLParam(r, "subScopeID"); subScopeIDStr != "" {
		if subScopeID, err := uuid.Parse(subScopeIDStr); err == nil {
			authzCtx.SubScopeID = &subScopeID
		}
	}
	
	if resourceIDStr := chi.URLParam(r, "resourceID"); resourceIDStr != "" {
		if resourceID, err := uuid.Parse(resourceIDStr); err == nil {
			authzCtx.ResourceID = &resourceID
		}
	}
	
	// Extract from query parameters
	if ownerIDStr := r.URL.Query().Get("ownerID"); ownerIDStr != "" {
		if ownerID, err := uuid.Parse(ownerIDStr); err == nil {
			authzCtx.ResourceOwnerID = &ownerID
		}
	}
	
	// Extract from headers
	if channelType := r.Header.Get("X-Channel-Type"); channelType != "" {
		authzCtx.Attributes["channel_type"] = channelType
	}
	
	if verificationLevel := r.Header.Get("X-Verification-Level"); verificationLevel != "" {
		authzCtx.Attributes["verification_level"] = verificationLevel
	}
	
	return authzCtx
}

// CommunityContext middleware extracts community ID from URL and adds to context
func CommunityContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if commIDStr := chi.URLParam(r, "communityID"); commIDStr != "" {
			if communityID, err := uuid.Parse(commIDStr); err == nil {
				ctx := context.WithValue(r.Context(), ContextCommunityID, communityID)
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// AuthzContextFromRequest extracts the authorization context from the request context
func AuthzContextFromRequest(r *http.Request) *models.AuthzContext {
	if authzCtx, ok := r.Context().Value(ContextAuthzInfo).(*models.AuthzContext); ok {
		return authzCtx
	}
	return &models.AuthzContext{}
}

// AuthenticationMiddleware extracts user from JWT/session and adds to context
func AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract user ID from JWT token, session, or other auth mechanism
		// For now, we'll use a placeholder implementation
		
		// In a real implementation, you would:
		// 1. Extract JWT from Authorization header
		// 2. Validate the token
		// 3. Extract user ID from token claims
		// 4. Add user ID to context
		
		// Placeholder: extract from X-User-ID header for testing
		userIDStr := r.Header.Get("X-User-ID")
		if userIDStr == "" {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusUnauthorized)
			return
		}
		
		// Add user ID to context
		ctx := context.WithValue(r.Context(), ContextUserID, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ValidationMiddleware validates request bodies
func ValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add request validation logic here if needed
		// For now, just pass through
		next.ServeHTTP(w, r)
	})
}
