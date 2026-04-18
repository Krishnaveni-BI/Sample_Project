package middleware

import (
	"context"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/shridarpatil/whatomate/internal/models"
	"github.com/valyala/fasthttp"
	"github.com/zerodha/fastglue"
	"github.com/zerodha/logf"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	ContextKeyUserID         = "user_id"
	ContextKeyOrganizationID = "organization_id"
	ContextKeyEmail          = "email"
	ContextKeyRoleID         = "role_id"
	ContextKeyIsSuperAdmin   = "is_super_admin"
	ContextKeyUser           = "user"
	ContextKeyOrganization   = "organization"
)

type JWTClaims struct {
	UserID         uuid.UUID  `json:"user_id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	Email          string     `json:"email"`
	RoleID         *uuid.UUID `json:"role_id,omitempty"`
	IsSuperAdmin   bool       `json:"is_super_admin"`
	jwt.RegisteredClaims
}

func RequestLogger(log logf.Logger) fastglue.FastMiddleware {
	return func(r *fastglue.Request) *fastglue.Request {
		start := time.Now()
		r.RequestCtx.SetUserValue("request_start", start)
		return r
	}
}

func ParseAllowedOrigins(allowedOrigins string) map[string]bool {
	origins := make(map[string]bool)
	for _, o := range strings.Split(allowedOrigins, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			origins[o] = true
		}
	}
	return origins
}

func IsOriginAllowed(origin string, allowedOrigins map[string]bool) bool {
	if len(allowedOrigins) == 0 {
		return true
	}
	return allowedOrigins[origin]
}

func CORS(allowedOrigins map[string]bool) fastglue.FastMiddleware {
	return func(r *fastglue.Request) *fastglue.Request {
		origin := string(r.RequestCtx.Request.Header.Peek("Origin"))

		if origin != "" && IsOriginAllowed(origin, allowedOrigins) {
			r.RequestCtx.Response.Header.Set("Access-Control-Allow-Origin", origin)
			r.RequestCtx.Response.Header.Set("Access-Control-Allow-Credentials", "true")
		} else if len(allowedOrigins) == 0 {
			if origin != "" {
				r.RequestCtx.Response.Header.Set("Access-Control-Allow-Origin", origin)
			}
		}

		r.RequestCtx.Response.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		r.RequestCtx.Response.Header.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Organization-ID, X-CSRF-Token")
		r.RequestCtx.Response.Header.Set("Access-Control-Max-Age", "86400")

		if string(r.RequestCtx.Method()) == "OPTIONS" {
			r.RequestCtx.SetStatusCode(fasthttp.StatusNoContent)
			r.RequestCtx.Response.Header.Set("Content-Length", "0")
			return nil
		}

		return r
	}
}

func SecurityHeaders() fastglue.FastMiddleware {
	return func(r *fastglue.Request) *fastglue.Request {
		h := &r.RequestCtx.Response.Header
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(self), geolocation=()")
		h.Set("X-XSS-Protection", "0")
		return r
	}
}

func Recovery(log logf.Logger) fastglue.FastMiddleware {
	return func(r *fastglue.Request) *fastglue.Request {
		defer func() {
			if err := recover(); err != nil {
				log.Error("Panic recovered", "error", err, "path", string(r.RequestCtx.Path()))
				r.RequestCtx.SetStatusCode(fasthttp.StatusInternalServerError)
				r.RequestCtx.SetBodyString(`{"status":"error","message":"Internal server error"}`)
			}
		}()
		return r
	}
}

func Auth(secret string) fastglue.FastMiddleware {
	return AuthWithDB(secret, nil)
}

func AuthWithDB(secret string, db *gorm.DB) fastglue.FastMiddleware {
	return func(r *fastglue.Request) *fastglue.Request {
		authHeader := string(r.RequestCtx.Request.Header.Peek("Authorization"))
		apiKey := string(r.RequestCtx.Request.Header.Peek("X-API-Key"))

		if apiKey != "" && db != nil {
			if validateAPIKey(r, apiKey, db) {
				return r
			}
			_ = r.SendErrorEnvelope(fasthttp.StatusUnauthorized, "Invalid API key", nil, "")
			return nil
		}

		var tokenString string

		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				_ = r.SendErrorEnvelope(fasthttp.StatusUnauthorized, "Invalid authorization header format", nil, "")
				return nil
			}
			tokenString = parts[1]
		} else {
			tokenString = string(r.RequestCtx.Request.Header.Cookie("whm_access"))
		}

		if tokenString == "" {
			_ = r.SendErrorEnvelope(fasthttp.StatusUnauthorized, "Missing authorization", nil, "")
			return nil
		}

		token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (any, error) {
			return []byte(secret), nil
		})

		if err != nil || !token.Valid {
			_ = r.SendErrorEnvelope(fasthttp.StatusUnauthorized, "Invalid or expired token", nil, "")
			return nil
		}

		claims, ok := token.Claims.(*JWTClaims)
		if !ok {
			_ = r.SendErrorEnvelope(fasthttp.StatusUnauthorized, "Invalid token claims", nil, "")
			return nil
		}

		r.RequestCtx.SetUserValue(ContextKeyUserID, claims.UserID)
		r.RequestCtx.SetUserValue(ContextKeyOrganizationID, claims.OrganizationID)
		r.RequestCtx.SetUserValue(ContextKeyEmail, claims.Email)
		if claims.RoleID != nil {
			r.RequestCtx.SetUserValue(ContextKeyRoleID, *claims.RoleID)
		}
		r.RequestCtx.SetUserValue(ContextKeyIsSuperAdmin, claims.IsSuperAdmin)

		return r
	}
}

func validateAPIKey(r *fastglue.Request, key string, db *gorm.DB) bool {
	if len(key) != 36 || key[:4] != "whm_" {
		return false
	}

	newPrefix := key[4:20]
	oldPrefix := key[4:12]

	var apiKeys []models.APIKey
	if err := db.Preload("User").Where("(key_prefix = ? OR key_prefix = ?) AND is_active = ?", newPrefix, oldPrefix, true).Find(&apiKeys).Error; err != nil {
		return false
	}

	for _, apiKey := range apiKeys {
		if err := bcrypt.CompareHashAndPassword([]byte(apiKey.KeyHash), []byte(key)); err == nil {
			if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
				return false
			}

			go func(id uuid.UUID) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				now := time.Now()
				db.WithContext(ctx).Model(&models.APIKey{}).Where("id = ?", id).Update("last_used_at", now)
			}(apiKey.ID)

			if apiKey.User != nil {
				r.RequestCtx.SetUserValue(ContextKeyUserID, apiKey.UserID)
				r.RequestCtx.SetUserValue(ContextKeyOrganizationID, apiKey.OrganizationID)
				r.RequestCtx.SetUserValue(ContextKeyEmail, apiKey.User.Email)
				if apiKey.User.RoleID != nil {
					r.RequestCtx.SetUserValue(ContextKeyRoleID, *apiKey.User.RoleID)
				}
				r.RequestCtx.SetUserValue(ContextKeyIsSuperAdmin, apiKey.User.IsSuperAdmin)
				return true
			}
		}
	}

	return false
}

func OrganizationContext(db *gorm.DB) fastglue.FastMiddleware {
	return func(r *fastglue.Request) *fastglue.Request {
		userID, ok := r.RequestCtx.UserValue(ContextKeyUserID).(uuid.UUID)
		if !ok {
			_ = r.SendErrorEnvelope(fasthttp.StatusUnauthorized, "User ID not found in context", nil, "")
			return nil
		}

		orgID, ok := r.RequestCtx.UserValue(ContextKeyOrganizationID).(uuid.UUID)
		if !ok {
			_ = r.SendErrorEnvelope(fasthttp.StatusUnauthorized, "Organization ID not found in context", nil, "")
			return nil
		}

		var user models.User
		if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
			_ = r.SendErrorEnvelope(fasthttp.StatusUnauthorized, "User not found", nil, "")
			return nil
		}

		if !user.IsActive {
			_ = r.SendErrorEnvelope(fasthttp.StatusUnauthorized, "Account is disabled", nil, "")
			return nil
		}

		var org models.Organization
		if err := db.Where("id = ?", orgID).First(&org).Error; err != nil {
			_ = r.SendErrorEnvelope(fasthttp.StatusUnauthorized, "Organization not found", nil, "")
			return nil
		}

		r.RequestCtx.SetUserValue(ContextKeyUser, &user)
		r.RequestCtx.SetUserValue(ContextKeyOrganization, &org)

		return r
	}
}

type PermissionChecker func(userID uuid.UUID, resource, action string) bool

func RequirePermission(checker PermissionChecker, resource, action string) fastglue.FastMiddleware {
	return func(r *fastglue.Request) *fastglue.Request {
		userID, ok := r.RequestCtx.UserValue(ContextKeyUserID).(uuid.UUID)
		if !ok {
			_ = r.SendErrorEnvelope(fasthttp.StatusUnauthorized, "User not authenticated", nil, "")
			return nil
		}

		if !checker(userID, resource, action) {
			_ = r.SendErrorEnvelope(fasthttp.StatusForbidden, "Insufficient permissions", nil, "")
			return nil
		}

		return r
	}
}

func RequireAnyPermission(checker PermissionChecker, permissions ...string) fastglue.FastMiddleware {
	return func(r *fastglue.Request) *fastglue.Request {
		userID, ok := r.RequestCtx.UserValue(ContextKeyUserID).(uuid.UUID)
		if !ok {
			_ = r.SendErrorEnvelope(fasthttp.StatusUnauthorized, "User not authenticated", nil, "")
			return nil
		}

		for _, perm := range permissions {
			parts := strings.Split(perm, ":")
			if len(parts) == 2 && checker(userID, parts[0], parts[1]) {
				return r
			}
		}

		_ = r.SendErrorEnvelope(fasthttp.StatusForbidden, "Insufficient permissions", nil, "")
		return nil
	}
}

func GetUserID(r *fastglue.Request) (uuid.UUID, bool) {
	userID, ok := r.RequestCtx.UserValue(ContextKeyUserID).(uuid.UUID)
	return userID, ok
}

func GetOrganizationID(r *fastglue.Request) (uuid.UUID, bool) {
	orgID, ok := r.RequestCtx.UserValue(ContextKeyOrganizationID).(uuid.UUID)
	return orgID, ok
}

func GetUser(r *fastglue.Request) (*models.User, bool) {
	user, ok := r.RequestCtx.UserValue(ContextKeyUser).(*models.User)
	return user, ok
}

func GetOrganization(r *fastglue.Request) (*models.Organization, bool) {
	org, ok := r.RequestCtx.UserValue(ContextKeyOrganization).(*models.Organization)
	return org, ok
}

func IsSuperAdmin(r *fastglue.Request) bool {
	isSuperAdmin, ok := r.RequestCtx.UserValue(ContextKeyIsSuperAdmin).(bool)
	return ok && isSuperAdmin
}
