package middleware

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-auth/internal/services"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

// AuditMiddleware logs all API requests
func AuditMiddleware(auditService *services.AuditService, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip health check, static endpoints, and OPTIONS requests
		if c.Request.URL.Path == "/health" || c.Request.URL.Path == "/metrics" || c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		// Read and buffer request body (for logging)
		var requestBody map[string]interface{}
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			bodyBytes, _ := io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Reset body

			if len(bodyBytes) > 0 {
				_ = json.Unmarshal(bodyBytes, &requestBody)
			}
		}

		// Create a custom response writer to capture status code
		blw := &bodyLogWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
		c.Writer = blw

		// Process request
		c.Next()

		// Extract user context (may not exist for auth endpoints)
		var userID primitive.ObjectID
		var username, tenantID, source string

		if uid, exists := c.Get("user_id"); exists {
			userID = uid.(primitive.ObjectID)
		}
		if uname, exists := c.Get("username"); exists {
			username = uname.(string)
		}
		if tid, exists := c.Get("tenant_id"); exists {
			tenantID = tid.(string)
		}
		if src, exists := c.Get("source"); exists {
			source = src.(string)
		} else {
			source = ExtractSource(c)
		}

		// Determine action from method, path, and source
		action := determineAction(c.Request.Method, c.Request.URL.Path, source)
		resourceType := determineResourceType(c.Request.URL.Path)

		// Get error if any
		errorMsg := ""
		if len(c.Errors) > 0 {
			errorMsg = c.Errors.String()
		}

		// Log to audit service (async)
		go func() {
			err := auditService.LogAction(
				userID,
				username,
				tenantID,
				action,
				resourceType,
				"", // resource_id extracted from path if needed
				c.Request.Method,
				c.Request.URL.Path,
				requestBody,
				blw.statusCode,
				source,
				c.ClientIP(),
				c.Request.UserAgent(),
				errorMsg,
			)
			if err != nil {
				logger.Error("Failed to log audit", zap.Error(err))
			}
		}()

		// Verbose logging removed - all requests are already stored in audit_logs collection in DB
	}
}

// bodyLogWriter is a custom response writer that captures status code
type bodyLogWriter struct {
	gin.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func (w *bodyLogWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *bodyLogWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// determineAction determines the action type from method, path, and source
func determineAction(method, path, source string) string {
	// Auth endpoints
	if contains(path, "/auth/signup") {
		return "signup"
	}
	if contains(path, "/auth/login") {
		return "login"
	}
	if contains(path, "/auth/logout") {
		return "logout"
	}
	if contains(path, "/auth/verify-otp") {
		return "verify_otp"
	}
	// A personal API key has no server-side "login" of its own — a CLI login
	// is really just a whoami check that confirms the key works. Label it
	// "login" anyway (only for the CLI's own check, not the web UI's regular
	// profile-page reads) so it shows up meaningfully in the audit trail.
	if method == "GET" && contains(path, "/users/me") && source == "cli" {
		return "login"
	}

	// Terminal sessions
	if contains(path, "/terminal/") && contains(path, "/ws") {
		return "connect"
	}
	if contains(path, "/terminal/sessions") && method == "DELETE" {
		return "disconnect"
	}

	// CRUD operations
	switch method {
	case "POST":
		if contains(path, "/users") {
			return "create_user"
		}
		if contains(path, "/organizations") {
			return "create_organization"
		}
		if contains(path, "/groups") {
			return "create_group"
		}
		return "create"
	case "GET":
		return "read"
	case "PUT", "PATCH":
		if contains(path, "/users") {
			return "update_user"
		}
		return "update"
	case "DELETE":
		if contains(path, "/users") {
			return "delete_user"
		}
		return "delete"
	default:
		return method
	}
}

// determineResourceType determines the resource type from path
func determineResourceType(path string) string {
	if contains(path, "/auth") {
		return "auth"
	}
	if contains(path, "/users") {
		return "user"
	}
	if contains(path, "/organizations") {
		return "organization"
	}
	if contains(path, "/groups") {
		return "group"
	}
	if contains(path, "/machines") {
		return "machine"
	}
	if contains(path, "/terminal") {
		return "terminal"
	}
	if contains(path, "/audit") {
		return "audit"
	}
	return "unknown"
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstr(s, substr)
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
