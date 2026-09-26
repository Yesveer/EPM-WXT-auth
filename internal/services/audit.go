package services

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-auth/internal/database"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

// AuditService handles audit logging
type AuditService struct {
	store  *database.Store
	logger *zap.Logger
}

func NewAuditService(store *database.Store, logger *zap.Logger) *AuditService {
	return &AuditService{
		store:  store,
		logger: logger,
	}
}

// LogAction logs an audit event
func (a *AuditService) LogAction(
	userID primitive.ObjectID,
	username string,
	tenantID string,
	action string,
	resourceType string,
	resourceID string,
	method string,
	endpoint string,
	requestBody map[string]interface{},
	responseStatus int,
	source string,
	ipAddress string,
	userAgent string,
	errorMsg string,
) error {
	log := &database.AuditLog{
		UserID:         userID,
		Username:       username,
		TenantID:       tenantID,
		Action:         action,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		Method:         method,
		Endpoint:       endpoint,
		RequestBody:    a.sanitizeRequestBody(requestBody),
		ResponseStatus: responseStatus,
		Source:         source,
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
		Error:          errorMsg,
	}

	if err := a.store.CreateAuditLog(log); err != nil {
		a.logger.Error("Failed to create audit log",
			zap.Error(err),
			zap.String("action", action),
			zap.String("username", username))
		return err
	}

	// Only log errors and important actions (not every request)
	if responseStatus >= 400 || action == "signup" || action == "login" || action == "delete_user" {
		a.logger.Debug("Audit log created",
			zap.String("action", action),
			zap.String("username", username),
			zap.String("source", source),
			zap.Int("status", responseStatus))
	}

	return nil
}

// LogFromContext logs an audit event from Gin context
func (a *AuditService) LogFromContext(
	c *gin.Context,
	action string,
	resourceType string,
	resourceID string,
	responseStatus int,
	errorMsg string,
) error {
	// Extract user info from context
	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")
	tenantID, _ := c.Get("tenant_id")
	source, _ := c.Get("source")

	// Parse request body
	var requestBody map[string]interface{}
	if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
		if err := c.ShouldBindJSON(&requestBody); err == nil {
			// Successfully parsed
		}
	}

	return a.LogAction(
		userID.(primitive.ObjectID),
		username.(string),
		tenantID.(string),
		action,
		resourceType,
		resourceID,
		c.Request.Method,
		c.Request.URL.Path,
		requestBody,
		responseStatus,
		source.(string),
		c.ClientIP(),
		c.Request.UserAgent(),
		errorMsg,
	)
}

// sanitizeRequestBody removes sensitive fields from request body
func (a *AuditService) sanitizeRequestBody(body map[string]interface{}) map[string]interface{} {
	if body == nil {
		return nil
	}

	// Create a copy to avoid modifying original
	sanitized := make(map[string]interface{})
	for k, v := range body {
		sanitized[k] = v
	}

	// Remove sensitive fields
	sensitiveFields := []string{
		"password",
		"confirm_password",
		"current_password",
		"new_password",
		"api_key",
		"secret",
		"token",
		"otp",
		"otp_code",
	}

	for _, field := range sensitiveFields {
		if _, exists := sanitized[field]; exists {
			sanitized[field] = "[REDACTED]"
		}
	}

	return sanitized
}

// GetUserAuditLogs retrieves audit logs for a user
func (a *AuditService) GetUserAuditLogs(userID primitive.ObjectID, limit int) ([]*database.AuditLog, error) {
	return a.store.GetAuditLogsByUser(userID, limit)
}

// GetTenantAuditLogs retrieves audit logs for a tenant
func (a *AuditService) GetTenantAuditLogs(tenantID string, limit int) ([]*database.AuditLog, error) {
	return a.store.GetAuditLogsByTenant(tenantID, limit)
}

// GetAuditLogsByAction retrieves audit logs by action type
func (a *AuditService) GetAuditLogsByAction(action string, limit int) ([]*database.AuditLog, error) {
	return a.store.GetAuditLogsByAction(action, limit)
}

// LogAuthEvent logs authentication-related events (signup, login, logout)
func (a *AuditService) LogAuthEvent(
	username string,
	tenantID string,
	action string, // "signup", "login", "logout", "otp_sent", "otp_verified"
	source string,
	ipAddress string,
	userAgent string,
	success bool,
	errorMsg string,
) error {
	status := 200
	if !success {
		status = 401
	}

	// For auth events, we might not have userID yet (signup case)
	log := &database.AuditLog{
		Username:       username,
		TenantID:       tenantID,
		Action:         action,
		ResourceType:   "auth",
		Method:         "POST",
		Endpoint:       "/api/auth/" + action,
		ResponseStatus: status,
		Source:         source,
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
		Error:          errorMsg,
	}

	if err := a.store.CreateAuditLog(log); err != nil {
		a.logger.Error("Failed to create auth audit log",
			zap.Error(err),
			zap.String("action", action),
			zap.String("username", username))
		return err
	}

	return nil
}

// ParseBrowser extracts browser info from user agent
func ParseBrowser(userAgent string) string {
	// Simple browser detection
	browsers := map[string]string{
		"Chrome":  "Chrome",
		"Firefox": "Firefox",
		"Safari":  "Safari",
		"Edge":    "Edge",
		"Opera":   "Opera",
	}

	for key, name := range browsers {
		if contains(userAgent, key) {
			return name
		}
	}
	return "Unknown"
}

// ParseOS extracts OS info from user agent
func ParseOS(userAgent string) string {
	// Simple OS detection
	oses := map[string]string{
		"Windows": "Windows",
		"Mac":     "macOS",
		"Linux":   "Linux",
		"Android": "Android",
		"iOS":     "iOS",
	}

	for key, name := range oses {
		if contains(userAgent, key) {
			return name
		}
	}
	return "Unknown"
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findSubstr(s, substr))
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// MarshalJSON is a helper to convert audit log to JSON
func (a *AuditService) MarshalJSON(log *database.AuditLog) ([]byte, error) {
	return json.Marshal(log)
}
