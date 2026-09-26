package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-auth/internal/database"
	"go.uber.org/zap"
)

type AuditHandler struct {
	store  *database.Store
	logger *zap.Logger
}

func NewAuditHandler(store *database.Store, logger *zap.Logger) *AuditHandler {
	return &AuditHandler{store: store, logger: logger}
}

// GetLogs returns paginated audit logs.
// - super_admin: ?tenant_id=xxx filters by tenant; omit for all tenants
// - company_admin: always scoped to their own tenant
// Query params: page (1-based), limit (rows per page)
func (h *AuditHandler) GetLogs(c *gin.Context) {
	role, _ := c.Get("role")
	callerTenantID, _ := c.Get("tenant_id")

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 200 {
		limit = 25
	}
	skip := (page - 1) * limit

	// Determine the tenant filter
	tenantID := ""
	if role == database.RoleSuperAdmin {
		tenantID = c.Query("tenant_id") // empty = all tenants
	} else {
		tenantID = callerTenantID.(string)
	}

	total, err := h.store.CountAuditLogs(tenantID)
	if err != nil {
		h.logger.Error("Failed to count audit logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count audit logs"})
		return
	}

	logs, err := h.store.GetAuditLogsByTenantPaged(tenantID, limit, skip)
	if err != nil {
		h.logger.Error("Failed to fetch audit logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch audit logs"})
		return
	}

	if logs == nil {
		logs = []*database.AuditLog{}
	}

	totalPages := int(total) / limit
	if int(total)%limit != 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":        logs,
		"total":       total,
		"page":        page,
		"limit":       limit,
		"total_pages": totalPages,
	})
}

// GetTenants returns all tenants for the super admin tenant picker.
func (h *AuditHandler) GetTenants(c *gin.Context) {
	orgs, err := h.store.ListOrganizations()
	if err != nil {
		h.logger.Error("Failed to list organizations", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tenants"})
		return
	}

	type tenantItem struct {
		TenantID   string `json:"tenant_id"`
		TenantName string `json:"tenant_name"`
	}
	result := make([]tenantItem, 0, len(orgs))
	for _, org := range orgs {
		name := org.DisplayName
		if name == "" {
			name = org.Name // fallback if display_name is empty
		}
		result = append(result, tenantItem{
			TenantID:   org.KeycloakRealm,
			TenantName: name,
		})
	}
	c.JSON(http.StatusOK, gin.H{"tenants": result})
}

// RegisterAuditRoutes registers audit log routes (company_admin + super_admin).
func RegisterAuditRoutes(r *gin.RouterGroup, handler *AuditHandler, authMW, adminMW gin.HandlerFunc) {
	audit := r.Group("/audit-logs")
	audit.Use(authMW, adminMW)
	{
		audit.GET("", handler.GetLogs)
		audit.GET("/tenants", handler.GetTenants)
	}
}
