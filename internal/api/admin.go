package api

import (
	"math"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-auth/internal/database"
	"github.com/vsay/vsay-auth/internal/keycloak"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

type AdminHandler struct {
	store  *database.Store
	kc     *keycloak.Client
	logger *zap.Logger
}

func NewAdminHandler(
	store *database.Store,
	kc *keycloak.Client,
	logger *zap.Logger,
) *AdminHandler {
	return &AdminHandler{
		store:  store,
		kc:     kc,
		logger: logger,
	}
}

// ListOrganizations returns all organizations
func (h *AdminHandler) ListOrganizations(c *gin.Context) {
	limitStr := c.Query("limit")

	if limitStr == "" {
		orgs, err := h.store.ListOrganizations()
		if err != nil {
			h.logger.Error("Failed to list organizations", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list organizations"})
			return
		}
		orgsResponse := make([]gin.H, 0, len(orgs))
		for _, org := range orgs {
			orgsResponse = append(orgsResponse, h.orgResponse(org))
		}
		c.JSON(http.StatusOK, gin.H{
			"organizations": orgsResponse, "total": len(orgsResponse),
			"page": 1, "limit": len(orgsResponse), "total_pages": 1,
		})
		return
	}

	limit, _ := strconv.Atoi(limitStr)
	if limit < 1 {
		limit = 10
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	skip := (page - 1) * limit

	total, err := h.store.CountOrganizations()
	if err != nil {
		h.logger.Error("Failed to count organizations", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list organizations"})
		return
	}
	orgs, err := h.store.ListOrganizationsPaged(limit, skip)
	if err != nil {
		h.logger.Error("Failed to list organizations", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list organizations"})
		return
	}

	orgsResponse := make([]gin.H, 0, len(orgs))
	for _, org := range orgs {
		orgsResponse = append(orgsResponse, h.orgResponse(org))
	}

	totalPages := int(math.Ceil(float64(total) / float64(limit)))
	c.JSON(http.StatusOK, gin.H{
		"organizations": orgsResponse, "total": total,
		"page": page, "limit": limit, "total_pages": totalPages,
	})
}

// GetOrganization returns a specific organization by ID
func (h *AdminHandler) GetOrganization(c *gin.Context) {
	orgIDStr := c.Param("id")
	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
		return
	}

	org, err := h.store.GetOrganizationByID(orgID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Organization not found"})
		return
	}

	// Get user count for this organization
	users, _ := h.store.ListUsersByTenant(org.KeycloakRealm)
	userCount := len(users)

	response := h.orgResponse(org)
	response["user_count"] = userCount

	c.JSON(http.StatusOK, response)
}

// CreateOrganizationRequest represents the organization creation payload
type CreateOrganizationRequest struct {
	Name        string `json:"name" binding:"required,min=3,max=100"`
	DisplayName string `json:"display_name" binding:"required"`
}

// CreateOrganization creates a new organization with Keycloak realm
func (h *AdminHandler) CreateOrganization(c *gin.Context) {
	var req CreateOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if organization name already exists
	_, err := h.store.GetOrganizationByName(req.Name)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Organization already exists"})
		return
	}

	// Create Keycloak realm
	realm, err := h.kc.CreateRealm(req.Name, req.DisplayName)
	if err != nil {
		h.logger.Error("Failed to create Keycloak realm", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create organization"})
		return
	}

	// Create organization in MongoDB
	org := &database.Organization{
		Name:          req.Name,
		DisplayName:   req.DisplayName,
		KeycloakRealm: *realm.Realm,
		Enabled:       true,
	}

	if err := h.store.CreateOrganization(org); err != nil {
		h.logger.Error("Failed to create organization in MongoDB", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create organization"})
		return
	}

	h.logger.Info("Organization created",
		zap.String("name", req.Name),
		zap.String("realm", *realm.Realm))

	c.JSON(http.StatusCreated, h.orgResponse(org))
}

// UpdateOrganizationRequest represents the organization update payload
type UpdateOrganizationRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

// UpdateOrganization updates an existing organization
func (h *AdminHandler) UpdateOrganization(c *gin.Context) {
	orgIDStr := c.Param("id")
	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
		return
	}

	var req UpdateOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing organization
	org, err := h.store.GetOrganizationByID(orgID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Organization not found"})
		return
	}

	// Update fields
	if req.DisplayName != nil {
		org.DisplayName = *req.DisplayName
	}
	if req.Enabled != nil {
		org.Enabled = *req.Enabled
	}

	// Update in MongoDB
	if err := h.store.UpdateOrganization(org); err != nil {
		h.logger.Error("Failed to update organization", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update organization"})
		return
	}

	h.logger.Info("Organization updated",
		zap.String("name", org.Name),
		zap.String("org_id", orgID.Hex()))

	c.JSON(http.StatusOK, h.orgResponse(org))
}

// DeleteOrganization deletes an organization
func (h *AdminHandler) DeleteOrganization(c *gin.Context) {
	orgIDStr := c.Param("id")
	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
		return
	}

	// Get existing organization
	org, err := h.store.GetOrganizationByID(orgID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Organization not found"})
		return
	}

	// Check if organization has users
	users, _ := h.store.ListUsersByTenant(org.KeycloakRealm)
	if len(users) > 0 {
		c.JSON(http.StatusConflict, gin.H{
			"error":      "Cannot delete organization with existing users",
			"user_count": len(users),
		})
		return
	}

	// Delete from MongoDB
	if err := h.store.DeleteOrganization(orgID); err != nil {
		h.logger.Error("Failed to delete organization from MongoDB", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete organization"})
		return
	}

	// Note: Deleting Keycloak realms is a destructive operation
	// Consider soft-delete or disable instead
	h.logger.Warn("Organization deleted - Keycloak realm not deleted (manual cleanup required)",
		zap.String("name", org.Name),
		zap.String("realm", org.KeycloakRealm))

	c.JSON(http.StatusOK, gin.H{
		"message": "Organization deleted successfully",
		"warning": "Keycloak realm was not deleted and requires manual cleanup",
	})
}

// GetOrganizationStats returns statistics for an organization
func (h *AdminHandler) GetOrganizationStats(c *gin.Context) {
	orgIDStr := c.Param("id")
	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
		return
	}

	org, err := h.store.GetOrganizationByID(orgID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Organization not found"})
		return
	}

	// Get users
	users, _ := h.store.ListUsersByTenant(org.KeycloakRealm)

	// Count roles
	adminCount := 0
	userCount := 0
	for _, user := range users {
		if user.Role == database.RoleCompanyAdmin || user.Role == database.RoleSuperAdmin {
			adminCount++
		} else {
			userCount++
		}
	}

	// Get groups
	groups, _ := h.store.ListGroupsByTenant(org.KeycloakRealm)

	c.JSON(http.StatusOK, gin.H{
		"organization": h.orgResponse(org),
		"stats": gin.H{
			"total_users":  len(users),
			"admin_users":  adminCount,
			"regular_users": userCount,
			"total_groups": len(groups),
		},
	})
}

// GetOrganizationUsers returns all users in an organization
func (h *AdminHandler) GetOrganizationUsers(c *gin.Context) {
	orgIDStr := c.Param("id")
	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
		return
	}

	org, err := h.store.GetOrganizationByID(orgID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Organization not found"})
		return
	}

	buildUserResponse := func(user *database.User) gin.H {
		return gin.H{
			"id": user.ID.Hex(), "username": user.Username, "email": user.Email,
			"first_name": user.FirstName, "last_name": user.LastName,
			"role": user.Role, "machine_role": user.MachineRole,
			"enabled": user.Enabled, "email_verified": user.EmailVerified, "created_at": user.CreatedAt,
		}
	}

	limitStr := c.Query("limit")
	tid := org.KeycloakRealm

	if limitStr == "" {
		users, err := h.store.ListUsersByTenant(tid)
		if err != nil {
			h.logger.Error("Failed to list organization users", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list users"})
			return
		}
		usersResponse := make([]gin.H, 0, len(users))
		for _, user := range users {
			usersResponse = append(usersResponse, buildUserResponse(user))
		}
		c.JSON(http.StatusOK, gin.H{
			"users": usersResponse, "total": len(usersResponse),
			"page": 1, "limit": len(usersResponse), "total_pages": 1,
		})
		return
	}

	limit, _ := strconv.Atoi(limitStr)
	if limit < 1 {
		limit = 10
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	skip := (page - 1) * limit

	total, err := h.store.CountUsersByTenant(tid)
	if err != nil {
		h.logger.Error("Failed to count organization users", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list users"})
		return
	}
	users, err := h.store.ListUsersByTenantPaged(tid, limit, skip)
	if err != nil {
		h.logger.Error("Failed to list organization users", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list users"})
		return
	}

	usersResponse := make([]gin.H, 0, len(users))
	for _, user := range users {
		usersResponse = append(usersResponse, buildUserResponse(user))
	}

	totalPages := int(math.Ceil(float64(total) / float64(limit)))
	c.JSON(http.StatusOK, gin.H{
		"users": usersResponse, "total": total,
		"page": page, "limit": limit, "total_pages": totalPages,
	})
}

// GetOrganizationGroups returns all groups in an organization
func (h *AdminHandler) GetOrganizationGroups(c *gin.Context) {
	orgIDStr := c.Param("id")
	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
		return
	}

	org, err := h.store.GetOrganizationByID(orgID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Organization not found"})
		return
	}

	buildGroupResponse := func(group *database.Group) gin.H {
		return gin.H{
			"id": group.ID.Hex(), "name": group.Name, "description": group.Description,
			"tenant_id": group.TenantID, "member_count": len(group.MemberIDs),
			"machine_count": len(group.MachineIDs), "created_at": group.CreatedAt,
		}
	}

	limitStr := c.Query("limit")
	tid := org.KeycloakRealm

	if limitStr == "" {
		groups, err := h.store.ListGroupsByTenant(tid)
		if err != nil {
			h.logger.Error("Failed to list organization groups", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list groups"})
			return
		}
		groupsResponse := make([]gin.H, 0, len(groups))
		for _, group := range groups {
			groupsResponse = append(groupsResponse, buildGroupResponse(group))
		}
		c.JSON(http.StatusOK, gin.H{
			"groups": groupsResponse, "total": len(groupsResponse),
			"page": 1, "limit": len(groupsResponse), "total_pages": 1,
		})
		return
	}

	limit, _ := strconv.Atoi(limitStr)
	if limit < 1 {
		limit = 10
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	skip := (page - 1) * limit

	total, err := h.store.CountGroupsByTenant(tid)
	if err != nil {
		h.logger.Error("Failed to count organization groups", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list groups"})
		return
	}
	groups, err := h.store.ListGroupsByTenantPaged(tid, limit, skip)
	if err != nil {
		h.logger.Error("Failed to list organization groups", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list groups"})
		return
	}

	groupsResponse := make([]gin.H, 0, len(groups))
	for _, group := range groups {
		groupsResponse = append(groupsResponse, buildGroupResponse(group))
	}

	totalPages := int(math.Ceil(float64(total) / float64(limit)))
	c.JSON(http.StatusOK, gin.H{
		"groups": groupsResponse, "total": total,
		"page": page, "limit": limit, "total_pages": totalPages,
	})
}

// Helper functions

func (h *AdminHandler) orgResponse(org *database.Organization) gin.H {
	return gin.H{
		"id":             org.ID.Hex(),
		"name":           org.Name,
		"display_name":   org.DisplayName,
		"keycloak_realm": org.KeycloakRealm,
		"enabled":        org.Enabled,
		"created_at":     org.CreatedAt,
		"updated_at":     org.UpdatedAt,
	}
}

// RegisterAdminRoutes registers all admin routes (super admin only)
func RegisterAdminRoutes(r *gin.RouterGroup, handler *AdminHandler, authMiddleware, superAdminMiddleware gin.HandlerFunc) {
	admin := r.Group("/admin")
	admin.Use(authMiddleware)        // Require authentication
	admin.Use(superAdminMiddleware)  // Require super admin role
	{
		// Organization management
		admin.GET("/organizations", handler.ListOrganizations)
		admin.POST("/organizations", handler.CreateOrganization)
		admin.GET("/organizations/:id", handler.GetOrganization)
		admin.PUT("/organizations/:id", handler.UpdateOrganization)
		admin.DELETE("/organizations/:id", handler.DeleteOrganization)
		admin.GET("/organizations/:id/stats", handler.GetOrganizationStats)

		// Organization details
		admin.GET("/organizations/:id/users", handler.GetOrganizationUsers)
		admin.GET("/organizations/:id/groups", handler.GetOrganizationGroups)
	}
}
