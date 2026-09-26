package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-auth/internal/database"
	"github.com/vsay/vsay-auth/internal/keycloak"
	"github.com/vsay/vsay-auth/internal/middleware"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

type RolesHandler struct {
	store  *database.Store
	kc     *keycloak.Client
	logger *zap.Logger
}

func NewRolesHandler(
	store *database.Store,
	kc *keycloak.Client,
	logger *zap.Logger,
) *RolesHandler {
	return &RolesHandler{
		store:  store,
		kc:     kc,
		logger: logger,
	}
}

// RoleDefinition represents a role with its metadata
type RoleDefinition struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Description string   `json:"description"`
	Type        string   `json:"type"` // "portal" or "machine"
	Permissions []string `json:"permissions"`
}

// Portal role definitions
var portalRoles = []RoleDefinition{
	{
		ID:          middleware.RoleSuperAdmin,
		Name:        "super_admin",
		DisplayName: "Super Administrator",
		Description: "Full system access across all organizations. Can create and manage organizations, users, groups, and all system resources.",
		Type:        "portal",
		Permissions: []string{
			"manage_organizations",
			"manage_all_users",
			"manage_all_groups",
			"manage_all_machines",
			"view_all_resources",
			"system_configuration",
		},
	},
	{
		ID:          middleware.RoleCompanyAdmin,
		Name:        "company_admin",
		DisplayName: "Administrator",
		Description: "Organization administrator with full access to manage users, groups, and resources within their organization.",
		Type:        "portal",
		Permissions: []string{
			"manage_users",
			"manage_groups",
			"manage_machines",
			"view_org_resources",
		},
	},
	{
		ID:          middleware.RoleUser,
		Name:        "user",
		DisplayName: "User",
		Description: "Standard user with access to assigned machines and resources. Can view and use machines they have permission for.",
		Type:        "portal",
		Permissions: []string{
			"view_assigned_machines",
			"use_assigned_machines",
			"view_own_profile",
		},
	},
}

// Machine role definitions
var machineRoles = []RoleDefinition{
	{
		ID:          "allow_sudo",
		Name:        "sudo",
		DisplayName: "Sudo Access",
		Description: "Full administrative access on machines. Can execute privileged commands using sudo.",
		Type:        "machine",
		Permissions: []string{
			"execute_sudo_commands",
			"modify_system_files",
			"install_packages",
			"manage_services",
		},
	},
	{
		ID:          "non_sudo",
		Name:        "non-sudo",
		DisplayName: "Non-Sudo Access",
		Description: "Standard user access on machines. Cannot execute privileged commands.",
		Type:        "machine",
		Permissions: []string{
			"execute_user_commands",
			"read_system_info",
		},
	},
}

// ListAllRoles returns all available role types (portal + machine)
func (h *RolesHandler) ListAllRoles(c *gin.Context) {
	allRoles := append(portalRoles, machineRoles...)

	c.JSON(http.StatusOK, gin.H{
		"roles": allRoles,
		"total": len(allRoles),
	})
}

// ListPortalRoles returns available portal roles
func (h *RolesHandler) ListPortalRoles(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"roles": portalRoles,
		"total": len(portalRoles),
	})
}

// ListMachineRoles returns available machine roles
func (h *RolesHandler) ListMachineRoles(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"roles": machineRoles,
		"total": len(machineRoles),
	})
}

// AssignUserRolesRequest represents the request to assign roles to a user
type AssignUserRolesRequest struct {
	PortalRole  string `json:"portal_role" binding:"required"`
	MachineRole string `json:"machine_role"`
}

// AssignUserRoles updates a user's portal and machine roles
func (h *RolesHandler) AssignUserRoles(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req AssignUserRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate portal role
	validPortalRole := false
	for _, role := range portalRoles {
		if role.ID == req.PortalRole {
			validPortalRole = true
			break
		}
	}
	if !validPortalRole {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid portal role"})
		return
	}

	// Validate machine role if provided
	if req.MachineRole != "" {
		validMachineRole := false
		for _, role := range machineRoles {
			if role.ID == req.MachineRole {
				validMachineRole = true
				break
			}
		}
		if !validMachineRole {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid machine role"})
			return
		}
	}

	// Get user
	user, err := h.store.GetUserByID(userID)
	if err != nil {
		h.logger.Error("Failed to get user", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check permissions
	currentUserRole, _ := c.Get("role")
	currentUserTenantID, _ := c.Get("tenant_id")

	// Super admin can change any user's roles
	if currentUserRole.(string) != middleware.RoleSuperAdmin {
		// Company admins can only change roles within their tenant
		if user.TenantID != currentUserTenantID.(string) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Cannot modify users in other organizations"})
			return
		}
		// Company admins cannot assign super_admin role
		if req.PortalRole == middleware.RoleSuperAdmin {
			c.JSON(http.StatusForbidden, gin.H{"error": "Cannot assign super admin role"})
			return
		}
	}

	// Update user roles
	user.Role = req.PortalRole
	user.MachineRole = req.MachineRole

	if err := h.store.UpdateUser(user); err != nil {
		h.logger.Error("Failed to update user roles", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user roles"})
		return
	}

	// Note: MongoDB is source of truth for roles
	// Keycloak roles sync is handled separately if needed

	h.logger.Info("User roles updated",
		zap.String("user_id", userID.Hex()),
		zap.String("portal_role", req.PortalRole),
		zap.String("machine_role", req.MachineRole))

	c.JSON(http.StatusOK, gin.H{
		"message":      "Roles updated successfully",
		"portal_role":  req.PortalRole,
		"machine_role": req.MachineRole,
	})
}

// GetUserRoles returns the current roles assigned to a user
func (h *RolesHandler) GetUserRoles(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	user, err := h.store.GetUserByID(userID)
	if err != nil {
		h.logger.Error("Failed to get user", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check permissions
	currentUserRole, _ := c.Get("role")
	currentUserTenantID, _ := c.Get("tenant_id")
	currentUserID, _ := c.Get("user_id")

	// Users can view their own roles, admins can view users in their tenant, super admins can view all
	if currentUserRole.(string) != middleware.RoleSuperAdmin {
		if currentUserRole.(string) != middleware.RoleCompanyAdmin {
			// Regular users can only view their own roles
			if user.ID != currentUserID.(primitive.ObjectID) {
				c.JSON(http.StatusForbidden, gin.H{"error": "Cannot view other users' roles"})
				return
			}
		} else {
			// Company admins can view users in their tenant
			if user.TenantID != currentUserTenantID.(string) {
				c.JSON(http.StatusForbidden, gin.H{"error": "Cannot view users in other organizations"})
				return
			}
		}
	}

	// Find role definitions
	var portalRoleDef, machineRoleDef *RoleDefinition

	for i := range portalRoles {
		if portalRoles[i].ID == user.Role {
			portalRoleDef = &portalRoles[i]
			break
		}
	}

	if user.MachineRole != "" {
		for i := range machineRoles {
			if machineRoles[i].ID == user.MachineRole {
				machineRoleDef = &machineRoles[i]
				break
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":       user.ID.Hex(),
		"username":      user.Username,
		"portal_role":   portalRoleDef,
		"machine_role":  machineRoleDef,
	})
}

// RegisterRolesRoutes registers the roles API routes
func RegisterRolesRoutes(r *gin.RouterGroup, handler *RolesHandler, authMiddleware, adminMiddleware gin.HandlerFunc) {
	roles := r.Group("/roles")
	roles.Use(authMiddleware, adminMiddleware) // Only admins can view roles
	{
		roles.GET("", handler.ListAllRoles)
		roles.GET("/portal", handler.ListPortalRoles)
		roles.GET("/machine", handler.ListMachineRoles)
	}

	// User role management - requires auth middleware
	users := r.Group("/users")
	users.Use(authMiddleware)
	{
		users.GET("/:id/roles", handler.GetUserRoles)
		users.POST("/:id/roles", adminMiddleware, handler.AssignUserRoles) // Only admins can assign roles
	}
}
