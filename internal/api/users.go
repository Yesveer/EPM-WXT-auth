package api

import (
	"math"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-auth/internal/database"
	"github.com/vsay/vsay-auth/internal/keycloak"
	"github.com/vsay/vsay-auth/internal/middleware"
	"github.com/vsay/vsay-auth/internal/services"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type UsersHandler struct {
	store        *database.Store
	kc           *keycloak.Client
	logger       *zap.Logger
	emailService *services.EmailService
}

func NewUsersHandler(
	store *database.Store,
	kc *keycloak.Client,
	emailService *services.EmailService,
	logger *zap.Logger,
) *UsersHandler {
	return &UsersHandler{
		store:        store,
		kc:           kc,
		emailService: emailService,
		logger:       logger,
	}
}

// ListUsers returns all users in the tenant
func (h *UsersHandler) ListUsers(c *gin.Context) {
	tenantID, _ := c.Get("tenant_id")
	role, _ := c.Get("role")

	// Super admins can see users from any tenant, but must specify tenant_id in query
	if role.(string) == middleware.RoleSuperAdmin {
		queryTenantID := c.Query("tenant_id")
		if queryTenantID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Super admin must specify tenant_id query parameter",
			})
			return
		}
		tenantID = queryTenantID
	}

	tid := tenantID.(string)
	limitStr := c.Query("limit")

	// No limit → return all (backward compatible)
	if limitStr == "" {
		users, err := h.store.ListUsersByTenant(tid)
		if err != nil {
			h.logger.Error("Failed to list users", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list users"})
			return
		}
		usersResponse := make([]gin.H, 0, len(users))
		for _, user := range users {
			usersResponse = append(usersResponse, h.userResponse(user))
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
		h.logger.Error("Failed to count users", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list users"})
		return
	}
	users, err := h.store.ListUsersByTenantPaged(tid, limit, skip)
	if err != nil {
		h.logger.Error("Failed to list users", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list users"})
		return
	}

	usersResponse := make([]gin.H, 0, len(users))
	for _, user := range users {
		usersResponse = append(usersResponse, h.userResponse(user))
	}

	totalPages := int(math.Ceil(float64(total) / float64(limit)))
	c.JSON(http.StatusOK, gin.H{
		"users": usersResponse, "total": total,
		"page": page, "limit": limit, "total_pages": totalPages,
	})
}

// GetUser returns a specific user by ID
func (h *UsersHandler) GetUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	user, err := h.store.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check tenant access (unless super admin)
	role, _ := c.Get("role")
	tenantID, _ := c.Get("tenant_id")
	if role.(string) != middleware.RoleSuperAdmin && user.TenantID != tenantID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	c.JSON(http.StatusOK, h.userResponse(user))
}

// CreateUserRequest represents the user creation payload
type CreateUserRequest struct {
	Username    string   `json:"username" binding:"required,min=3,max=50"`
	Email       string   `json:"email" binding:"required,email"`
	Password    string   `json:"password" binding:"required,min=8"`
	FirstName   string   `json:"first_name" binding:"required"`
	LastName    string   `json:"last_name" binding:"required"`
	Role        string   `json:"role" binding:"required,oneof=user company_admin"`
	MachineRole string   `json:"machine_role,omitempty" binding:"omitempty,oneof=allow_sudo non_sudo"`
	Groups      []string `json:"groups,omitempty"`
}

// CreateUser creates a new user in the tenant
func (h *UsersHandler) CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID, _ := c.Get("tenant_id")
	tenantName, _ := c.Get("tenant_name")
	requestorRole, _ := c.Get("role")

	// Only company admins can create company admins (and super admins, but they can do anything)
	if req.Role == database.RoleCompanyAdmin && requestorRole.(string) != middleware.RoleSuperAdmin && requestorRole.(string) != middleware.RoleCompanyAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions to create admin users"})
		return
	}

	// Check if username already exists
	exists, existingRealm, err := h.kc.CheckUsernameExists(req.Username)
	if err != nil {
		h.logger.Error("Failed to check username", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check username"})
		return
	}
	if exists {
		c.JSON(http.StatusConflict, gin.H{
			"error": "Username already exists",
			"realm": existingRealm,
		})
		return
	}

	// Create user in Keycloak
	kcUserID, err := h.kc.CreateUser(
		tenantID.(string),
		req.Username,
		req.Email,
		req.Password,
		req.FirstName,
		req.LastName,
		[]string{req.Role},
	)
	if err != nil {
		h.logger.Error("Failed to create user in Keycloak", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Hash password for MongoDB
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("Failed to hash password", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Create user in MongoDB
	user := &database.User{
		Username:          req.Username,
		Email:             req.Email,
		PasswordHash:      string(passwordHash),
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		KeycloakID:        kcUserID,
		TenantID:          tenantID.(string),
		TenantName:        tenantName.(string),
		Role:              req.Role,
		MachineRole:       req.MachineRole,
		Groups:            req.Groups,
		EmailVerified:     false,
		Enabled:           true,
		APIKey:            primitive.NewObjectID().Hex(),
		MustResetPassword: true,
	}

	if err := h.store.CreateUser(user); err != nil {
		h.logger.Error("Failed to create user in MongoDB", zap.Error(err))
		// Try to clean up Keycloak user
		_ = h.kc.DeleteUser(tenantID.(string), kcUserID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Send welcome email with credentials
	if h.emailService != nil {
		firstName := req.FirstName
		if firstName == "" {
			firstName = req.Username
		}
		if err := h.emailService.SendUserCredentialsEmail(
			req.Email,
			firstName,
			req.Username,
			req.Password,
			tenantName.(string),
		); err != nil {
			h.logger.Warn("Failed to send welcome email",
				zap.String("email", req.Email),
				zap.Error(err))
			// Don't fail the request if email fails
		}
	}

	h.logger.Info("User created",
		zap.String("username", req.Username),
		zap.String("tenant", tenantID.(string)))

	c.JSON(http.StatusCreated, h.userResponse(user))
}

// UpdateUserRequest represents the user update payload
type UpdateUserRequest struct {
	Email       *string  `json:"email,omitempty" binding:"omitempty,email"`
	FirstName   *string  `json:"first_name,omitempty"`
	LastName    *string  `json:"last_name,omitempty"`
	Role        *string  `json:"role,omitempty" binding:"omitempty,oneof=user company_admin"`
	MachineRole *string  `json:"machine_role,omitempty" binding:"omitempty,oneof=allow_sudo non_sudo"`
	Groups      []string `json:"groups,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
}

// UpdateUser updates an existing user
func (h *UsersHandler) UpdateUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing user
	user, err := h.store.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check tenant access
	role, _ := c.Get("role")
	tenantID, _ := c.Get("tenant_id")
	requestorUsername, _ := c.Get("username")

	if role.(string) != middleware.RoleSuperAdmin && user.TenantID != tenantID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Prevent users from modifying their own super admin role
	if user.Username == requestorUsername.(string) && user.Role == middleware.RoleSuperAdmin && req.Role != nil && *req.Role != middleware.RoleSuperAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot remove your own super admin role"})
		return
	}

	// Update fields
	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.FirstName != nil {
		user.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		user.LastName = *req.LastName
	}
	if req.Role != nil {
		// Only admins can change roles
		if role.(string) != middleware.RoleSuperAdmin && role.(string) != middleware.RoleCompanyAdmin {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions to change role"})
			return
		}
		user.Role = *req.Role
	}
	if req.MachineRole != nil {
		user.MachineRole = *req.MachineRole
	}
	if req.Groups != nil {
		user.Groups = req.Groups
	}
	if req.Enabled != nil {
		// Only admins can enable/disable users
		if role.(string) != middleware.RoleSuperAdmin && role.(string) != middleware.RoleCompanyAdmin {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions to enable/disable users"})
			return
		}
		user.Enabled = *req.Enabled
	}

	// Update in MongoDB
	if err := h.store.UpdateUser(user); err != nil {
		h.logger.Error("Failed to update user", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	// TODO: Sync changes to Keycloak

	h.logger.Info("User updated",
		zap.String("username", user.Username),
		zap.String("user_id", userID.Hex()))

	c.JSON(http.StatusOK, h.userResponse(user))
}

// DeleteUser deletes a user
func (h *UsersHandler) DeleteUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Get existing user
	user, err := h.store.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check tenant access
	role, _ := c.Get("role")
	tenantID, _ := c.Get("tenant_id")
	requestorUsername, _ := c.Get("username")

	if role.(string) != middleware.RoleSuperAdmin && user.TenantID != tenantID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Prevent users from deleting themselves
	if user.Username == requestorUsername.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot delete your own account"})
		return
	}

	// Prevent deleting super admin (unless requestor is also super admin)
	if user.Role == middleware.RoleSuperAdmin && role.(string) != middleware.RoleSuperAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot delete super admin"})
		return
	}

	// Delete from Keycloak
	if err := h.kc.DeleteUser(user.TenantID, user.KeycloakID); err != nil {
		h.logger.Warn("Failed to delete user from Keycloak", zap.Error(err))
		// Continue with MongoDB deletion
	}

	// Delete from MongoDB
	if err := h.store.DeleteUser(userID); err != nil {
		h.logger.Error("Failed to delete user from MongoDB", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	h.logger.Info("User deleted",
		zap.String("username", user.Username),
		zap.String("user_id", userID.Hex()))

	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
	})
}

// GetMe returns the current user's profile
func (h *UsersHandler) GetMe(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	user, err := h.store.GetUserByID(userID.(primitive.ObjectID))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, h.userResponse(user))
}

// Helper functions

func (h *UsersHandler) userResponse(user *database.User) gin.H {
	return gin.H{
		"id":             user.ID.Hex(),
		"username":       user.Username,
		"email":          user.Email,
		"first_name":     user.FirstName,
		"last_name":      user.LastName,
		"tenant_id":      user.TenantID,
		"tenant_name":    user.TenantName,
		"role":           user.Role,
		"machine_role":   user.MachineRole,
		"groups":         user.Groups,
		"email_verified": user.EmailVerified,
		"enabled":        user.Enabled,
		"api_key":        user.APIKey,
		"created_at":     user.CreatedAt,
		"updated_at":     user.UpdatedAt,
		"last_login_at":  user.LastLoginAt,
	}
}

// RegisterUsersRoutes registers all user routes
func RegisterUsersRoutes(r *gin.RouterGroup, handler *UsersHandler, authMiddleware, adminMiddleware gin.HandlerFunc) {
	users := r.Group("/users")
	users.Use(authMiddleware) // All user routes require authentication
	{
		users.GET("/me", handler.GetMe)                                  // Get current user
		users.GET("", adminMiddleware, handler.ListUsers)                // List users (admin only)
		users.GET("/:id", handler.GetUser)                               // Get user by ID
		users.POST("", adminMiddleware, handler.CreateUser)              // Create user (admin only)
		users.PUT("/:id", adminMiddleware, handler.UpdateUser)           // Update user (admin only)
		users.DELETE("/:id", adminMiddleware, handler.DeleteUser)        // Delete user (admin only)
	}
}
