package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-auth/internal/config"
	"github.com/vsay/vsay-auth/internal/database"
	"github.com/vsay/vsay-auth/internal/keycloak"
	"github.com/vsay/vsay-auth/internal/metrics"
	"github.com/vsay/vsay-auth/internal/middleware"
	"github.com/vsay/vsay-auth/internal/services"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	store        *database.Store
	kc           *keycloak.Client
	config       *config.Config
	jwtService   *services.JWTService
	otpService   *services.OTPService
	emailService *services.EmailService
	auditService *services.AuditService
	logger       *zap.Logger
}

func NewAuthHandler(
	store *database.Store,
	kc *keycloak.Client,
	cfg *config.Config,
	jwtService *services.JWTService,
	otpService *services.OTPService,
	emailService *services.EmailService,
	auditService *services.AuditService,
	logger *zap.Logger,
) *AuthHandler {
	return &AuthHandler{
		store:        store,
		kc:           kc,
		config:       cfg,
		jwtService:   jwtService,
		otpService:   otpService,
		emailService: emailService,
		auditService: auditService,
		logger:       logger,
	}
}

// SignupRequest represents the signup payload
type SignupRequest struct {
	Username         string `json:"username" binding:"required,min=3,max=50"`
	Email            string `json:"email" binding:"required,email"`
	Password         string `json:"password" binding:"required,min=8"`
	FirstName        string `json:"first_name" binding:"required"`
	LastName         string `json:"last_name" binding:"required"`
	OrganizationName string `json:"organization_name" binding:"required"`
	CompanyName      string `json:"company_name" binding:"required"`
}

// Signup creates a new user and organization
func (h *AuthHandler) Signup(c *gin.Context) {
	var req SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if username exists globally across all realms
	exists, existingRealm, err := h.kc.CheckUsernameExists(req.Username)
	if err != nil {
		h.logger.Error("Failed to check username existence", zap.Error(err))
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

	// Normalize realm name from organization name
	realmName := strings.ToLower(strings.ReplaceAll(req.OrganizationName, " ", "-"))

	// Check if organization/realm already exists
	_, err = h.store.GetOrganizationByRealm(realmName)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Organization already exists"})
		return
	}

	// Create Keycloak realm for the organization
	realm, err := h.kc.CreateRealm(req.OrganizationName, req.CompanyName)
	if err != nil {
		h.logger.Error("Failed to create Keycloak realm", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create organization"})
		return
	}

	// Create organization in MongoDB
	org := &database.Organization{
		Name:          req.OrganizationName,
		DisplayName:   req.CompanyName,
		KeycloakRealm: *realm.Realm,
		Enabled:       true,
	}
	if err := h.store.CreateOrganization(org); err != nil {
		h.logger.Error("Failed to create organization in MongoDB", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create organization"})
		return
	}

	// Create user in Keycloak with company_admin role
	userID, err := h.kc.CreateUser(
		*realm.Realm,
		req.Username,
		req.Email,
		req.Password,
		req.FirstName,
		req.LastName,
		[]string{database.RoleCompanyAdmin},
	)
	if err != nil {
		h.logger.Error("Failed to create user in Keycloak", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Generate password hash for MongoDB
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("Failed to hash password", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Create user in MongoDB
	dbUser := &database.User{
		Username:      req.Username,
		Email:         req.Email,
		PasswordHash:  string(passwordHash),
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		KeycloakID:    userID,
		TenantID:      *realm.Realm,
		TenantName:    req.CompanyName,
		Role:          database.RoleCompanyAdmin,
		EmailVerified: false,
		Enabled:       true,
		APIKey:        primitive.NewObjectID().Hex(),
	}

	if err := h.store.CreateUser(dbUser); err != nil {
		h.logger.Error("Failed to create user in MongoDB", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Send welcome email
	err = h.emailService.SendWelcomeEmail(req.Email, req.Username, req.CompanyName)
	if err != nil {
		h.logger.Warn("Failed to send welcome email", zap.Error(err))
	}

	h.logger.Info("User signed up successfully",
		zap.String("username", req.Username),
		zap.String("realm", *realm.Realm))

	c.JSON(http.StatusCreated, gin.H{
		"message":      "User created successfully. Please check your email to verify your account.",
		"user_id":      dbUser.ID.Hex(),
		"username":     dbUser.Username,
		"organization": req.CompanyName,
	})
}

// LoginRequest represents the login payload (email-based)
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// TenantInfo represents a tenant the user has access to
type TenantInfo struct {
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name"`
	Username   string `json:"username"`
	UserID     string `json:"user_id"`
}

// Login authenticates a user by email, finds all tenants for that email, and returns them
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get all users with this email across all tenants
	users, err := h.store.GetUsersByEmail(req.Email)
	if err != nil || len(users) == 0 {
		metrics.LoginAttemptsTotal.WithLabelValues("failure", "local").Inc()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Verify password against Keycloak for each tenant and collect valid ones
	var validUsers []*database.User
	for _, user := range users {
		if !user.Enabled {
			continue
		}
		_, kcErr := h.kc.Login(user.TenantID, user.Username, req.Password)
		if kcErr == nil {
			validUsers = append(validUsers, user)
		}
	}

	if len(validUsers) == 0 {
		h.logger.Warn("Login failed: no valid tenants for email", zap.String("email", req.Email))
		metrics.LoginAttemptsTotal.WithLabelValues("failure", "local").Inc()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	metrics.LoginAttemptsTotal.WithLabelValues("success", "local").Inc()

	source := middleware.ExtractSource(c)

	// Build tenant list and ID slice
	tenants := make([]TenantInfo, len(validUsers))
	tenantIDs := make([]string, len(validUsers))
	for i, u := range validUsers {
		tenants[i] = TenantInfo{
			TenantID:   u.TenantID,
			TenantName: u.TenantName,
			Username:   u.Username,
			UserID:     u.ID.Hex(),
		}
		tenantIDs[i] = u.TenantID
	}

	// Generate session token (used for tenant switching from navbar)
	sessionToken, err := h.jwtService.GenerateTenantSelectionToken(req.Email, tenantIDs)
	if err != nil {
		h.logger.Error("Failed to generate session token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate session"})
		return
	}

	// If OTP is enabled for UI and single tenant, send OTP and return
	if source == "ui" && h.otpService.IsEnabled() {
		// For OTP, use the first valid user's username (OTP keyed on username)
		// If multiple tenants, return tenant selection first, then handle OTP per-tenant via /select-tenant
		if len(validUsers) > 1 {
			c.JSON(http.StatusOK, gin.H{
				"requires_tenant_selection": true,
				"tenants":                   tenants,
				"session_token":             sessionToken,
			})
			return
		}

		user := validUsers[0]
		otpCode, otpErr := h.otpService.GenerateOTP(user.Username, user.TenantID)
		if otpErr != nil {
			h.logger.Error("Failed to generate OTP", zap.Error(otpErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
			return
		}

		if emailErr := h.emailService.SendOTPEmail(user.Email, user.Username, otpCode, h.otpService.GetOTPExpiryMinutes()); emailErr != nil {
			h.logger.Error("Failed to send OTP email", zap.Error(emailErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP email"})
			return
		}

		h.logger.Info("OTP sent via email", zap.String("email", req.Email))

		c.JSON(http.StatusOK, gin.H{
			"message":            "OTP sent to your email",
			"requires_otp":       true,
			"username":           user.Username,
			"tenants":            tenants,
			"session_token":      sessionToken,
			"otp_expires_in_min": h.otpService.GetOTPExpiryMinutes(),
		})
		return
	}

	// OTP disabled: if single tenant, return token directly
	if len(validUsers) == 1 {
		user := validUsers[0]
		token, tokenErr := h.generateToken(user, source)
		if tokenErr != nil {
			h.logger.Error("Failed to generate token", zap.Error(tokenErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		if err := h.store.UpdateUserLastLogin(user.ID); err != nil {
			h.logger.Warn("Failed to update last login", zap.Error(err))
		}

		c.JSON(http.StatusOK, gin.H{
			"token":               token,
			"user":                h.userResponse(user),
			"expires_in":          int(h.jwtService.GetTokenExpiry().Seconds()),
			"session_token":       sessionToken,
			"available_tenants":   tenants,
			"must_reset_password": user.MustResetPassword,
		})
		return
	}

	// Multiple tenants — require user to select one
	c.JSON(http.StatusOK, gin.H{
		"requires_tenant_selection": true,
		"tenants":                   tenants,
		"session_token":             sessionToken,
	})
}

// SelectTenantRequest represents the tenant selection payload
type SelectTenantRequest struct {
	SessionToken string `json:"session_token" binding:"required"`
	TenantID     string `json:"tenant_id" binding:"required"`
}

// SelectTenant issues a full JWT for the chosen tenant, validated against the session token
func (h *AuthHandler) SelectTenant(c *gin.Context) {
	var req SelectTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate session token
	claims, err := h.jwtService.ValidateTenantSelectionToken(req.SessionToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired session"})
		return
	}

	// Ensure selected tenant is in the validated list
	allowed := false
	for _, tid := range claims.TenantIDs {
		if tid == req.TenantID {
			allowed = true
			break
		}
	}
	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access to this tenant is not allowed"})
		return
	}

	// Get the specific user for this tenant
	user, err := h.store.GetUserByEmailAndTenant(claims.Email, req.TenantID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	if !user.Enabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "Account is disabled"})
		return
	}

	source := middleware.ExtractSource(c)

	// If OTP enabled for UI, send OTP and return username for verify-otp page
	if source == "ui" && h.otpService.IsEnabled() {
		otpCode, otpErr := h.otpService.GenerateOTP(user.Username, user.TenantID)
		if otpErr != nil {
			h.logger.Error("Failed to generate OTP", zap.Error(otpErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
			return
		}

		if emailErr := h.emailService.SendOTPEmail(user.Email, user.Username, otpCode, h.otpService.GetOTPExpiryMinutes()); emailErr != nil {
			h.logger.Error("Failed to send OTP email", zap.Error(emailErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP email"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message":            "OTP sent to your email",
			"requires_otp":       true,
			"username":           user.Username,
			"otp_expires_in_min": h.otpService.GetOTPExpiryMinutes(),
		})
		return
	}

	// Generate full token for selected tenant
	token, err := h.generateToken(user, source)
	if err != nil {
		h.logger.Error("Failed to generate token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	if err := h.store.UpdateUserLastLogin(user.ID); err != nil {
		h.logger.Warn("Failed to update last login", zap.Error(err))
	}

	// Build available tenants list from session token
	availableTenants := make([]TenantInfo, 0, len(claims.TenantIDs))
	for _, tid := range claims.TenantIDs {
		u, err := h.store.GetUserByEmailAndTenant(claims.Email, tid)
		if err != nil {
			continue
		}
		availableTenants = append(availableTenants, TenantInfo{
			TenantID:   u.TenantID,
			TenantName: u.TenantName,
			Username:   u.Username,
			UserID:     u.ID.Hex(),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"token":               token,
		"user":                h.userResponse(user),
		"expires_in":          int(h.jwtService.GetTokenExpiry().Seconds()),
		"session_token":       req.SessionToken,
		"available_tenants":   availableTenants,
		"must_reset_password": user.MustResetPassword,
	})
}

// VerifyOTPRequest represents the OTP verification payload
type VerifyOTPRequest struct {
	Username string `json:"username" binding:"required"`
	OTPCode  string `json:"otp_code" binding:"required,len=6"`
}

// VerifyOTP verifies OTP and returns JWT token
func (h *AuthHandler) VerifyOTP(c *gin.Context) {
	var req VerifyOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify OTP
	valid, err := h.otpService.ValidateOTP(req.Username, req.OTPCode)
	if err != nil {
		h.logger.Error("Failed to validate OTP", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate OTP"})
		return
	}

	if !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired OTP"})
		return
	}

	// Get user
	user, err := h.store.GetUserByUsername(req.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// Generate token
	token, err := h.generateToken(user, "ui")
	if err != nil {
		h.logger.Error("Failed to generate token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Update last login
	if err := h.store.UpdateUserLastLogin(user.ID); err != nil {
		h.logger.Warn("Failed to update last login", zap.Error(err))
	}

	// Delete OTP session
	_ = h.otpService.DeleteOTP(req.Username, user.TenantID)

	// Build available tenants list for this user's email
	allUsers, _ := h.store.GetUsersByEmail(user.Email)
	availableTenants := make([]TenantInfo, 0, len(allUsers))
	tenantIDs := make([]string, 0, len(allUsers))
	for _, u := range allUsers {
		if u.Enabled {
			availableTenants = append(availableTenants, TenantInfo{
				TenantID:   u.TenantID,
				TenantName: u.TenantName,
				Username:   u.Username,
				UserID:     u.ID.Hex(),
			})
			tenantIDs = append(tenantIDs, u.TenantID)
		}
	}

	sessionToken, _ := h.jwtService.GenerateTenantSelectionToken(user.Email, tenantIDs)

	c.JSON(http.StatusOK, gin.H{
		"token":               token,
		"user":                h.userResponse(user),
		"expires_in":          int(h.jwtService.GetTokenExpiry().Seconds()),
		"session_token":       sessionToken,
		"available_tenants":   availableTenants,
		"must_reset_password": user.MustResetPassword,
	})
}

// ChangePasswordRequest represents the change-password payload
type ChangePasswordRequest struct {
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// ChangePassword allows a logged-in user to set a new password (used for first-time forced reset)
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("user_id")
	keycloakID, _ := c.Get("keycloak_id")
	source, _ := c.Get("source")
	sourceStr := "ui"
	if source != nil {
		sourceStr = source.(string)
	}

	user, err := h.store.GetUserByID(userID.(primitive.ObjectID))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Update password in Keycloak
	if err := h.kc.SetUserPassword(user.TenantID, keycloakID.(string), req.NewPassword); err != nil {
		h.logger.Error("Failed to update password in Keycloak", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	// Hash new password for MongoDB
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process password"})
		return
	}

	// Update in MongoDB — also clears must_reset_password flag
	if err := h.store.UpdateUserPassword(user.ID, string(passwordHash)); err != nil {
		h.logger.Error("Failed to update password in MongoDB", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	// Issue fresh token (without the reset flag)
	user.MustResetPassword = false
	newToken, err := h.generateToken(user, sourceStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	h.logger.Info("Password changed", zap.String("username", user.Username))

	c.JSON(http.StatusOK, gin.H{
		"message":    "Password changed successfully",
		"token":      newToken,
		"user":       h.userResponse(user),
		"expires_in": int(h.jwtService.GetTokenExpiry().Seconds()),
	})
}

// Logout invalidates the user's token
func (h *AuthHandler) Logout(c *gin.Context) {
	username, exists := c.Get("username")
	if exists && username != nil {
		h.logger.Info("User logged out", zap.String("username", username.(string)))
	} else {
		h.logger.Info("User logged out (username not available)")
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

// RefreshTokenRequest represents the token refresh payload
type RefreshTokenRequest struct {
	Token string `json:"token" binding:"required"`
}

// RefreshToken generates a new token from an existing valid token
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate existing token — allow expired tokens so clients can refresh silently
	claims, err := h.jwtService.ValidateTokenAllowExpired(req.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Get user from database
	userID, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
		return
	}

	user, err := h.store.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// Check if user is still enabled
	if !user.Enabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "Account is disabled"})
		return
	}

	// Generate new token
	newToken, err := h.generateToken(user, claims.Source)
	if err != nil {
		h.logger.Error("Failed to generate token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      newToken,
		"expires_in": int(h.jwtService.GetTokenExpiry().Seconds()),
	})
}

// Helper functions

func (h *AuthHandler) generateToken(user *database.User, source string) (string, error) {
	return h.jwtService.GenerateToken(user, source)
}

func (h *AuthHandler) userResponse(user *database.User) gin.H {
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
		"api_key":        user.APIKey,
	}
}

// RegisterAuthRoutes registers all auth routes
func RegisterAuthRoutes(r *gin.RouterGroup, handler *AuthHandler, authMiddleware gin.HandlerFunc) {
	auth := r.Group("/auth")
	{
		auth.POST("/signup", handler.Signup)
		auth.POST("/login", handler.Login)
		auth.POST("/select-tenant", handler.SelectTenant)
		auth.POST("/verify-otp", handler.VerifyOTP)
		// Requires auth so the audit log can attribute the logout to a user —
		// previously public, which meant every logout (UI and CLI alike) was
		// logged with an empty username since no middleware had populated it.
		auth.POST("/logout", authMiddleware, handler.Logout)
		auth.POST("/refresh", handler.RefreshToken)
		auth.POST("/change-password", authMiddleware, handler.ChangePassword)
	}
}
