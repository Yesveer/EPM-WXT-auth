package keycloak

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/vsay/vsay-auth/internal/config"
	"github.com/vsay/vsay-auth/internal/models"
	"go.uber.org/zap"
)

type Client struct {
	client      *gocloak.GoCloak
	config      *config.Config
	logger      *zap.Logger
	token       *gocloak.JWT
	tokenExpiry time.Time
	tokenMux    sync.RWMutex
}

func NewClient(cfg *config.Config, logger *zap.Logger) (*Client, error) {
	client := gocloak.NewClient(cfg.KeycloakURL)

	kc := &Client{
		client: client,
		config: cfg,
		logger: logger,
	}

	// Get admin token
	if err := kc.refreshAdminToken(); err != nil {
		return nil, fmt.Errorf("failed to get admin token: %w", err)
	}

	return kc, nil
}

// refreshAdminToken gets a new admin access token
func (kc *Client) refreshAdminToken() error {
	kc.tokenMux.Lock()
	defer kc.tokenMux.Unlock()

	ctx := context.Background()
	token, err := kc.client.LoginAdmin(
		ctx,
		kc.config.KeycloakAdminUser,
		kc.config.KeycloakAdminPass,
		kc.config.KeycloakRealm,
	)
	if err != nil {
		return err
	}
	kc.token = token
	// Set expiry to token.ExpiresIn seconds from now, minus 30 seconds buffer
	kc.tokenExpiry = time.Now().Add(time.Duration(token.ExpiresIn-30) * time.Second)
	return nil
}

// ensureValidToken checks if token is valid and refreshes if needed
func (kc *Client) ensureValidToken() error {
	kc.tokenMux.RLock()
	needsRefresh := time.Now().After(kc.tokenExpiry)
	kc.tokenMux.RUnlock()

	if needsRefresh {
		return kc.refreshAdminToken()
	}
	return nil
}

// CreateRealm creates a new realm (tenant/organization)
func (kc *Client) CreateRealm(name, displayName string) (*gocloak.RealmRepresentation, error) {
	if err := kc.ensureValidToken(); err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()

	// Normalize realm name (lowercase, no spaces)
	realmName := strings.ToLower(strings.ReplaceAll(name, " ", "-"))

	realm := gocloak.RealmRepresentation{
		Realm:       gocloak.StringP(realmName),
		DisplayName: gocloak.StringP(displayName),
		Enabled:     gocloak.BoolP(true),
		// Enable user registration and email verification
		RegistrationAllowed:  gocloak.BoolP(true),
		RegistrationEmailAsUsername: gocloak.BoolP(false),
		VerifyEmail:          gocloak.BoolP(true),
		LoginWithEmailAllowed: gocloak.BoolP(false), // Only username login
		DuplicateEmailsAllowed: gocloak.BoolP(true), // Allow same email across tenants
	}

	_, err := kc.client.CreateRealm(ctx, kc.token.AccessToken, realm)
	if err != nil {
		return nil, fmt.Errorf("failed to create realm: %w", err)
	}

	// Create client for the realm (required for login)
	if err := kc.CreateRealmClient(realmName); err != nil {
		kc.logger.Warn("Failed to create realm client", zap.Error(err))
		// Continue anyway - client might already exist
	}

	return &realm, nil
}

// CreateRealmClient creates a client in the realm for authentication
func (kc *Client) CreateRealmClient(realmName string) error {
	if err := kc.ensureValidToken(); err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()

	// Create client for user authentication
	client := gocloak.Client{
		ClientID: gocloak.StringP(kc.config.KeycloakClientID),
		Enabled:  gocloak.BoolP(true),
		// Public client for direct access grants
		PublicClient:                 gocloak.BoolP(true),
		DirectAccessGrantsEnabled:    gocloak.BoolP(true), // Enable password grant
		StandardFlowEnabled:          gocloak.BoolP(true),
		ImplicitFlowEnabled:          gocloak.BoolP(false),
		ServiceAccountsEnabled:       gocloak.BoolP(false),
		AuthorizationServicesEnabled: gocloak.BoolP(false),
	}

	_, err := kc.client.CreateClient(ctx, kc.token.AccessToken, realmName, client)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	return nil
}

// GetRealm gets realm details
func (kc *Client) GetRealm(realmName string) (*gocloak.RealmRepresentation, error) {
	if err := kc.ensureValidToken(); err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	return kc.client.GetRealm(ctx, kc.token.AccessToken, realmName)
}

// ListRealms lists all realms
func (kc *Client) ListRealms() ([]*gocloak.RealmRepresentation, error) {
	if err := kc.ensureValidToken(); err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	return kc.client.GetRealms(ctx, kc.token.AccessToken)
}

// CreateUser creates a new user in the specified realm
func (kc *Client) CreateUser(realm, username, email, password, firstName, lastName string, roles []string) (string, error) {
	if err := kc.ensureValidToken(); err != nil {
		return "", fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()

	// Skip email verification for all users (we use OTP for verification)
	emailVerified := true
	requiredActions := []string{} // No required actions

	user := gocloak.User{
		Username:        gocloak.StringP(username),
		Email:           gocloak.StringP(email),
		FirstName:       gocloak.StringP(firstName),
		LastName:        gocloak.StringP(lastName),
		Enabled:         gocloak.BoolP(true),
		EmailVerified:   gocloak.BoolP(emailVerified),
		RequiredActions: &requiredActions,
	}

	userID, err := kc.client.CreateUser(ctx, kc.token.AccessToken, realm, user)
	if err != nil {
		return "", fmt.Errorf("failed to create user: %w", err)
	}

	// Set password
	err = kc.client.SetPassword(ctx, kc.token.AccessToken, userID, realm, password, false)
	if err != nil {
		return "", fmt.Errorf("failed to set password: %w", err)
	}

	// Assign roles if provided
	if len(roles) > 0 {
		if err := kc.AssignRolesToUser(realm, userID, roles); err != nil {
			kc.logger.Error("Failed to assign roles to user", zap.Error(err))
		}
	}

	// Email verification is handled by OTP system, not Keycloak
	return userID, nil
}

// GetUser gets user by ID
func (kc *Client) GetUser(realm, userID string) (*gocloak.User, error) {
	if err := kc.ensureValidToken(); err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	return kc.client.GetUserByID(ctx, kc.token.AccessToken, realm, userID)
}

// GetUserByUsername gets user by username
func (kc *Client) GetUserByUsername(realm, username string) (*gocloak.User, error) {
	if err := kc.ensureValidToken(); err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	users, err := kc.client.GetUsers(ctx, kc.token.AccessToken, realm, gocloak.GetUsersParams{
		Username: gocloak.StringP(username),
		Exact:    gocloak.BoolP(true),
	})
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("user not found")
	}
	return users[0], nil
}

// ListUsers lists all users in realm
func (kc *Client) ListUsers(realm string) ([]*gocloak.User, error) {
	if err := kc.ensureValidToken(); err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	return kc.client.GetUsers(ctx, kc.token.AccessToken, realm, gocloak.GetUsersParams{})
}

// DeleteUser deletes a user
func (kc *Client) DeleteUser(realm, userID string) error {
	if err := kc.ensureValidToken(); err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	return kc.client.DeleteUser(ctx, kc.token.AccessToken, realm, userID)
}

// ClearRequiredActions clears all required actions for a user
func (kc *Client) ClearRequiredActions(realm, userID string) error {
	if err := kc.ensureValidToken(); err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	user, err := kc.client.GetUserByID(ctx, kc.token.AccessToken, realm, userID)
	if err != nil {
		return err
	}

	emptyActions := []string{}
	user.RequiredActions = &emptyActions
	user.EmailVerified = gocloak.BoolP(true)

	return kc.client.UpdateUser(ctx, kc.token.AccessToken, realm, *user)
}

// SetUserPassword updates a user's password in Keycloak (used for forced password reset)
func (kc *Client) SetUserPassword(realm, userID, newPassword string) error {
	if err := kc.ensureValidToken(); err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}
	ctx := context.Background()
	return kc.client.SetPassword(ctx, kc.token.AccessToken, userID, realm, newPassword, false)
}

// Login authenticates a user
func (kc *Client) Login(realm, username, password string) (*gocloak.JWT, error) {
	ctx := context.Background()
	return kc.client.Login(
		ctx,
		kc.config.KeycloakClientID,
		kc.config.KeycloakClientSecret,
		realm,
		username,
		password,
	)
}

// VerifyToken verifies and parses a JWT token
func (kc *Client) VerifyToken(realm, token string) (*gocloak.JWT, error) {
	ctx := context.Background()
	_, _, err := kc.client.DecodeAccessToken(ctx, token, realm)
	if err != nil {
		return nil, err
	}
	// If no error, token is valid
	return &gocloak.JWT{AccessToken: token}, nil
}

// CreateGroup creates a new group in realm
func (kc *Client) CreateGroup(realm, name, description string) (string, error) {
	if err := kc.ensureValidToken(); err != nil {
		return "", fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	group := gocloak.Group{
		Name: gocloak.StringP(name),
		Attributes: &map[string][]string{
			"description": {description},
		},
	}
	return kc.client.CreateGroup(ctx, kc.token.AccessToken, realm, group)
}

// GetGroup gets group by ID
func (kc *Client) GetGroup(realm, groupID string) (*gocloak.Group, error) {
	if err := kc.ensureValidToken(); err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	return kc.client.GetGroup(ctx, kc.token.AccessToken, realm, groupID)
}

// ListGroups lists all groups in realm
func (kc *Client) ListGroups(realm string) ([]*gocloak.Group, error) {
	if err := kc.ensureValidToken(); err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	return kc.client.GetGroups(ctx, kc.token.AccessToken, realm, gocloak.GetGroupsParams{})
}

// DeleteGroup deletes a group
func (kc *Client) DeleteGroup(realm, groupID string) error {
	if err := kc.ensureValidToken(); err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	return kc.client.DeleteGroup(ctx, kc.token.AccessToken, realm, groupID)
}

// AddUserToGroup adds a user to a group
func (kc *Client) AddUserToGroup(realm, userID, groupID string) error {
	if err := kc.ensureValidToken(); err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	return kc.client.AddUserToGroup(ctx, kc.token.AccessToken, realm, userID, groupID)
}

// RemoveUserFromGroup removes a user from a group
func (kc *Client) RemoveUserFromGroup(realm, userID, groupID string) error {
	if err := kc.ensureValidToken(); err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	return kc.client.DeleteUserFromGroup(ctx, kc.token.AccessToken, realm, userID, groupID)
}

// GetUserGroups gets all groups for a user
func (kc *Client) GetUserGroups(realm, userID string) ([]*gocloak.Group, error) {
	if err := kc.ensureValidToken(); err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	return kc.client.GetUserGroups(ctx, kc.token.AccessToken, realm, userID, gocloak.GetGroupsParams{})
}

// CreateRole creates a new role in realm
func (kc *Client) CreateRole(realm, roleName, description string) error {
	if err := kc.ensureValidToken(); err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	role := gocloak.Role{
		Name:        gocloak.StringP(roleName),
		Description: gocloak.StringP(description),
	}
	_, err := kc.client.CreateRealmRole(ctx, kc.token.AccessToken, realm, role)
	return err
}

// AssignRolesToUser assigns roles to a user
func (kc *Client) AssignRolesToUser(realm, userID string, roleNames []string) error {
	if err := kc.ensureValidToken(); err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()

	var roles []gocloak.Role
	for _, roleName := range roleNames {
		role, err := kc.client.GetRealmRole(ctx, kc.token.AccessToken, realm, roleName)
		if err != nil {
			return fmt.Errorf("failed to get role %s: %w", roleName, err)
		}
		roles = append(roles, *role)
	}

	return kc.client.AddRealmRoleToUser(ctx, kc.token.AccessToken, realm, userID, roles)
}

// GetUserRoles gets all roles for a user
func (kc *Client) GetUserRoles(realm, userID string) ([]*gocloak.Role, error) {
	if err := kc.ensureValidToken(); err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	ctx := context.Background()
	return kc.client.GetRealmRolesByUserID(ctx, kc.token.AccessToken, realm, userID)
}

// CheckUsernameExists checks if username exists across all realms
func (kc *Client) CheckUsernameExists(username string) (bool, string, error) {
	if err := kc.ensureValidToken(); err != nil {
		return false, "", fmt.Errorf("failed to refresh token: %w", err)
	}

	realms, err := kc.ListRealms()
	if err != nil {
		return false, "", err
	}

	for _, realm := range realms {
		if realm.Realm == nil {
			continue
		}
		user, err := kc.GetUserByUsername(*realm.Realm, username)
		if err == nil && user != nil {
			return true, *realm.Realm, nil
		}
	}

	return false, "", nil
}

// ConvertToUser converts Keycloak user to our User model
func ConvertToUser(kcUser *gocloak.User, realm string, roles []string) *models.User {
	user := &models.User{
		ID:            *kcUser.ID,
		Username:      *kcUser.Username,
		Email:         *kcUser.Email,
		TenantID:      realm,
		EmailVerified: *kcUser.EmailVerified,
		Enabled:       *kcUser.Enabled,
	}

	if kcUser.FirstName != nil {
		user.FirstName = *kcUser.FirstName
	}
	if kcUser.LastName != nil {
		user.LastName = *kcUser.LastName
	}

	// Determine role (highest priority role)
	for _, role := range roles {
		if role == models.RoleSuperAdmin {
			user.Role = models.RoleSuperAdmin
			break
		} else if role == models.RoleCompanyAdmin {
			user.Role = models.RoleCompanyAdmin
		} else if user.Role == "" {
			user.Role = models.RoleUser
		}
	}

	if user.Role == "" {
		user.Role = models.RoleUser
	}

	return user
}
