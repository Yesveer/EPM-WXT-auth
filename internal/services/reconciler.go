package services

import (
	"context"
	"fmt"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/vsay/vsay-auth/internal/config"
	"github.com/vsay/vsay-auth/internal/database"
	"github.com/vsay/vsay-auth/internal/keycloak"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// Reconciler syncs users between Keycloak and MongoDB
type Reconciler struct {
	kc       *keycloak.Client
	store    *database.Store
	config   *config.Config
	logger   *zap.Logger
	interval time.Duration
}

func NewReconciler(
	kc *keycloak.Client,
	store *database.Store,
	cfg *config.Config,
	logger *zap.Logger,
) *Reconciler {
	return &Reconciler{
		kc:       kc,
		store:    store,
		config:   cfg,
		logger:   logger,
		interval: time.Duration(cfg.ReconcilerIntervalMin) * time.Minute,
	}
}

// Start starts the reconciliation loop.
// Always runs once on startup. If RECONCILER_ENABLED=false or
// RECONCILER_INTERVAL_MINUTES=0, it stops after that single run.
func (r *Reconciler) Start(ctx context.Context) {
	// Run once on startup unconditionally
	r.reconcileAll(ctx)

	if !r.config.ReconcilerEnabled || r.interval == 0 {
		r.logger.Info("Reconciler ran once — periodic sync disabled",
			zap.Bool("enabled", r.config.ReconcilerEnabled),
			zap.Duration("interval", r.interval))
		return
	}

	r.logger.Info("Reconciler started", zap.Duration("interval", r.interval))

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Reconciler stopped")
			return
		case <-ticker.C:
			r.reconcileAll(ctx)
		}
	}
}

// reconcileAll reconciles all organizations/realms
func (r *Reconciler) reconcileAll(ctx context.Context) {
	r.logger.Info("Starting full reconciliation")

	// Get all organizations from MongoDB
	orgs, err := r.store.ListOrganizations()
	if err != nil {
		r.logger.Error("Failed to list organizations", zap.Error(err))
		return
	}

	for _, org := range orgs {
		if !org.Enabled {
			continue
		}

		if err := r.reconcileRealm(ctx, org.KeycloakRealm); err != nil {
			r.logger.Error("Failed to reconcile realm",
				zap.String("realm", org.KeycloakRealm),
				zap.Error(err))
		}
	}

	r.logger.Info("Full reconciliation completed",
		zap.Int("organizations", len(orgs)))
}

// reconcileRealm reconciles a single realm
func (r *Reconciler) reconcileRealm(ctx context.Context, realmName string) error {
	r.logger.Debug("Reconciling realm", zap.String("realm", realmName))

	var (
		usersCreated  int
		usersUpdated  int
		usersDisabled int
		syncErrors    []string
	)

	// Get users from Keycloak
	kcUsers, err := r.kc.ListUsers(realmName)
	if err != nil {
		r.logger.Error("Sync failed: could not list Keycloak users",
			zap.String("realm", realmName),
			zap.Error(err))
		return err
	}

	// Get users from MongoDB for this tenant
	dbUsers, err := r.store.ListUsersByTenant(realmName)
	if err != nil {
		r.logger.Error("Sync failed: could not list MongoDB users",
			zap.String("realm", realmName),
			zap.Error(err))
		return err
	}

	// Create maps for efficient lookup
	kcUserMap := make(map[string]*gocloak.User) // keycloak_id -> user
	dbUserMap := make(map[string]*database.User) // keycloak_id -> user

	for _, user := range kcUsers {
		if user.ID != nil {
			kcUserMap[*user.ID] = user
		}
	}

	for _, user := range dbUsers {
		dbUserMap[user.KeycloakID] = user
	}

	// Sync: Keycloak -> MongoDB
	for kcID, kcUser := range kcUserMap {
		dbUser, exists := dbUserMap[kcID]

		if !exists {
			// User exists in KC but not in MongoDB -> Create in MongoDB
			if err := r.createUserFromKeycloak(kcUser, realmName); err != nil {
				r.logger.Error("Failed to create user from Keycloak",
					zap.String("keycloak_id", kcID),
					zap.Error(err))
				syncErrors = append(syncErrors, fmt.Sprintf("create user %s: %v", *kcUser.Username, err))
			} else {
				usersCreated++
			}
		} else {
			// User exists in both -> Update MongoDB from KC (KC is source of truth)
			if r.needsUpdate(kcUser, dbUser) {
				if err := r.updateUserFromKeycloak(kcUser, dbUser); err != nil {
					r.logger.Error("Failed to update user from Keycloak",
						zap.String("keycloak_id", kcID),
						zap.Error(err))
					syncErrors = append(syncErrors, fmt.Sprintf("update user %s: %v", *kcUser.Username, err))
				} else {
					usersUpdated++
				}
			}
		}
	}

	// Check for users in MongoDB but not in Keycloak -> Mark as disabled
	for kcID, dbUser := range dbUserMap {
		if _, exists := kcUserMap[kcID]; !exists && dbUser.Enabled {
			dbUser.Enabled = false
			if err := r.store.UpdateUser(dbUser); err != nil {
				r.logger.Error("Failed to disable user",
					zap.String("keycloak_id", kcID),
					zap.Error(err))
				syncErrors = append(syncErrors, fmt.Sprintf("disable user %s: %v", dbUser.Username, err))
			} else {
				usersDisabled++
			}
		}
	}

	// Log the sync result — no DB write
	if len(syncErrors) > 0 {
		r.logger.Warn("Realm sync completed with errors",
			zap.String("realm", realmName),
			zap.Int("created", usersCreated),
			zap.Int("updated", usersUpdated),
			zap.Int("disabled", usersDisabled),
			zap.Strings("errors", syncErrors))
	} else {
		r.logger.Info("Realm sync completed successfully",
			zap.String("realm", realmName),
			zap.Int("created", usersCreated),
			zap.Int("updated", usersUpdated),
			zap.Int("disabled", usersDisabled))
	}

	return nil
}

// createUserFromKeycloak creates a user in MongoDB from Keycloak user
func (r *Reconciler) createUserFromKeycloak(kcUser *gocloak.User, realmName string) error {
	// Get user roles from Keycloak
	roles, err := r.kc.GetUserRoles(realmName, *kcUser.ID)
	if err != nil {
		r.logger.Warn("Failed to get user roles", zap.String("user_id", *kcUser.ID), zap.Error(err))
		roles = []*gocloak.Role{}
	}

	roleNames := make([]string, 0)
	for _, role := range roles {
		if role.Name != nil {
			roleNames = append(roleNames, *role.Name)
		}
	}

	// Get organization info
	org, err := r.store.GetOrganizationByRealm(realmName)
	if err != nil {
		return fmt.Errorf("failed to get organization: %w", err)
	}

	// Determine role (super_admin, company_admin, user)
	userRole := database.RoleUser
	for _, roleName := range roleNames {
		if roleName == database.RoleSuperAdmin {
			userRole = database.RoleSuperAdmin
			break
		} else if roleName == database.RoleCompanyAdmin {
			userRole = database.RoleCompanyAdmin
		}
	}

	// Create MongoDB user
	dbUser := &database.User{
		Username:      getStringValue(kcUser.Username),
		Email:         getStringValue(kcUser.Email),
		FirstName:     getStringValue(kcUser.FirstName),
		LastName:      getStringValue(kcUser.LastName),
		KeycloakID:    *kcUser.ID,
		TenantID:      realmName,
		TenantName:    org.DisplayName,
		Role:          userRole,
		EmailVerified: getBoolValue(kcUser.EmailVerified),
		Enabled:       getBoolValue(kcUser.Enabled),
		APIKey:        primitive.NewObjectID().Hex(), // Generate API key
	}

	// Generate a placeholder password hash (user should reset via Keycloak)
	hash, _ := bcrypt.GenerateFromPassword([]byte(primitive.NewObjectID().Hex()), bcrypt.DefaultCost)
	dbUser.PasswordHash = string(hash)

	if err := r.store.CreateUser(dbUser); err != nil {
		return fmt.Errorf("failed to create user in MongoDB: %w", err)
	}

	r.logger.Info("Created user from Keycloak",
		zap.String("username", dbUser.Username),
		zap.String("keycloak_id", dbUser.KeycloakID))

	return nil
}

// updateUserFromKeycloak updates MongoDB user from Keycloak user
func (r *Reconciler) updateUserFromKeycloak(kcUser *gocloak.User, dbUser *database.User) error {
	dbUser.Email = getStringValue(kcUser.Email)
	dbUser.FirstName = getStringValue(kcUser.FirstName)
	dbUser.LastName = getStringValue(kcUser.LastName)
	dbUser.EmailVerified = getBoolValue(kcUser.EmailVerified)
	dbUser.Enabled = getBoolValue(kcUser.Enabled)

	if err := r.store.UpdateUserSyncTime(dbUser.ID); err != nil {
		return fmt.Errorf("failed to update user in MongoDB: %w", err)
	}

	r.logger.Debug("Updated user from Keycloak",
		zap.String("username", dbUser.Username),
		zap.String("keycloak_id", dbUser.KeycloakID))

	return nil
}

// needsUpdate checks if MongoDB user needs to be updated from Keycloak
func (r *Reconciler) needsUpdate(kcUser *gocloak.User, dbUser *database.User) bool {
	return getStringValue(kcUser.Email) != dbUser.Email ||
		getStringValue(kcUser.FirstName) != dbUser.FirstName ||
		getStringValue(kcUser.LastName) != dbUser.LastName ||
		getBoolValue(kcUser.EmailVerified) != dbUser.EmailVerified ||
		getBoolValue(kcUser.Enabled) != dbUser.Enabled
}

// SyncUser syncs a single user from Keycloak to MongoDB
func (r *Reconciler) SyncUser(keycloakID, realmName string) error {
	kcUser, err := r.kc.GetUser(realmName, keycloakID)
	if err != nil {
		return fmt.Errorf("failed to get user from Keycloak: %w", err)
	}

	dbUser, err := r.store.GetUserByKeycloakID(keycloakID)
	if err != nil {
		// User doesn't exist in MongoDB, create it
		return r.createUserFromKeycloak(kcUser, realmName)
	}

	// Update existing user
	return r.updateUserFromKeycloak(kcUser, dbUser)
}

// Helper functions
func getStringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func getBoolValue(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}
