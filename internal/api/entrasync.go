package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/vsay/vsay-auth/internal/config"
	"github.com/vsay/vsay-auth/internal/database"
	"github.com/vsay/vsay-auth/internal/entrasync"
	"github.com/vsay/vsay-auth/internal/graph"
	"github.com/vsay/vsay-auth/internal/middleware"
)

// manualSyncTimeout bounds an operator-triggered run. A large directory takes
// a while; a hung one should not hold the request forever.
const manualSyncTimeout = 10 * time.Minute

// EntraSyncHandler exposes directory synchronisation.
type EntraSyncHandler struct {
	store  *database.Store
	config *config.Config
	syncer *entrasync.Syncer
	logger *zap.Logger
}

// NewEntraSyncHandler builds the handler.
func NewEntraSyncHandler(store *database.Store, cfg *config.Config, syncer *entrasync.Syncer, logger *zap.Logger) *EntraSyncHandler {
	return &EntraSyncHandler{store: store, config: cfg, syncer: syncer, logger: logger}
}

// entraSyncResponse is what the settings screen reads.
//
// The secret is never returned — only whether one is stored, so the form can
// show "configured" without ever putting the value on the wire again.
type entraSyncResponse struct {
	Enabled           bool   `json:"enabled"`
	DirectoryTenantID string `json:"directory_tenant_id"`
	ClientID          string `json:"client_id"`
	HasClientSecret   bool   `json:"has_client_secret"`
	SyncUsers         bool   `json:"sync_users"`
	SyncGroups        bool   `json:"sync_groups"`
	IntervalMinutes   int    `json:"interval_minutes"`
	DefaultRole       string `json:"default_role"`
	GroupFilter       string `json:"group_filter"`

	// UsingSharedCredentials says the sync is falling back to the sign-in
	// button's app registration. Worth stating: those usually carry only
	// delegated permissions, which the sync cannot use.
	UsingSharedCredentials bool `json:"using_shared_credentials"`

	LastRunAt  *time.Time `json:"last_run_at,omitempty"`
	LastStatus string     `json:"last_status,omitempty"`
	LastError  string     `json:"last_error,omitempty"`

	LastUsersCreated  int `json:"last_users_created"`
	LastUsersUpdated  int `json:"last_users_updated"`
	LastUsersDisabled int `json:"last_users_disabled"`
	LastGroupsCreated int `json:"last_groups_created"`
	LastGroupsUpdated int `json:"last_groups_updated"`

	// What the run attempted. Returned so the portal can explain four zeros
	// instead of showing them and leaving the reader to guess.
	LastUsersSeen    int    `json:"last_users_seen"`
	LastUsersSkipped int    `json:"last_users_skipped"`
	LastUsersFailed  int    `json:"last_users_failed"`
	LastUserError    string `json:"last_user_error,omitempty"`
	LastUsersSyncOff bool   `json:"last_users_sync_off"`
}

// GetSettings handles GET /api/entra-sync.
func (h *EntraSyncHandler) GetSettings(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return
	}

	settings, err := h.store.GetEntraSyncSettings(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load settings"})
		return
	}
	if settings == nil {
		settings = &database.EntraSyncSettings{
			TenantID: tenantID, SyncUsers: true, SyncGroups: true, DefaultRole: "user",
		}
	}

	resolved := h.ResolveCredentials(settings)

	c.JSON(http.StatusOK, entraSyncResponse{
		Enabled:                settings.Enabled,
		DirectoryTenantID:      resolved.TenantID,
		ClientID:               resolved.ClientID,
		HasClientSecret:        resolved.ClientSecret != "",
		SyncUsers:              settings.SyncUsers,
		SyncGroups:             settings.SyncGroups,
		IntervalMinutes:        settings.IntervalMinutes,
		DefaultRole:            settings.DefaultRole,
		GroupFilter:            settings.GroupFilter,
		UsingSharedCredentials: settings.ClientID == "" || settings.ClientSecret == "",
		LastRunAt:              settings.LastRunAt,
		LastStatus:             settings.LastStatus,
		LastError:              settings.LastError,
		LastUsersCreated:       settings.LastUsersCreated,
		LastUsersUpdated:       settings.LastUsersUpdated,
		LastUsersDisabled:      settings.LastUsersDisabled,
		LastGroupsCreated:      settings.LastGroupsCreated,
		LastGroupsUpdated:      settings.LastGroupsUpdated,
		LastUsersSeen:          settings.LastUsersSeen,
		LastUsersSkipped:       settings.LastUsersSkipped,
		LastUsersFailed:        settings.LastUsersFailed,
		LastUserError:          settings.LastUserError,
		LastUsersSyncOff:       settings.LastUsersSyncOff,
	})
}

// SaveSettings handles POST /api/entra-sync.
func (h *EntraSyncHandler) SaveSettings(c *gin.Context) {
	tenantID, ok := h.requireAdmin(c)
	if !ok {
		return
	}

	var body struct {
		Enabled           bool   `json:"enabled"`
		DirectoryTenantID string `json:"directory_tenant_id"`
		ClientID          string `json:"client_id"`
		ClientSecret      string `json:"client_secret"` // empty means keep the stored one
		SyncUsers         bool   `json:"sync_users"`
		SyncGroups        bool   `json:"sync_groups"`
		IntervalMinutes   int    `json:"interval_minutes"`
		DefaultRole       string `json:"default_role"`
		GroupFilter       string `json:"group_filter"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	existing, err := h.store.GetEntraSyncSettings(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load settings"})
		return
	}

	secret := body.ClientSecret
	if secret == "" && existing != nil {
		// An empty field means "leave it alone", not "clear it" — the form
		// never receives the stored value, so it cannot send it back.
		secret = existing.ClientSecret
	}

	role := body.DefaultRole
	if role != database.RoleCompanyAdmin {
		// Only ordinary users and company admins can be provisioned. A super
		// admin is a deliberate, manual act, never a directory side effect.
		role = "user"
	}

	settings := &database.EntraSyncSettings{
		TenantID:          tenantID,
		Enabled:           body.Enabled,
		DirectoryTenantID: strings.TrimSpace(body.DirectoryTenantID),
		ClientID:          strings.TrimSpace(body.ClientID),
		ClientSecret:      secret,
		SyncUsers:         body.SyncUsers,
		SyncGroups:        body.SyncGroups,
		IntervalMinutes:   body.IntervalMinutes,
		DefaultRole:       role,
		GroupFilter:       strings.TrimSpace(body.GroupFilter),
		UpdatedBy:         c.GetString("username"),
	}

	if settings.Enabled && !settings.SyncUsers && !settings.SyncGroups {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Turn on users, groups, or both — otherwise the sync has nothing to do",
		})
		return
	}

	if err := h.store.UpsertEntraSyncSettings(settings); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save settings"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Directory sync settings saved"})
}

// TestConnection handles POST /api/entra-sync/test.
//
// It reads one user rather than only fetching a token, because authenticating
// successfully while the application permissions were never consented is the
// most common half-configured state and a token alone would not catch it.
func (h *EntraSyncHandler) TestConnection(c *gin.Context) {
	tenantID, ok := h.requireAdmin(c)
	if !ok {
		return
	}

	client, err := h.directoryClient(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	if err := client.TestConnection(ctx); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Connected to Microsoft Entra successfully"})
}

// RunNow handles POST /api/entra-sync/run.
func (h *EntraSyncHandler) RunNow(c *gin.Context) {
	tenantID, ok := h.requireAdmin(c)
	if !ok {
		return
	}

	settings, err := h.store.GetEntraSyncSettings(tenantID)
	if err != nil || settings == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Directory sync is not configured"})
		return
	}

	client, err := h.directoryClient(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), manualSyncTimeout)
	defer cancel()

	counts, runErr := h.syncer.Run(ctx, settings, client)

	status, errMsg := "success", ""
	if runErr != nil {
		errMsg = runErr.Error()
		// "partial" rather than "failed" when work was done: a run that
		// provisioned forty people and then lost its connection did forty
		// useful things, and calling that a failure sends somebody hunting.
		status = "failed"
		if counts.UsersCreated+counts.UsersUpdated+counts.GroupsCreated+counts.GroupsUpdated > 0 {
			status = "partial"
		}
	}
	if err := h.store.RecordEntraSyncRun(tenantID, status, errMsg, counts); err != nil {
		h.logger.Warn("Entra sync: could not record the run", zap.Error(err))
	}

	code := http.StatusOK
	if status == "failed" {
		code = http.StatusBadGateway
	}
	c.JSON(code, gin.H{
		"status":         status,
		"error":          errMsg,
		"users_created":  counts.UsersCreated,
		"users_updated":  counts.UsersUpdated,
		"users_disabled": counts.UsersDisabled,
		"groups_created": counts.GroupsCreated,
		"groups_updated": counts.GroupsUpdated,
	})
}

// directoryClient builds a Graph client for a tenant.
func (h *EntraSyncHandler) directoryClient(tenantID string) (*graph.Client, error) {
	settings, err := h.store.GetEntraSyncSettings(tenantID)
	if err != nil {
		return nil, err
	}
	if settings == nil {
		settings = &database.EntraSyncSettings{TenantID: tenantID}
	}
	return graph.New(h.ResolveCredentials(settings))
}

// ResolveCredentials falls back to the sign-in app registration when the sync
// has none of its own.
//
// That fallback is a convenience for the common single-directory deployment,
// not a recommendation: a sign-in registration usually carries only delegated
// permissions, and the sync needs application ones. The settings screen says
// so when the fallback is in use.
func (h *EntraSyncHandler) ResolveCredentials(settings *database.EntraSyncSettings) graph.Config {
	cfg := graph.Config{
		TenantID:     settings.DirectoryTenantID,
		ClientID:     settings.ClientID,
		ClientSecret: settings.ClientSecret,
	}

	shared := resolveOIDCSettings(h.store, h.config)
	if cfg.TenantID == "" {
		cfg.TenantID = shared.MicrosoftTenantID
	}
	if cfg.ClientID == "" {
		cfg.ClientID = shared.MicrosoftClientID
	}
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = shared.MicrosoftClientSecret
	}
	return cfg
}

func (h *EntraSyncHandler) requireAdmin(c *gin.Context) (string, bool) {
	role := c.GetString("role")
	if role != middleware.RoleSuperAdmin && role != database.RoleCompanyAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin access required"})
		return "", false
	}
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id not found in context"})
		return "", false
	}
	return tenantID, true
}

// RegisterEntraSyncRoutes mounts the directory-sync endpoints.
func RegisterEntraSyncRoutes(r *gin.RouterGroup, h *EntraSyncHandler) {
	r.GET("/entra-sync", h.GetSettings)
	r.POST("/entra-sync", h.SaveSettings)
	r.POST("/entra-sync/test", h.TestConnection)
	r.POST("/entra-sync/run", h.RunNow)
}
