package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-auth/internal/config"
	"github.com/vsay/vsay-auth/internal/database"
	"go.uber.org/zap"
)

// resolvedOIDCSettings is the effective Microsoft/GitHub OIDC configuration:
// the stored document's values, falling back field-by-field to the
// env-loaded config.Config for anything never customized (including the
// whole document being absent). OIDCHandler's login/callback handlers and
// OIDCSettingsHandler's admin CRUD both read through this single function so
// they can never disagree about what's "currently enabled".
type resolvedOIDCSettings struct {
	MicrosoftEnabled      bool
	MicrosoftClientID     string
	MicrosoftClientSecret string
	MicrosoftTenantID     string
	GitHubEnabled         bool
	GitHubClientID        string
	GitHubClientSecret    string
	HasMicrosoftSecret    bool
	HasGitHubSecret       bool
	UpdatedAt             time.Time
	UpdatedBy             string
}

func resolveOIDCSettings(store *database.Store, cfg *config.Config) resolvedOIDCSettings {
	settings, err := store.GetOIDCSettings()
	if err != nil || settings == nil {
		return resolvedOIDCSettings{
			MicrosoftEnabled:      cfg.MicrosoftClientID != "" && cfg.MicrosoftClientSecret != "",
			MicrosoftClientID:     cfg.MicrosoftClientID,
			MicrosoftClientSecret: cfg.MicrosoftClientSecret,
			MicrosoftTenantID:     cfg.MicrosoftTenantID,
			GitHubEnabled:         cfg.GitHubClientID != "" && cfg.GitHubClientSecret != "",
			GitHubClientID:        cfg.GitHubClientID,
			GitHubClientSecret:    cfg.GitHubClientSecret,
			HasMicrosoftSecret:    cfg.MicrosoftClientSecret != "",
			HasGitHubSecret:       cfg.GitHubClientSecret != "",
		}
	}
	return resolvedOIDCSettings{
		MicrosoftEnabled:      settings.MicrosoftEnabled,
		MicrosoftClientID:     settings.MicrosoftClientID,
		MicrosoftClientSecret: settings.MicrosoftClientSecret,
		MicrosoftTenantID:     settings.MicrosoftTenantID,
		GitHubEnabled:         settings.GitHubEnabled,
		GitHubClientID:        settings.GitHubClientID,
		GitHubClientSecret:    settings.GitHubClientSecret,
		HasMicrosoftSecret:    settings.MicrosoftClientSecret != "",
		HasGitHubSecret:       settings.GitHubClientSecret != "",
		UpdatedAt:             settings.UpdatedAt,
		UpdatedBy:             settings.UpdatedBy,
	}
}

// OIDCSettingsHandler lets a super_admin manage the Microsoft/GitHub social
// login buttons — enable/disable each and set its OAuth app credentials —
// from the UI instead of server env vars.
type OIDCSettingsHandler struct {
	store  *database.Store
	config *config.Config
	logger *zap.Logger
}

func NewOIDCSettingsHandler(store *database.Store, cfg *config.Config, logger *zap.Logger) *OIDCSettingsHandler {
	return &OIDCSettingsHandler{store: store, config: cfg, logger: logger}
}

// GetProviders is PUBLIC (no auth) — the login page needs to know which
// buttons to show before anyone signs in. Fails CLOSED (both false) on any
// error, since a broken-looking disabled button is safer than a button that
// 501s when clicked.
func (h *OIDCSettingsHandler) GetProviders(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
	c.Header("Pragma", "no-cache")

	if _, err := h.store.GetOIDCSettings(); err != nil {
		h.logger.Error("Failed to load OIDC settings", zap.Error(err))
		c.JSON(http.StatusOK, gin.H{"microsoft_enabled": false, "github_enabled": false})
		return
	}
	r := resolveOIDCSettings(h.store, h.config)
	c.JSON(http.StatusOK, gin.H{
		"microsoft_enabled": r.MicrosoftEnabled,
		"github_enabled":    r.GitHubEnabled,
	})
}

func oidcSettingsResponse(r resolvedOIDCSettings) gin.H {
	resp := gin.H{
		"microsoft_enabled":           r.MicrosoftEnabled,
		"microsoft_client_id":         r.MicrosoftClientID,
		"microsoft_client_secret_set": r.HasMicrosoftSecret,
		"microsoft_tenant_id":         r.MicrosoftTenantID,
		"github_enabled":              r.GitHubEnabled,
		"github_client_id":            r.GitHubClientID,
		"github_client_secret_set":    r.HasGitHubSecret,
		"updated_by":                  r.UpdatedBy,
	}
	if !r.UpdatedAt.IsZero() {
		resp["updated_at"] = r.UpdatedAt.Format(time.RFC3339)
	} else {
		resp["updated_at"] = ""
	}
	return resp
}

// GetOIDCSettings — super_admin only. Never returns raw client secrets, only
// whether one is currently set.
func (h *OIDCSettingsHandler) GetOIDCSettings(c *gin.Context) {
	c.JSON(http.StatusOK, oidcSettingsResponse(resolveOIDCSettings(h.store, h.config)))
}

// UpdateOIDCSettingsRequest — pointer fields distinguish "not sent" from
// "cleared". Client secrets are only overwritten when non-empty, so a save
// never has to re-supply an already-configured secret.
type UpdateOIDCSettingsRequest struct {
	MicrosoftEnabled      *bool   `json:"microsoft_enabled"`
	MicrosoftClientID     *string `json:"microsoft_client_id"`
	MicrosoftClientSecret *string `json:"microsoft_client_secret"`
	MicrosoftTenantID     *string `json:"microsoft_tenant_id"`
	GitHubEnabled         *bool   `json:"github_enabled"`
	GitHubClientID        *string `json:"github_client_id"`
	GitHubClientSecret    *string `json:"github_client_secret"`
}

// UpdateOIDCSettings — super_admin only.
func (h *OIDCSettingsHandler) UpdateOIDCSettings(c *gin.Context) {
	var req UpdateOIDCSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	existing, err := h.store.GetOIDCSettings()
	if err != nil {
		h.logger.Error("Failed to load OIDC settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load OIDC settings"})
		return
	}

	// Start from the effective (env-fallback-resolved) values so a partial
	// update never blanks out fields the admin didn't touch.
	current := resolveOIDCSettings(h.store, h.config)
	settings := &database.OIDCSettings{
		MicrosoftEnabled:      current.MicrosoftEnabled,
		MicrosoftClientID:     current.MicrosoftClientID,
		MicrosoftClientSecret: current.MicrosoftClientSecret,
		MicrosoftTenantID:     current.MicrosoftTenantID,
		GitHubEnabled:         current.GitHubEnabled,
		GitHubClientID:        current.GitHubClientID,
		GitHubClientSecret:    current.GitHubClientSecret,
	}
	if existing != nil {
		settings.ID = existing.ID
	}

	if req.MicrosoftClientID != nil {
		settings.MicrosoftClientID = *req.MicrosoftClientID
	}
	if req.MicrosoftClientSecret != nil && *req.MicrosoftClientSecret != "" {
		settings.MicrosoftClientSecret = *req.MicrosoftClientSecret
	}
	if req.MicrosoftTenantID != nil {
		settings.MicrosoftTenantID = *req.MicrosoftTenantID
	}
	if req.GitHubClientID != nil {
		settings.GitHubClientID = *req.GitHubClientID
	}
	if req.GitHubClientSecret != nil && *req.GitHubClientSecret != "" {
		settings.GitHubClientSecret = *req.GitHubClientSecret
	}

	// Enabling a provider requires a usable OAuth app config — otherwise the
	// login button would show but 501 on click.
	if req.MicrosoftEnabled != nil && *req.MicrosoftEnabled {
		if settings.MicrosoftClientID == "" || settings.MicrosoftClientSecret == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Microsoft client ID and client secret are required to enable Microsoft login"})
			return
		}
	}
	if req.GitHubEnabled != nil && *req.GitHubEnabled {
		if settings.GitHubClientID == "" || settings.GitHubClientSecret == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "GitHub client ID and client secret are required to enable GitHub login"})
			return
		}
	}
	if req.MicrosoftEnabled != nil {
		settings.MicrosoftEnabled = *req.MicrosoftEnabled
	}
	if req.GitHubEnabled != nil {
		settings.GitHubEnabled = *req.GitHubEnabled
	}

	if username, exists := c.Get("username"); exists {
		if u, ok := username.(string); ok {
			settings.UpdatedBy = u
		}
	}

	if err := h.store.UpsertOIDCSettings(settings); err != nil {
		h.logger.Error("Failed to update OIDC settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update OIDC settings"})
		return
	}

	h.logger.Info("OIDC settings updated",
		zap.String("updated_by", settings.UpdatedBy),
		zap.Bool("microsoft_enabled", settings.MicrosoftEnabled),
		zap.Bool("github_enabled", settings.GitHubEnabled))
	c.JSON(http.StatusOK, oidcSettingsResponse(resolveOIDCSettings(h.store, h.config)))
}

// RegisterOIDCSettingsRoutes registers the public providers-list route and
// the super-admin-only read/write settings routes.
func RegisterOIDCSettingsRoutes(r *gin.RouterGroup, handler *OIDCSettingsHandler, authMiddleware, superAdminMiddleware gin.HandlerFunc) {
	r.GET("/oidc/providers", handler.GetProviders) // public — no auth

	admin := r.Group("/admin")
	admin.Use(authMiddleware)
	admin.Use(superAdminMiddleware)
	{
		admin.GET("/oidc-settings", handler.GetOIDCSettings)
		admin.PUT("/oidc-settings", handler.UpdateOIDCSettings)
	}
}
