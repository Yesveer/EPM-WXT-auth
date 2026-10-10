package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-auth/internal/database"
	"go.uber.org/zap"
)

type BrandingHandler struct {
	store  *database.Store
	logger *zap.Logger
}

func NewBrandingHandler(store *database.Store, logger *zap.Logger) *BrandingHandler {
	return &BrandingHandler{store: store, logger: logger}
}

// defaultBranding is what every fresh deployment shows until a super admin
// customizes it via UpdateBranding.
var defaultBranding = gin.H{
	"logo_url":                       "",
	"favicon_url":                    "",
	"name_part1":                     "E",
	"name_part1_color":               "",
	"name_part2":                     "PM",
	"name_part2_color":               "",
	"default_theme_color":            "cyan",
	"default_theme_color_updated_at": "", // never customized — any personal colour a user has is honoured
	"terminal_idle_timeout_minutes":  defaultTerminalIdleTimeoutMinutes,
	"updated_at":                     "", // never customized — any personal colour a user has is honoured
}

// defaultTerminalIdleTimeoutMinutes is how long (minutes) a terminal session
// may sit idle before the frontend closes it, until a super_admin customizes
// it. Enforcement is entirely client-side — this value is just stored and
// served, never acted on here.
const defaultTerminalIdleTimeoutMinutes = 2

// effectiveTerminalIdleTimeoutMinutes treats an unset (zero) stored value as
// "never customized" and falls back to the default, rather than serving 0.
func effectiveTerminalIdleTimeoutMinutes(v int) int {
	if v > 0 {
		return v
	}
	return defaultTerminalIdleTimeoutMinutes
}

func brandingResponse(cfg *database.BrandingConfig) gin.H {
	themeColorUpdatedAt := ""
	if !cfg.DefaultThemeColorUpdatedAt.IsZero() {
		themeColorUpdatedAt = cfg.DefaultThemeColorUpdatedAt.Format(time.RFC3339)
	}
	return gin.H{
		"logo_url":            cfg.LogoURL,
		"favicon_url":         cfg.FaviconURL,
		"name_part1":          cfg.NamePart1,
		"name_part1_color":    cfg.NamePart1Color,
		"name_part2":          cfg.NamePart2,
		"name_part2_color":    cfg.NamePart2Color,
		"default_theme_color": cfg.DefaultThemeColor,
		// Lets clients decide whether a locally-stored personal colour choice
		// predates the last actual color change (stale) or postdates it (still
		// honoured) — deliberately NOT the blanket updated_at below, since that
		// changes on every save (logo, name, ...) unrelated to color.
		"default_theme_color_updated_at": themeColorUpdatedAt,
		"terminal_idle_timeout_minutes":  effectiveTerminalIdleTimeoutMinutes(cfg.TerminalIdleTimeoutMinutes),
		"updated_at":                     cfg.UpdatedAt.Format(time.RFC3339),
	}
}

// GetBranding is PUBLIC (no auth) — the login/signup pages and the browser favicon
// need this before anyone signs in.
func (h *BrandingHandler) GetBranding(c *gin.Context) {
	// This is a cacheable-looking plain GET (no auth, no per-request variation), so
	// tell every layer — browser and any reverse proxy/CDN in front of this
	// service — not to cache it. Otherwise a reset/save can appear to "not take"
	// on the next page load even though the stored config is correct.
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
	c.Header("Pragma", "no-cache")

	cfg, err := h.store.GetBranding()
	if err != nil {
		h.logger.Error("Failed to load branding config", zap.Error(err))
		c.JSON(http.StatusOK, defaultBranding) // fail open with sane defaults
		return
	}
	if cfg == nil {
		c.JSON(http.StatusOK, defaultBranding)
		return
	}
	c.JSON(http.StatusOK, brandingResponse(cfg))
}

// UpdateBrandingRequest represents the branding update payload. Pointer fields
// distinguish "not sent" from "cleared to empty string".
type UpdateBrandingRequest struct {
	LogoURL                    *string `json:"logo_url"`
	FaviconURL                 *string `json:"favicon_url"`
	NamePart1                  *string `json:"name_part1"`
	NamePart1Color             *string `json:"name_part1_color"`
	NamePart2                  *string `json:"name_part2"`
	NamePart2Color             *string `json:"name_part2_color"`
	DefaultThemeColor          *string `json:"default_theme_color"`
	TerminalIdleTimeoutMinutes *int    `json:"terminal_idle_timeout_minutes"`
}

// UpdateBranding — super_admin only.
func (h *BrandingHandler) UpdateBranding(c *gin.Context) {
	var req UpdateBrandingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfg, err := h.store.GetBranding()
	if err != nil {
		h.logger.Error("Failed to load branding config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load branding config"})
		return
	}
	if cfg == nil {
		cfg = &database.BrandingConfig{
			NamePart1:         "E",
			NamePart2:         "PM",
			DefaultThemeColor: "cyan",
		}
	}

	if req.LogoURL != nil {
		cfg.LogoURL = *req.LogoURL
	}
	if req.FaviconURL != nil {
		cfg.FaviconURL = *req.FaviconURL
	}
	if req.NamePart1 != nil {
		cfg.NamePart1 = *req.NamePart1
	}
	if req.NamePart1Color != nil {
		cfg.NamePart1Color = *req.NamePart1Color
	}
	if req.NamePart2 != nil {
		cfg.NamePart2 = *req.NamePart2
	}
	if req.NamePart2Color != nil {
		cfg.NamePart2Color = *req.NamePart2Color
	}
	if req.DefaultThemeColor != nil && *req.DefaultThemeColor != cfg.DefaultThemeColor {
		cfg.DefaultThemeColor = *req.DefaultThemeColor
		cfg.DefaultThemeColorUpdatedAt = time.Now()
	}
	if req.TerminalIdleTimeoutMinutes != nil {
		if *req.TerminalIdleTimeoutMinutes < 1 || *req.TerminalIdleTimeoutMinutes > 240 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "terminal_idle_timeout_minutes must be between 1 and 240"})
			return
		}
		cfg.TerminalIdleTimeoutMinutes = *req.TerminalIdleTimeoutMinutes
	}

	if username, exists := c.Get("username"); exists {
		if u, ok := username.(string); ok {
			cfg.UpdatedBy = u
		}
	}

	if err := h.store.UpsertBranding(cfg); err != nil {
		h.logger.Error("Failed to update branding config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update branding config"})
		return
	}

	h.logger.Info("Branding config updated", zap.String("updated_by", cfg.UpdatedBy))
	c.JSON(http.StatusOK, brandingResponse(cfg))
}

// RegisterBrandingRoutes registers the public read route and the super-admin-only
// write route under the given /api group.
func RegisterBrandingRoutes(r *gin.RouterGroup, handler *BrandingHandler, authMiddleware, superAdminMiddleware gin.HandlerFunc) {
	r.GET("/branding", handler.GetBranding) // public — no auth

	admin := r.Group("/admin")
	admin.Use(authMiddleware)
	admin.Use(superAdminMiddleware)
	{
		admin.PUT("/branding", handler.UpdateBranding)
	}
}
