package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-auth/internal/config"
	"github.com/vsay/vsay-auth/internal/database"
	"go.uber.org/zap"
)

// MFASettingsHandler lets a super_admin manage OTP/email-2FA and the SMTP
// credentials used to send it, from the UI instead of server env vars.
type MFASettingsHandler struct {
	store  *database.Store
	config *config.Config
	logger *zap.Logger
}

func NewMFASettingsHandler(store *database.Store, cfg *config.Config, logger *zap.Logger) *MFASettingsHandler {
	return &MFASettingsHandler{store: store, config: cfg, logger: logger}
}

// resolved is the effective MFA configuration: the stored document's values,
// falling back field-by-field to the env-loaded config.Config for anything
// never customized (including the whole document being absent).
type resolvedMFASettings struct {
	OTPEnabled       bool
	OTPExpiryMinutes int
	SMTPHost         string
	SMTPPort         int
	SMTPUsername     string
	SMTPPassword     string
	SMTPFrom         string
	HasPassword      bool
	UpdatedAt        time.Time
	UpdatedBy        string
}

func (h *MFASettingsHandler) resolve(cfg *database.MFASettings) resolvedMFASettings {
	if cfg == nil {
		return resolvedMFASettings{
			OTPEnabled:       h.config.OTPEnabled,
			OTPExpiryMinutes: h.config.OTPExpiryMinutes,
			SMTPHost:         h.config.SMTPHost,
			SMTPPort:         h.config.SMTPPort,
			SMTPUsername:     h.config.SMTPUsername,
			SMTPPassword:     h.config.SMTPPassword,
			SMTPFrom:         h.config.SMTPFrom,
			HasPassword:      h.config.SMTPPassword != "",
		}
	}
	return resolvedMFASettings{
		OTPEnabled:       cfg.OTPEnabled,
		OTPExpiryMinutes: cfg.OTPExpiryMinutes,
		SMTPHost:         cfg.SMTPHost,
		SMTPPort:         cfg.SMTPPort,
		SMTPUsername:     cfg.SMTPUsername,
		SMTPPassword:     cfg.SMTPPassword,
		SMTPFrom:         cfg.SMTPFrom,
		HasPassword:      cfg.SMTPPassword != "",
		UpdatedAt:        cfg.UpdatedAt,
		UpdatedBy:        cfg.UpdatedBy,
	}
}

func mfaSettingsResponse(r resolvedMFASettings) gin.H {
	resp := gin.H{
		"otp_enabled":        r.OTPEnabled,
		"otp_expiry_minutes": r.OTPExpiryMinutes,
		"smtp_host":          r.SMTPHost,
		"smtp_port":          r.SMTPPort,
		"smtp_username":      r.SMTPUsername,
		"smtp_password_set":  r.HasPassword,
		"smtp_from":          r.SMTPFrom,
		"updated_by":         r.UpdatedBy,
	}
	if !r.UpdatedAt.IsZero() {
		resp["updated_at"] = r.UpdatedAt.Format(time.RFC3339)
	} else {
		resp["updated_at"] = ""
	}
	return resp
}

// GetMFASettings — super_admin only. Never returns the raw SMTP password,
// only whether one is currently set.
func (h *MFASettingsHandler) GetMFASettings(c *gin.Context) {
	cfg, err := h.store.GetMFASettings()
	if err != nil {
		h.logger.Error("Failed to load MFA settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load MFA settings"})
		return
	}
	c.JSON(http.StatusOK, mfaSettingsResponse(h.resolve(cfg)))
}

// UpdateMFASettingsRequest — pointer fields distinguish "not sent" from
// "cleared". SMTPPassword is only overwritten when non-empty, so a save
// never has to re-supply an already-configured password.
type UpdateMFASettingsRequest struct {
	OTPEnabled       *bool   `json:"otp_enabled"`
	OTPExpiryMinutes *int    `json:"otp_expiry_minutes"`
	SMTPHost         *string `json:"smtp_host"`
	SMTPPort         *int    `json:"smtp_port"`
	SMTPUsername     *string `json:"smtp_username"`
	SMTPPassword     *string `json:"smtp_password"`
	SMTPFrom         *string `json:"smtp_from"`
}

// UpdateMFASettings — super_admin only.
func (h *MFASettingsHandler) UpdateMFASettings(c *gin.Context) {
	var req UpdateMFASettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	existing, err := h.store.GetMFASettings()
	if err != nil {
		h.logger.Error("Failed to load MFA settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load MFA settings"})
		return
	}

	// Start from the effective (env-fallback-resolved) values so a partial
	// update never blanks out fields the admin didn't touch.
	current := h.resolve(existing)
	cfg := &database.MFASettings{
		OTPEnabled:       current.OTPEnabled,
		OTPExpiryMinutes: current.OTPExpiryMinutes,
		SMTPHost:         current.SMTPHost,
		SMTPPort:         current.SMTPPort,
		SMTPUsername:     current.SMTPUsername,
		SMTPPassword:     current.SMTPPassword,
		SMTPFrom:         current.SMTPFrom,
	}
	if existing != nil {
		cfg.ID = existing.ID
	}

	if req.OTPExpiryMinutes != nil {
		if *req.OTPExpiryMinutes < 1 || *req.OTPExpiryMinutes > 60 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "otp_expiry_minutes must be between 1 and 60"})
			return
		}
		cfg.OTPExpiryMinutes = *req.OTPExpiryMinutes
	}
	if req.SMTPHost != nil {
		cfg.SMTPHost = *req.SMTPHost
	}
	if req.SMTPPort != nil {
		if *req.SMTPPort < 1 || *req.SMTPPort > 65535 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "smtp_port must be between 1 and 65535"})
			return
		}
		cfg.SMTPPort = *req.SMTPPort
	}
	if req.SMTPUsername != nil {
		cfg.SMTPUsername = *req.SMTPUsername
	}
	if req.SMTPPassword != nil && *req.SMTPPassword != "" {
		cfg.SMTPPassword = *req.SMTPPassword
	}
	if req.SMTPFrom != nil {
		cfg.SMTPFrom = *req.SMTPFrom
	}

	// Enabling OTP requires a usable SMTP config — otherwise every login
	// would silently fail to send its OTP email.
	enabling := req.OTPEnabled != nil && *req.OTPEnabled
	if enabling && (cfg.SMTPHost == "" || cfg.SMTPUsername == "" || cfg.SMTPPassword == "" || cfg.SMTPFrom == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SMTP host, username, password and from-address are required to enable OTP"})
		return
	}
	if req.OTPEnabled != nil {
		cfg.OTPEnabled = *req.OTPEnabled
	}

	if username, exists := c.Get("username"); exists {
		if u, ok := username.(string); ok {
			cfg.UpdatedBy = u
		}
	}

	if err := h.store.UpsertMFASettings(cfg); err != nil {
		h.logger.Error("Failed to update MFA settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update MFA settings"})
		return
	}

	h.logger.Info("MFA settings updated", zap.String("updated_by", cfg.UpdatedBy), zap.Bool("otp_enabled", cfg.OTPEnabled))
	c.JSON(http.StatusOK, mfaSettingsResponse(h.resolve(cfg)))
}

// RegisterMFASettingsRoutes registers both routes under /admin — super_admin
// only for read too, since the response (indirectly) reflects live SMTP config.
func RegisterMFASettingsRoutes(r *gin.RouterGroup, handler *MFASettingsHandler, authMiddleware, superAdminMiddleware gin.HandlerFunc) {
	admin := r.Group("/admin")
	admin.Use(authMiddleware)
	admin.Use(superAdminMiddleware)
	{
		admin.GET("/mfa-settings", handler.GetMFASettings)
		admin.PUT("/mfa-settings", handler.UpdateMFASettings)
	}
}
