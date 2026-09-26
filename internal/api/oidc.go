package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/vsay/vsay-auth/internal/config"
	"github.com/vsay/vsay-auth/internal/database"
	"github.com/vsay/vsay-auth/internal/services"
	"go.uber.org/zap"
)

const (
	githubAuthURL  = "https://github.com/login/oauth/authorize"
	githubTokenURL = "https://github.com/login/oauth/access_token" // #nosec G101 -- public GitHub OAuth endpoint, not a credential
	githubUserURL  = "https://api.github.com/user"
	githubEmailURL = "https://api.github.com/user/emails"
)

type OIDCHandler struct {
	store      *database.Store
	config     *config.Config
	jwtService *services.JWTService
	logger     *zap.Logger
}

func NewOIDCHandler(
	store *database.Store,
	cfg *config.Config,
	jwtService *services.JWTService,
	logger *zap.Logger,
) *OIDCHandler {
	return &OIDCHandler{
		store:      store,
		config:     cfg,
		jwtService: jwtService,
		logger:     logger,
	}
}

// oidcStateClaims is a short-lived signed JWT used as OAuth2 state (CSRF protection)
type oidcStateClaims struct {
	Provider string `json:"provider"`
	jwt.RegisteredClaims
}

func (h *OIDCHandler) generateState(provider string) (string, error) {
	now := time.Now()
	claims := &oidcStateClaims{
		Provider: provider,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "vsay-oidc-state",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(h.config.JWTSecret))
}

func (h *OIDCHandler) validateState(state, expectedProvider string) error {
	token, err := jwt.ParseWithClaims(state, &oidcStateClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(h.config.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return fmt.Errorf("invalid state")
	}
	claims, ok := token.Claims.(*oidcStateClaims)
	if !ok || claims.Provider != expectedProvider {
		return fmt.Errorf("invalid state provider")
	}
	return nil
}

// microsoftAuthURL builds the tenant-scoped authorization endpoint, falling
// back to the multi-tenant "common" endpoint when no tenant is configured.
func microsoftAuthURL(tenantID string) string {
	if tenantID == "" {
		tenantID = "common"
	}
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenantID)
}

func microsoftTokenURL(tenantID string) string {
	if tenantID == "" {
		tenantID = "common"
	}
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
}

// microsoftCallbackURL builds the redirect_uri for Microsoft
func (h *OIDCHandler) microsoftCallbackURL() string {
	return h.config.OIDCRedirectBaseURL + "/api/auth/oidc/microsoft/callback"
}

// githubCallbackURL builds the redirect_uri for GitHub
func (h *OIDCHandler) githubCallbackURL() string {
	return h.config.OIDCRedirectBaseURL + "/api/auth/oidc/github/callback"
}

// frontendError redirects to frontend with an error message
func (h *OIDCHandler) frontendError(c *gin.Context, msg string) {
	redirectURL := fmt.Sprintf("%s/oauth/callback?error=%s", h.config.FrontendURL, url.QueryEscape(msg))
	c.Redirect(http.StatusFound, redirectURL)
}

// oidcTenantJSON is the tenant info sent to the frontend as base64 JSON
type oidcTenantJSON struct {
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name"`
	Username   string `json:"username"`
	UserID     string `json:"user_id"`
}

// handleOIDCResult is shared logic after the provider returns the user's email
func (h *OIDCHandler) handleOIDCResult(c *gin.Context, email, provider string) {
	email = strings.ToLower(strings.TrimSpace(email))

	// Find all users with this email across all tenants
	users, err := h.store.GetUsersByEmail(email)
	if err != nil || len(users) == 0 {
		h.logger.Warn("OIDC: no account found for email",
			zap.String("email", email),
			zap.String("provider", provider))
		h.frontendError(c, "No account found for this email. Please sign up first.")
		return
	}

	// Keep only enabled users
	var validUsers []*database.User
	for _, u := range users {
		if u.Enabled {
			validUsers = append(validUsers, u)
		}
	}
	if len(validUsers) == 0 {
		h.frontendError(c, "Your account is disabled. Please contact your administrator.")
		return
	}

	// Build tenant IDs and info list
	tenantIDs := make([]string, len(validUsers))
	tenantList := make([]oidcTenantJSON, len(validUsers))
	for i, u := range validUsers {
		tenantIDs[i] = u.TenantID
		tenantList[i] = oidcTenantJSON{
			TenantID:   u.TenantID,
			TenantName: u.TenantName,
			Username:   u.Username,
			UserID:     u.ID.Hex(),
		}
	}

	// Generate session token (same as email-login flow)
	sessionToken, err := h.jwtService.GenerateTenantSelectionToken(email, tenantIDs)
	if err != nil {
		h.frontendError(c, "Authentication failed. Please try again.")
		return
	}

	// Encode tenants as base64 JSON for URL param
	tenantsJSON, _ := json.Marshal(tenantList)
	tenantsB64 := base64.URLEncoding.EncodeToString(tenantsJSON)

	if len(validUsers) > 1 {
		// Multiple tenants — frontend shows workspace picker
		redirectURL := fmt.Sprintf("%s/oauth/callback?session_token=%s&tenants=%s&requires_selection=true",
			h.config.FrontendURL,
			url.QueryEscape(sessionToken),
			url.QueryEscape(tenantsB64))
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	// Single tenant — generate token directly and redirect with everything
	user := validUsers[0]
	token, err := h.jwtService.GenerateToken(user, "ui")
	if err != nil {
		h.frontendError(c, "Failed to generate token. Please try again.")
		return
	}
	_ = h.store.UpdateUserLastLogin(user.ID)

	userMap := map[string]interface{}{
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
	userJSON, _ := json.Marshal(userMap)
	userB64 := base64.URLEncoding.EncodeToString(userJSON)

	redirectURL := fmt.Sprintf("%s/oauth/callback?token=%s&session_token=%s&user=%s&tenants=%s",
		h.config.FrontendURL,
		url.QueryEscape(token),
		url.QueryEscape(sessionToken),
		url.QueryEscape(userB64),
		url.QueryEscape(tenantsB64))
	c.Redirect(http.StatusFound, redirectURL)
}

// ─── Microsoft ────────────────────────────────────────────────────────────────

// MicrosoftLogin redirects the user to Microsoft's OAuth2 authorization page
func (h *OIDCHandler) MicrosoftLogin(c *gin.Context) {
	settings := resolveOIDCSettings(h.store, h.config)
	if !settings.MicrosoftEnabled {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "Microsoft login is not configured"})
		return
	}

	state, err := h.generateState("microsoft")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state"})
		return
	}

	params := url.Values{}
	params.Set("client_id", settings.MicrosoftClientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", h.microsoftCallbackURL())
	// Use only openid/profile/email — no User.Read, so no admin consent needed
	params.Set("scope", "openid profile email")
	params.Set("state", state)
	params.Set("response_mode", "query")
	// Always show account picker so users can choose personal or work accounts
	params.Set("prompt", "select_account")

	c.Redirect(http.StatusFound, microsoftAuthURL(settings.MicrosoftTenantID)+"?"+params.Encode())
}

// MicrosoftCallback handles the OAuth2 callback from Microsoft
func (h *OIDCHandler) MicrosoftCallback(c *gin.Context) {
	if errParam := c.Query("error"); errParam != "" {
		errDesc := c.Query("error_description")
		h.logger.Warn("Microsoft OAuth error",
			zap.String("error", errParam),
			zap.String("description", errDesc))
		h.frontendError(c, fmt.Sprintf("Microsoft error: %s — %s", errParam, errDesc))
		return
	}

	if err := h.validateState(c.Query("state"), "microsoft"); err != nil {
		h.frontendError(c, "Invalid state. Please try again.")
		return
	}

	settings := resolveOIDCSettings(h.store, h.config)
	if !settings.MicrosoftEnabled {
		h.frontendError(c, "Microsoft login is not configured.")
		return
	}

	// Exchange authorization code for tokens
	tokenData := url.Values{}
	tokenData.Set("client_id", settings.MicrosoftClientID)
	tokenData.Set("client_secret", settings.MicrosoftClientSecret)
	tokenData.Set("code", c.Query("code"))
	tokenData.Set("redirect_uri", h.microsoftCallbackURL())
	tokenData.Set("grant_type", "authorization_code")

	resp, err := http.PostForm(microsoftTokenURL(settings.MicrosoftTenantID), tokenData)
	if err != nil {
		h.logger.Error("Microsoft token exchange failed", zap.Error(err))
		h.frontendError(c, "Failed to exchange authorization code.")
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var tokenResp struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		ErrDesc string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil || tokenResp.IDToken == "" {
		h.logger.Error("Microsoft token parse failed",
			zap.String("error", tokenResp.Error),
			zap.String("desc", tokenResp.ErrDesc),
			zap.String("body", string(body)))
		h.frontendError(c, fmt.Sprintf("Microsoft token error: %s — %s", tokenResp.Error, tokenResp.ErrDesc))
		return
	}

	// Extract email from the id_token JWT payload (no Graph API call needed)
	email, name := parseMicrosoftIDToken(tokenResp.IDToken)
	if email == "" {
		h.logger.Error("Microsoft id_token missing email", zap.String("id_token", tokenResp.IDToken))
		h.frontendError(c, "Could not retrieve email from Microsoft account.")
		return
	}

	h.logger.Info("Microsoft OIDC authenticated",
		zap.String("email", email),
		zap.String("name", name))

	h.handleOIDCResult(c, email, "microsoft")
}

// parseMicrosoftIDToken decodes the JWT payload of an id_token to extract email and name.
// The token is received directly from Microsoft's token endpoint over TLS during a
// server-side code exchange, so we trust it without re-verifying the signature.
func parseMicrosoftIDToken(idToken string) (email, name string) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return
	}
	// JWT payload is base64url encoded (no padding)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}
	var claims struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	if json.Unmarshal(payload, &claims) == nil {
		email = claims.Email
		if email == "" {
			// Work/school accounts may only have preferred_username
			email = claims.PreferredUsername
		}
		name = claims.Name
	}
	return
}

// ─── GitHub ───────────────────────────────────────────────────────────────────

// GitHubLogin redirects the user to GitHub's OAuth2 authorization page
func (h *OIDCHandler) GitHubLogin(c *gin.Context) {
	settings := resolveOIDCSettings(h.store, h.config)
	if !settings.GitHubEnabled {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "GitHub login is not configured"})
		return
	}

	state, err := h.generateState("github")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state"})
		return
	}

	params := url.Values{}
	params.Set("client_id", settings.GitHubClientID)
	params.Set("redirect_uri", h.githubCallbackURL())
	params.Set("scope", "user:email read:user")
	params.Set("state", state)

	c.Redirect(http.StatusFound, githubAuthURL+"?"+params.Encode())
}

// GitHubCallback handles the OAuth2 callback from GitHub
func (h *OIDCHandler) GitHubCallback(c *gin.Context) {
	if errParam := c.Query("error"); errParam != "" {
		errDesc := c.Query("error_description")
		h.logger.Warn("GitHub OAuth error",
			zap.String("error", errParam),
			zap.String("description", errDesc))
		h.frontendError(c, fmt.Sprintf("GitHub error: %s — %s", errParam, errDesc))
		return
	}

	if err := h.validateState(c.Query("state"), "github"); err != nil {
		h.frontendError(c, "Invalid state. Please try again.")
		return
	}

	settings := resolveOIDCSettings(h.store, h.config)
	if !settings.GitHubEnabled {
		h.frontendError(c, "GitHub login is not configured.")
		return
	}

	// Exchange authorization code for access token
	tokenData := url.Values{}
	tokenData.Set("client_id", settings.GitHubClientID)
	tokenData.Set("client_secret", settings.GitHubClientSecret)
	tokenData.Set("code", c.Query("code"))
	tokenData.Set("redirect_uri", h.githubCallbackURL())

	client := &http.Client{}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, githubTokenURL, strings.NewReader(tokenData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		h.logger.Error("GitHub token exchange failed", zap.Error(err))
		h.frontendError(c, "Failed to exchange authorization code.")
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil || tokenResp.AccessToken == "" {
		h.logger.Error("GitHub token parse failed",
			zap.String("error", tokenResp.Error),
			zap.String("body", string(body)))
		h.frontendError(c, fmt.Sprintf("GitHub token error: %s (raw: %s)", tokenResp.Error, string(body)))
		return
	}

	// Fetch user profile
	userReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, githubUserURL, nil)
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	userReq.Header.Set("Accept", "application/json")

	userResp, err := client.Do(userReq)
	if err != nil {
		h.logger.Error("GitHub user request failed", zap.Error(err))
		h.frontendError(c, "Failed to get user info from GitHub.")
		return
	}
	defer userResp.Body.Close()

	userBody, _ := io.ReadAll(userResp.Body)
	var ghUser struct {
		Email string `json:"email"`
		Name  string `json:"name"`
		Login string `json:"login"`
	}
	if err := json.Unmarshal(userBody, &ghUser); err != nil {
		h.logger.Warn("Failed to parse GitHub user response", zap.Error(err))
	}

	email := ghUser.Email

	// GitHub users may have private email — fetch from /user/emails
	if email == "" {
		emailReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, githubEmailURL, nil)
		emailReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
		emailReq.Header.Set("Accept", "application/json")

		emailResp, err := client.Do(emailReq)
		if err == nil {
			defer emailResp.Body.Close()
			emailBody, _ := io.ReadAll(emailResp.Body)
			var emails []struct {
				Email   string `json:"email"`
				Primary bool   `json:"primary"`
			}
			if json.Unmarshal(emailBody, &emails) == nil {
				for _, e := range emails {
					if e.Primary {
						email = e.Email
						break
					}
				}
				if email == "" && len(emails) > 0 {
					email = emails[0].Email
				}
			}
		}
	}

	if email == "" {
		h.frontendError(c, "Could not retrieve email from GitHub. Please make your email public or grant email access.")
		return
	}

	h.logger.Info("GitHub OIDC authenticated",
		zap.String("email", email),
		zap.String("login", ghUser.Login))

	h.handleOIDCResult(c, email, "github")
}

// RegisterOIDCRoutes registers Microsoft and GitHub OAuth2 routes
func RegisterOIDCRoutes(r *gin.RouterGroup, handler *OIDCHandler) {
	oidc := r.Group("/auth/oidc")
	{
		oidc.GET("/microsoft", handler.MicrosoftLogin)
		oidc.GET("/microsoft/callback", handler.MicrosoftCallback)
		oidc.GET("/github", handler.GitHubLogin)
		oidc.GET("/github/callback", handler.GitHubCallback)
	}
}
