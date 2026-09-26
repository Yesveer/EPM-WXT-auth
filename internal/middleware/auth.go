package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-auth/internal/database"
	"github.com/vsay/vsay-auth/internal/metrics"
	"github.com/vsay/vsay-auth/internal/services"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

// apiKeyPrefix identifies a bearer token as a personal access key (see
// internal/api/apikeys.go's APIKeyPrefix) rather than a short-lived JWT.
// Duplicated as a constant here instead of importing internal/api to avoid a
// middleware -> api package dependency cycle (api already imports middleware).
const apiKeyPrefix = "vsay_"

// AuthMiddleware validates either a JWT session token or a personal API key
// (Authorization: Bearer vsay_...) and sets identical user context either way,
// so every existing endpoint keeps working unchanged regardless of which one
// was used.
func AuthMiddleware(jwtService *services.JWTService, store *database.Store, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenString string

		// Check if this is a WebSocket upgrade request
		isWebSocket := c.GetHeader("Upgrade") == "websocket"

		if isWebSocket {
			// For WebSocket connections, check query parameter first (common for WebSocket auth)
			tokenString = c.Query("token")
			if tokenString == "" {
				// Fall back to Authorization header
				authHeader := c.GetHeader("Authorization")
				if authHeader != "" {
					tokenString = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			if tokenString == "" {
				logger.Warn("WebSocket connection without token",
					zap.String("path", c.Request.URL.Path),
					zap.String("ip", c.ClientIP()))
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token required for WebSocket connection (use ?token= query parameter or Authorization header)"})
				c.Abort()
				return
			}
		} else {
			// For regular HTTP requests, require Authorization header
			authHeader := c.GetHeader("Authorization")
			if authHeader == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
				c.Abort()
				return
			}

			// Remove "Bearer " prefix
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format. Use: Bearer <token>"})
				c.Abort()
				return
			}
		}

		// A personal API key (vsay_...) authenticates independently of the JWT
		// path below — no OTP/login flow, just the key itself.
		if strings.HasPrefix(tokenString, apiKeyPrefix) {
			authenticateAPIKey(c, store, tokenString, logger)
			return
		}

		// Validate token
		claims, err := jwtService.ValidateToken(tokenString)
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "expired") {
				metrics.JWTValidationsTotal.WithLabelValues("expired").Inc()
			} else {
				metrics.JWTValidationsTotal.WithLabelValues("failed").Inc()
			}
			logger.Warn("Invalid token",
				zap.Error(err),
				zap.String("ip", c.ClientIP()))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}
		metrics.JWTValidationsTotal.WithLabelValues("success").Inc()

		// Parse user ID
		userID, err := primitive.ObjectIDFromHex(claims.UserID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
			c.Abort()
			return
		}

		// Set user context
		c.Set("user_id", userID)
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)
		c.Set("tenant_id", claims.TenantID)
		c.Set("tenant_name", claims.TenantName)
		c.Set("role", claims.Role)
		c.Set("machine_role", claims.MachineRole)
		c.Set("groups", claims.Groups)
		c.Set("keycloak_id", claims.KeycloakID)
		c.Set("source", claims.Source)

		logger.Debug("User authenticated",
			zap.String("username", claims.Username),
			zap.String("role", claims.Role),
			zap.String("source", claims.Source))

		c.Next()
	}
}

// authenticateAPIKey looks up a personal API key by its hash, checks it hasn't
// expired, loads the still-current User record (so a role change or a
// disabled account takes effect immediately — not just on the key's next
// rotation), and sets the exact same context keys the JWT path does. On any
// failure it writes the 401 response itself; callers should just return.
func authenticateAPIKey(c *gin.Context, store *database.Store, rawKey string, logger *zap.Logger) {
	sum := sha256.Sum256([]byte(rawKey))
	hash := hex.EncodeToString(sum[:])

	key, err := store.GetAPIKeyByHash(hash)
	if err != nil {
		logger.Error("Failed to look up api key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Authentication failed"})
		c.Abort()
		return
	}
	if key == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
		c.Abort()
		return
	}
	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "API key has expired"})
		c.Abort()
		return
	}

	user, err := store.GetUserByID(key.UserID)
	if err != nil || user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
		c.Abort()
		return
	}
	if !user.Enabled {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "This account is disabled"})
		c.Abort()
		return
	}

	c.Set("user_id", user.ID)
	c.Set("username", user.Username)
	c.Set("email", user.Email)
	c.Set("tenant_id", user.TenantID)
	c.Set("tenant_name", user.TenantName)
	c.Set("role", user.Role)
	c.Set("machine_role", user.MachineRole)
	c.Set("groups", user.Groups)
	c.Set("keycloak_id", user.KeycloakID)

	// Callers can identify themselves (e.g. -H "X-Source: my-script") so audit
	// logs show which integration made the call instead of a generic label.
	// A ?source= query param is also accepted — WebSocket clients (like the
	// CLI's terminal connect) can't easily set custom headers, but already
	// pass this on the URL for other reasons.
	source := c.GetHeader("X-Source")
	if source == "" {
		source = c.Query("source")
	}
	if source == "" {
		source = "api_key"
	}
	c.Set("source", source)

	// Best-effort usage tracking — never blocks or fails the request it rides on.
	go func(id primitive.ObjectID) {
		if err := store.UpdateAPIKeyLastUsed(id, time.Now()); err != nil {
			logger.Warn("Failed to update api key last_used_at", zap.Error(err))
		}
	}(key.ID)

	logger.Debug("User authenticated via API key",
		zap.String("username", user.Username),
		zap.String("role", user.Role))

	c.Next()
}

// OptionalAuthMiddleware is like AuthMiddleware but doesn't abort if no token
func OptionalAuthMiddleware(jwtService *services.JWTService, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// No auth header, continue without setting user context
			c.Next()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := jwtService.ValidateToken(tokenString)
		if err != nil {
			// Invalid token, but don't abort
			logger.Warn("Invalid token in optional auth", zap.Error(err))
			c.Next()
			return
		}

		userID, err := primitive.ObjectIDFromHex(claims.UserID)
		if err != nil {
			c.Next()
			return
		}

		// Set user context
		c.Set("user_id", userID)
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)
		c.Set("tenant_id", claims.TenantID)
		c.Set("tenant_name", claims.TenantName)
		c.Set("role", claims.Role)
		c.Set("machine_role", claims.MachineRole)
		c.Set("groups", claims.Groups)
		c.Set("keycloak_id", claims.KeycloakID)
		c.Set("source", claims.Source)

		c.Next()
	}
}

// ExtractSource extracts the source (ui, cli, vscode) from request
func ExtractSource(c *gin.Context) string {
	// Check if already set in context (from JWT)
	if source, exists := c.Get("source"); exists {
		return source.(string)
	}

	// Check X-Source header
	if source := c.GetHeader("X-Source"); source != "" {
		return source
	}

	// Guess from User-Agent
	userAgent := c.Request.UserAgent()
	if strings.Contains(strings.ToLower(userAgent), "vscode") {
		return "vscode"
	}
	if strings.Contains(strings.ToLower(userAgent), "curl") ||
		strings.Contains(strings.ToLower(userAgent), "cli") {
		return "cli"
	}

	// Default to UI
	return "ui"
}
