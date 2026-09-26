package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-auth/internal/database"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

// MaxAPIKeysPerUser caps how many personal access keys a single user may have
// active at once (mirrors GitHub-style token limits, keeps the list manageable).
const MaxAPIKeysPerUser = 5

// APIKeyPrefix identifies a bearer token as a personal access key rather than a
// short-lived JWT — AuthMiddleware branches on this exact prefix.
const APIKeyPrefix = "vsay_"

type APIKeysHandler struct {
	store  *database.Store
	logger *zap.Logger
}

func NewAPIKeysHandler(store *database.Store, logger *zap.Logger) *APIKeysHandler {
	return &APIKeysHandler{store: store, logger: logger}
}

// generateAPIKey returns a fresh random key plus the hash that gets stored.
// High-entropy tokens like this are looked up by exact hash match, so a fast
// hash (SHA-256) is the right tool here — not bcrypt, which is for slow-hashing
// low-entropy human passwords and can't be queried by value anyway.
func generateAPIKey() (raw string, hash string) {
	buf := make([]byte, 24) // 24 random bytes -> 48 hex chars
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand.Read failing means the OS RNG is broken — nothing sane to
		// do but panic; this should never happen in practice.
		panic("failed to read random bytes for api key: " + err.Error())
	}
	raw = APIKeyPrefix + hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return raw, hash
}

func hashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func keyPrefixForDisplay(raw string) string {
	if len(raw) <= 12 {
		return raw
	}
	return raw[:12]
}

func apiKeyResponse(k *database.APIKey) gin.H {
	resp := gin.H{
		"id":         k.ID.Hex(),
		"name":       k.Name,
		"key_prefix": k.KeyPrefix,
		"created_at": k.CreatedAt.Format(time.RFC3339),
	}
	if k.ExpiresAt != nil {
		resp["expires_at"] = k.ExpiresAt.Format(time.RFC3339)
	} else {
		resp["expires_at"] = nil
	}
	if k.LastUsedAt != nil {
		resp["last_used_at"] = k.LastUsedAt.Format(time.RFC3339)
	} else {
		resp["last_used_at"] = nil
	}
	return resp
}

// GET /api/api-keys — the caller's own keys, never including any raw value.
func (h *APIKeysHandler) ListAPIKeys(c *gin.Context) {
	userID := c.MustGet("user_id").(primitive.ObjectID)

	keys, err := h.store.ListAPIKeysByUser(userID)
	if err != nil {
		h.logger.Error("Failed to list api keys", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list API keys"})
		return
	}

	out := make([]gin.H, 0, len(keys))
	for _, k := range keys {
		out = append(out, apiKeyResponse(k))
	}
	c.JSON(http.StatusOK, gin.H{"keys": out, "total": len(out)})
}

type createAPIKeyRequest struct {
	Name string `json:"name" binding:"required"`
	// ExpiresInDays: nil or 0 means "never expires". Otherwise the number of
	// days from now until the key stops working.
	ExpiresInDays *int `json:"expires_in_days"`
}

// POST /api/api-keys — creates a new key and returns the raw value exactly
// once. It is not recoverable after this response; only its hash is stored.
func (h *APIKeysHandler) CreateAPIKey(c *gin.Context) {
	userID := c.MustGet("user_id").(primitive.ObjectID)
	tenantID := c.GetString("tenant_id")

	var req createAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	name := strings.TrimSpace(req.Name)
	if len(name) < 1 || len(name) > 60 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name must be between 1 and 60 characters"})
		return
	}

	if req.ExpiresInDays != nil && (*req.ExpiresInDays < 0 || *req.ExpiresInDays > 3650) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expires_in_days must be between 0 and 3650"})
		return
	}

	count, err := h.store.CountAPIKeysByUser(userID)
	if err != nil {
		h.logger.Error("Failed to count api keys", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}
	if count >= MaxAPIKeysPerUser {
		c.JSON(http.StatusConflict, gin.H{"error": "You already have the maximum of 5 API keys — revoke one before creating another"})
		return
	}

	raw, hash := generateAPIKey()

	key := &database.APIKey{
		UserID:    userID,
		TenantID:  tenantID,
		Name:      name,
		KeyHash:   hash,
		KeyPrefix: keyPrefixForDisplay(raw),
	}
	if req.ExpiresInDays != nil && *req.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, *req.ExpiresInDays)
		key.ExpiresAt = &t
	}

	if err := h.store.CreateAPIKey(key); err != nil {
		h.logger.Error("Failed to create api key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}

	h.logger.Info("API key created", zap.String("user_id", userID.Hex()), zap.String("name", name))

	resp := apiKeyResponse(key)
	resp["key"] = raw // present only in this one response, never again
	c.JSON(http.StatusCreated, resp)
}

// DELETE /api/api-keys/:id — revokes (deletes) a key the caller owns.
func (h *APIKeysHandler) DeleteAPIKey(c *gin.Context) {
	userID := c.MustGet("user_id").(primitive.ObjectID)

	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid key id"})
		return
	}

	key, err := h.store.GetAPIKeyByID(id)
	if err != nil {
		h.logger.Error("Failed to look up api key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke API key"})
		return
	}
	if key == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
		return
	}
	if key.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "not authorized"})
		return
	}

	if err := h.store.DeleteAPIKey(id); err != nil {
		h.logger.Error("Failed to delete api key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke API key"})
		return
	}

	h.logger.Info("API key revoked", zap.String("user_id", userID.Hex()), zap.String("key_id", id.Hex()))
	c.JSON(http.StatusOK, gin.H{"message": "API key revoked"})
}

// RegisterAPIKeysRoutes — self-service: every authenticated user manages only
// their own keys, no admin middleware needed.
func RegisterAPIKeysRoutes(r *gin.RouterGroup, handler *APIKeysHandler, authMiddleware gin.HandlerFunc) {
	keys := r.Group("/api-keys")
	keys.Use(authMiddleware)
	{
		keys.GET("", handler.ListAPIKeys)
		keys.POST("", handler.CreateAPIKey)
		keys.DELETE("/:id", handler.DeleteAPIKey)
	}
}
