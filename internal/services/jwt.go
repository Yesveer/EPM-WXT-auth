package services

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/vsay/vsay-auth/internal/config"
	"github.com/vsay/vsay-auth/internal/database"
)

// JWTClaims represents JWT token claims
type JWTClaims struct {
	UserID       string   `json:"user_id"`
	Username     string   `json:"username"`
	Email        string   `json:"email"`
	TenantID     string   `json:"tenant_id"`
	TenantName   string   `json:"tenant_name"`
	Role         string   `json:"role"`
	MachineRole  string   `json:"machine_role,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	KeycloakID   string   `json:"keycloak_id"`
	Source       string   `json:"source"` // ui, cli, vscode
	jwt.RegisteredClaims
}

// JWTService handles JWT token operations
type JWTService struct {
	secretKey []byte
	expiry    time.Duration
}

func NewJWTService(cfg *config.Config) *JWTService {
	return &JWTService{
		secretKey: []byte(cfg.JWTSecret),
		expiry:    time.Duration(cfg.JWTExpiryHours) * time.Hour,
	}
}

// GenerateToken generates a JWT token for a user
func (j *JWTService) GenerateToken(user *database.User, source string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(j.expiry)

	claims := &JWTClaims{
		UserID:      user.ID.Hex(),
		Username:    user.Username,
		Email:       user.Email,
		TenantID:    user.TenantID,
		TenantName:  user.TenantName,
		Role:        user.Role,
		MachineRole: user.MachineRole,
		Groups:      user.Groups,
		KeycloakID:  user.KeycloakID,
		Source:      source,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "vsay-auth",
			Subject:   user.ID.Hex(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(j.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates and parses a JWT token
func (j *JWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// RefreshToken generates a new token from an existing valid token
func (j *JWTService) RefreshToken(tokenString string) (string, error) {
	claims, err := j.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	// Create new token with fresh expiry
	now := time.Now()
	expiresAt := now.Add(j.expiry)

	newClaims := &JWTClaims{
		UserID:      claims.UserID,
		Username:    claims.Username,
		Email:       claims.Email,
		TenantID:    claims.TenantID,
		TenantName:  claims.TenantName,
		Role:        claims.Role,
		MachineRole: claims.MachineRole,
		Groups:      claims.Groups,
		KeycloakID:  claims.KeycloakID,
		Source:      claims.Source,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "vsay-auth",
			Subject:   claims.UserID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
	tokenString, err = token.SignedString(j.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign refreshed token: %w", err)
	}

	return tokenString, nil
}

// GetTokenExpiry returns the token expiry duration
func (j *JWTService) GetTokenExpiry() time.Duration {
	return j.expiry
}

// ValidateTokenAllowExpired parses and validates a JWT token, allowing expired tokens.
// Used only for token refresh flows — validates the signature but ignores expiry.
func (j *JWTService) ValidateTokenAllowExpired(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	})

	// Allow expired tokens but reject any other error (invalid signature, malformed, etc.)
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if token == nil {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// TenantSelectionClaims for tenant selection short-lived JWT
type TenantSelectionClaims struct {
	Email     string   `json:"email"`
	TenantIDs []string `json:"tenant_ids"`
	jwt.RegisteredClaims
}

// GenerateTenantSelectionToken generates a token encoding the email and list of valid tenant IDs
func (j *JWTService) GenerateTenantSelectionToken(email string, tenantIDs []string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(j.expiry)

	claims := &TenantSelectionClaims{
		Email:     email,
		TenantIDs: tenantIDs,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "vsay-auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(j.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign tenant selection token: %w", err)
	}
	return tokenString, nil
}

// ValidateTenantSelectionToken validates and parses a tenant selection token
func (j *JWTService) ValidateTenantSelectionToken(tokenString string) (*TenantSelectionClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TenantSelectionClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(*TenantSelectionClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}
