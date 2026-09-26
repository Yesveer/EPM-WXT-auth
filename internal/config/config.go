package config

import (
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	// Server
	Port        string
	Environment string

	// Keycloak
	KeycloakURL          string
	KeycloakRealm        string
	KeycloakClientID     string
	KeycloakClientSecret string
	KeycloakAdminUser    string
	KeycloakAdminPass    string

	// Super Admin
	SuperAdminUsername string
	SuperAdminEmail    string
	SuperAdminPassword string

	// Backend Services
	VsayAgentBackendURL string
	VsayTunnelURL       string // optional — if empty, /api/deployments/* returns 503
	GatewaySecret       string

	// JWT
	JWTSecret      string
	JWTExpiryHours int

	// Email/SMTP
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string

	// OTP
	OTPEnabled bool

	// MongoDB
	MongoURI              string
	MongoDatabase         string
	OTPExpiryMinutes      int
	ReconcilerIntervalMin int
	ReconcilerEnabled     bool // if false, runs once on startup then stops

	// CORS
	AllowedOrigins []string
	FrontendURL    string

	// OIDC / Social Login
	MicrosoftClientID     string
	MicrosoftClientSecret string
	MicrosoftTenantID     string // Azure AD tenant ID; "common" = multi-tenant, "organizations" = work/school only
	GitHubClientID        string
	GitHubClientSecret    string
	OIDCRedirectBaseURL   string // public base URL of this backend (for OAuth callbacks)
}

func Load() (*Config, error) {
	// Load .env file if exists (for local development)
	_ = godotenv.Load()

	cfg := &Config{
		Port:        getEnv("PORT", "8081"),
		Environment: getEnv("ENVIRONMENT", "development"),

		KeycloakURL:          getEnv("KEYCLOAK_URL", "http://localhost:8080"),
		KeycloakRealm:        getEnv("KEYCLOAK_REALM", "master"),
		KeycloakClientID:     getEnv("KEYCLOAK_CLIENT_ID", "vsay-auth"),
		KeycloakClientSecret: getEnv("KEYCLOAK_CLIENT_SECRET", ""),
		KeycloakAdminUser:    getEnv("KEYCLOAK_ADMIN_USERNAME", "admin"),
		KeycloakAdminPass:    getEnv("KEYCLOAK_ADMIN_PASSWORD", "admin"),

		SuperAdminUsername: getEnv("SUPER_ADMIN_USERNAME", "superadmin"),
		SuperAdminEmail:    getEnv("SUPER_ADMIN_EMAIL", "admin@example.com"),
		SuperAdminPassword: getEnv("SUPER_ADMIN_PASSWORD", "adminpassword"),

		VsayAgentBackendURL: getEnv("VSAY_AGENT_BACKEND_URL", "http://localhost:8082"),
		VsayTunnelURL:       getEnv("VSAY_TUNNEL_URL", ""),
		GatewaySecret:       getEnv("GATEWAY_SECRET", "change-this-secret-in-production"),

		JWTSecret:      getEnv("JWT_SECRET", "your-super-secret-jwt-key"),
		JWTExpiryHours: getEnvInt("JWT_EXPIRY_HOURS", 24),

		SMTPHost:     getEnv("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:     getEnvInt("SMTP_PORT", 587),
		SMTPUsername: getEnv("SMTP_USERNAME", ""),
		SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:     getEnv("SMTP_FROM", "noreply@vsay.com"),

		OTPEnabled: getEnvBool("OTP_ENABLED", true),

		MongoURI:              getEnv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDatabase:         getEnv("MONGO_DATABASE", "vsay_auth"),
		OTPExpiryMinutes:      getEnvInt("OTP_EXPIRY_MINUTES", 10),
		ReconcilerIntervalMin: getEnvInt("RECONCILER_INTERVAL_MINUTES", 5),
		ReconcilerEnabled:     getEnvBool("RECONCILER_ENABLED", true),

		AllowedOrigins: strings.Split(getEnv("ALLOWED_ORIGINS", "http://localhost:3000"), ","),
		FrontendURL:    getEnv("FRONTEND_URL", "http://localhost:3000"),

		MicrosoftClientID:     getEnv("MICROSOFT_CLIENT_ID", ""),
		MicrosoftClientSecret: getEnv("MICROSOFT_CLIENT_SECRET", ""),
		MicrosoftTenantID:     getEnv("MICROSOFT_TENANT_ID", "common"),
		GitHubClientID:        getEnv("GITHUB_CLIENT_ID", ""),
		GitHubClientSecret:    getEnv("GITHUB_CLIENT_SECRET", ""),
		OIDCRedirectBaseURL:   getEnv("OIDC_REDIRECT_BASE_URL", "http://localhost:8082"),
	}

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return strings.EqualFold(value, "true") || value == "1"
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}
