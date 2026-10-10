package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vsay/vsay-auth/internal/api"
	"github.com/vsay/vsay-auth/internal/config"
	"github.com/vsay/vsay-auth/internal/database"
	"github.com/vsay/vsay-auth/internal/entrasync"
	"github.com/vsay/vsay-auth/internal/keycloak"
	_ "github.com/vsay/vsay-auth/internal/metrics"
	"github.com/vsay/vsay-auth/internal/middleware"
	"github.com/vsay/vsay-auth/internal/proxy"
	"github.com/vsay/vsay-auth/internal/services"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/bcrypt"
)

// initLogger creates a custom formatted logger
func initLogger() *zap.Logger {
	// Use standard production config with custom encoder
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     customTimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(&customWriter{}),
		zapcore.InfoLevel,
	)

	return zap.New(core)
}

// customTimeEncoder formats time as "2006-01-02 15:04:05"
func customTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006-01-02 15:04:05"))
}

// customWriter wraps stdout and reformats logs with pipes
type customWriter struct{}

func (w *customWriter) Write(p []byte) (n int, err error) {
	// Replace tabs with pipes: "TIME\tLEVEL\tMSG" -> "TIME | LEVEL | MSG"
	output := string(p)
	tabCount := 0
	result := ""
	for _, ch := range output {
		if ch == '\t' && tabCount < 2 {
			result += " | "
			tabCount++
		} else {
			result += string(ch)
		}
	}
	return os.Stdout.WriteString(result)
}

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize logger with custom format
	logger := initLogger()
	defer logger.Sync()

	// Initialize MongoDB
	logger.Info("Connecting to MongoDB...")
	db, err := database.NewMongoDB(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to connect to MongoDB", zap.Error(err))
	}
	defer db.Close(context.Background())

	// Initialize store
	store := database.NewStore(db)

	// Initialize Keycloak client
	logger.Info("Connecting to Keycloak...")
	kcClient, err := keycloak.NewClient(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to initialize Keycloak client", zap.Error(err))
	}

	// Initialize services
	logger.Info("Initializing services...")
	jwtService := services.NewJWTService(cfg)
	otpService := services.NewOTPService(store, cfg, logger)
	emailService := services.NewEmailService(store, cfg, logger)
	auditService := services.NewAuditService(store, logger)
	reconciler := services.NewReconciler(kcClient, store, cfg, logger)
	accessService := services.NewAccessService(store, cfg, logger)

	// Initialize proxy to vsay-agent-backend
	logger.Info("Initializing backend proxy...",
		zap.String("backend_url", cfg.VsayAgentBackendURL))
	proxyService, err := proxy.NewProxy(cfg.VsayAgentBackendURL, cfg.GatewaySecret, logger)
	if err != nil {
		logger.Fatal("Failed to initialize proxy", zap.Error(err))
	}

	// Initialize proxy to vsay-tunnel (optional)
	var tunnelProxyService *proxy.Proxy
	if cfg.VsayTunnelURL != "" {
		logger.Info("Initializing tunnel proxy...", zap.String("tunnel_url", cfg.VsayTunnelURL))
		tunnelProxyService, err = proxy.NewTunnelProxy(cfg.VsayTunnelURL, cfg.GatewaySecret, logger)
		if err != nil {
			logger.Warn("Failed to initialize tunnel proxy (tunnel feature disabled)", zap.Error(err))
		}
	} else {
		logger.Info("VSAY_TUNNEL_URL not set — deploy-applications feature is disabled")
	}

	// Initialize handlers
	authHandler := api.NewAuthHandler(store, kcClient, cfg, jwtService, otpService, emailService, auditService, logger)
	usersHandler := api.NewUsersHandler(store, kcClient, emailService, logger)
	adminHandler := api.NewAdminHandler(store, kcClient, logger)
	groupsHandler := api.NewGroupsHandler(store, kcClient, accessService, logger)

	// Directory synchronisation from Microsoft Entra: provisions users and
	// groups so SSO sign-in finds an account, and so application policy can be
	// scoped to directory groups.
	entraSyncer := entrasync.New(store, kcClient, logger)
	entraSyncHandler := api.NewEntraSyncHandler(store, cfg, entraSyncer, logger)
	rolesHandler := api.NewRolesHandler(store, kcClient, logger)
	oidcHandler := api.NewOIDCHandler(store, cfg, jwtService, logger)
	auditHandler := api.NewAuditHandler(store, logger)
	brandingHandler := api.NewBrandingHandler(store, logger)
	apiKeysHandler := api.NewAPIKeysHandler(store, logger)
	mfaSettingsHandler := api.NewMFASettingsHandler(store, cfg, logger)
	oidcSettingsHandler := api.NewOIDCSettingsHandler(store, cfg, logger)

	// Initialize Gin router - always use release mode for clean logs
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Global middleware
	router.Use(gin.Recovery())
	router.Use(middleware.AuditMiddleware(auditService, logger))
	router.Use(middleware.MetricsMiddleware())

	// CORS configuration - Allow all origins (development mode)
	corsConfig := cors.Config{
		AllowAllOrigins:  true,          // Allow all origins
		AllowMethods:     []string{"*"}, // Allow all methods
		AllowHeaders:     []string{"*"}, // Allow all headers
		ExposeHeaders:    []string{"*"}, // Expose all headers
		AllowCredentials: false,         // Must be false when AllowAllOrigins is true
		MaxAge:           12 * time.Hour,
	}
	router.Use(cors.New(corsConfig))

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":      "ok",
			"service":     "vsay-auth",
			"version":     "1.0.0",
			"environment": cfg.Environment,
			"checks":      gin.H{"liveness": "ok"},
		})
	})

	// Prometheus metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Readiness probe — checks MongoDB connectivity
	router.GET("/ready", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "unavailable",
				"checks": gin.H{"mongodb": "error", "error": err.Error()},
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"checks": gin.H{"mongodb": "ok"},
		})
	})

	// Public backend routes (no JWT auth — these have their own auth or are public)
	proxy.RegisterPublicProxyRoutes(router, proxyService)

	// gRPC mode endpoint — proxies to backend to get the actual mTLS setting
	router.GET("/grpc-mode", func(c *gin.Context) {
		backendURL := strings.TrimSuffix(cfg.VsayAgentBackendURL, "/") + "/grpc-mode"
		resp, err := http.Get(backendURL) // #nosec G107 -- VsayAgentBackendURL is server config (env var), not user input
		if err != nil {
			c.JSON(200, gin.H{"mtls_enabled": false})
			return
		}
		defer resp.Body.Close()
		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			c.JSON(200, gin.H{"mtls_enabled": false})
			return
		}
		c.JSON(200, result)
	})

	// Internal email endpoint — lets the agent backend send mail through vsay-auth's
	// SMTP config (so SMTP creds live in ONE place). Protected by the shared gateway
	// secret; it is NOT a proxied route, so vsay-auth serves it directly.
	router.POST("/internal/send-email", func(c *gin.Context) {
		if c.GetHeader("X-Gateway-Token") != cfg.GatewaySecret {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid gateway token"})
			return
		}
		var body struct {
			To      []string `json:"to"`
			Subject string   `json:"subject"`
			HTML    string   `json:"html"`
		}
		if err := c.ShouldBindJSON(&body); err != nil || body.Subject == "" || len(body.To) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "to, subject, html required"})
			return
		}
		var firstErr error
		for _, addr := range body.To {
			if addr == "" {
				continue
			}
			if err := emailService.SendRaw(addr, body.Subject, body.HTML); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if firstErr != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": firstErr.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"sent": len(body.To)})
	})

	// Initialize middleware functions
	authMiddleware := middleware.AuthMiddleware(jwtService, store, logger)
	adminMiddleware := middleware.RequireAdmin(logger)
	superAdminMiddleware := middleware.RequireSuperAdmin(logger)

	// API routes
	apiGroup := router.Group("/api")
	{
		// Auth routes (public, except change-password which needs auth)
		api.RegisterAuthRoutes(apiGroup, authHandler, authMiddleware)

		// OIDC / Social login routes (public)
		api.RegisterOIDCRoutes(apiGroup, oidcHandler)

		// Users routes (authenticated)
		api.RegisterUsersRoutes(apiGroup, usersHandler, authMiddleware, adminMiddleware)

		// Admin routes (super admin only)
		api.RegisterAdminRoutes(apiGroup, adminHandler, authMiddleware, superAdminMiddleware)

		// Groups routes (authenticated, admin for mutations)
		api.RegisterGroupsRoutes(apiGroup, groupsHandler, authMiddleware, adminMiddleware)

		// Directory sync routes (admin only — the handler checks the role)
		api.RegisterEntraSyncRoutes(apiGroup.Group("", authMiddleware), entraSyncHandler)

		// Roles routes (authenticated, admin for viewing/assigning)
		api.RegisterRolesRoutes(apiGroup, rolesHandler, authMiddleware, adminMiddleware)

		// Audit log routes (company_admin + super_admin)
		api.RegisterAuditRoutes(apiGroup, auditHandler, authMiddleware, adminMiddleware)

		// Branding routes — public read, super-admin-only write
		api.RegisterBrandingRoutes(apiGroup, brandingHandler, authMiddleware, superAdminMiddleware)

		// Personal API key routes (self-service — every user manages only their own)
		api.RegisterAPIKeysRoutes(apiGroup, apiKeysHandler, authMiddleware)

		// MFA/OTP + SMTP settings — super-admin-only read and write
		api.RegisterMFASettingsRoutes(apiGroup, mfaSettingsHandler, authMiddleware, superAdminMiddleware)

		// OIDC (Microsoft/GitHub social login) settings — public provider list, super-admin-only CRUD
		api.RegisterOIDCSettingsRoutes(apiGroup, oidcSettingsHandler, authMiddleware, superAdminMiddleware)

		// Proxy routes to backend (authenticated)
		proxy.RegisterProxyRoutes(apiGroup, proxyService, authMiddleware)

		// Tunnel routes — proxied to vsay-tunnel if configured, otherwise returns 503
		proxy.RegisterTunnelProxyRoutes(apiGroup, tunnelProxyService, authMiddleware)
	}

	// Setup super admin on startup
	logger.Info("Setting up super admin...")
	if err := setupSuperAdmin(cfg, store, kcClient, logger); err != nil {
		logger.Error("Failed to setup super admin", zap.Error(err))
		// Don't fail startup, admin might already exist
	}

	// Start reconciler in background
	logger.Info("Starting reconciler...",
		zap.Bool("periodic", cfg.ReconcilerEnabled && cfg.ReconcilerIntervalMin > 0),
		zap.Duration("interval", time.Duration(cfg.ReconcilerIntervalMin)*time.Minute))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reconciler.Start(ctx)

	// Directory sync runs on each tenant's own interval. It shares the
	// handler's credential resolution so a scheduled run and a manual one can
	// never authenticate differently.
	go entrasync.NewScheduler(entraSyncer, store, entraSyncHandler.ResolveCredentials, logger).Run(ctx)

	// Start server
	logger.Info("Starting vsay-auth service",
		zap.String("port", cfg.Port),
		zap.String("environment", cfg.Environment),
		zap.String("keycloak_url", cfg.KeycloakURL),
		zap.String("backend_url", cfg.VsayAgentBackendURL),
	)

	// Graceful shutdown
	go func() {
		if err := router.Run(":" + cfg.Port); err != nil {
			logger.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")
	cancel() // Stop reconciler
	logger.Info("Server shutdown complete")
}

// setupSuperAdmin creates or verifies super admin user from environment variables
func setupSuperAdmin(cfg *config.Config, store *database.Store, kc *keycloak.Client, logger *zap.Logger) error {
	if cfg.SuperAdminUsername == "" || cfg.SuperAdminPassword == "" {
		logger.Warn("Super admin credentials not provided in environment variables")
		return nil
	}

	// Ensure super-admin realm client exists first (for login)
	superAdminRealm := "super-admin"
	if err := kc.CreateRealmClient(superAdminRealm); err != nil {
		logger.Warn("Failed to create client (might already exist)", zap.String("realm", superAdminRealm), zap.Error(err))
	} else {
		logger.Info("Client created successfully", zap.String("realm", superAdminRealm))
	}

	// Check if super admin already exists
	existingUser, err := store.GetUserByUsername(cfg.SuperAdminUsername)
	if err == nil {
		// Super admin exists, verify role
		if existingUser.Role == database.RoleSuperAdmin {
			// Clear any required actions in Keycloak
			if err := kc.ClearRequiredActions(superAdminRealm, existingUser.KeycloakID); err != nil {
				logger.Warn("Failed to clear required actions", zap.Error(err))
			} else {
				logger.Info("Cleared required actions for super admin")
			}
			logger.Info("Super admin already exists",
				zap.String("username", cfg.SuperAdminUsername))
			return nil
		}

		// Update existing user to super admin
		existingUser.Role = database.RoleSuperAdmin
		if err := store.UpdateUser(existingUser); err != nil {
			return err
		}
		logger.Info("Updated existing user to super admin",
			zap.String("username", cfg.SuperAdminUsername))
		return nil
	}

	// Create super admin organization/realm if it doesn't exist
	var org *database.Organization
	org, err = store.GetOrganizationByRealm(superAdminRealm)
	if err != nil {
		// Create organization
		var realmName string
		realm, err := kc.CreateRealm(superAdminRealm, "Super Admin Organization")
		if err != nil {
			logger.Warn("Failed to create super admin realm (might already exist)", zap.Error(err))
			// Realm might already exist, try to get it
			existingRealm, err := kc.GetRealm(superAdminRealm)
			if err != nil {
				logger.Error("Failed to get existing super admin realm", zap.Error(err))
				return err
			}
			realmName = *existingRealm.Realm
		} else {
			realmName = *realm.Realm
		}

		org = &database.Organization{
			Name:          "super-admin",
			DisplayName:   "Super Admin Organization",
			KeycloakRealm: realmName,
			Enabled:       true,
		}
		if err := store.CreateOrganization(org); err != nil {
			logger.Error("Failed to create super admin organization in MongoDB", zap.Error(err))
			// Continue anyway
		}
	}

	// Create super admin user in Keycloak
	userID, err := kc.CreateUser(
		superAdminRealm,
		cfg.SuperAdminUsername,
		cfg.SuperAdminEmail,
		cfg.SuperAdminPassword,
		"Super",
		"Admin",
		[]string{database.RoleSuperAdmin},
	)
	if err != nil {
		logger.Warn("Failed to create super admin in Keycloak (might already exist)", zap.Error(err))
		// Try to get existing user
		kcUser, err := kc.GetUserByUsername(superAdminRealm, cfg.SuperAdminUsername)
		if err != nil {
			return err
		}
		userID = *kcUser.ID
	}

	// Hash password for MongoDB
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(cfg.SuperAdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Create super admin in MongoDB
	superAdmin := &database.User{
		Username:      cfg.SuperAdminUsername,
		Email:         cfg.SuperAdminEmail,
		PasswordHash:  string(passwordHash),
		FirstName:     "Super",
		LastName:      "Admin",
		KeycloakID:    userID,
		TenantID:      superAdminRealm,
		TenantName:    "Super Admin Organization",
		Role:          database.RoleSuperAdmin,
		EmailVerified: true,
		Enabled:       true,
		APIKey:        primitive.NewObjectID().Hex(),
	}

	if err := store.CreateUser(superAdmin); err != nil {
		// User might already exist in MongoDB
		logger.Warn("Failed to create super admin in MongoDB (might already exist)", zap.Error(err))
		return nil
	}

	logger.Info("Super admin created successfully",
		zap.String("username", cfg.SuperAdminUsername),
		zap.String("realm", superAdminRealm))

	return nil
}
