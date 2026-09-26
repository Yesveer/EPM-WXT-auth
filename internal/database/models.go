package database

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Role constants
const (
	RoleSuperAdmin   = "super_admin"
	RoleCompanyAdmin = "company_admin"
	RoleUser         = "user"
)

// User represents a user stored in MongoDB (synced with Keycloak)
type User struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username          string             `bson:"username" json:"username"` // Globally unique
	Email             string             `bson:"email" json:"email"`
	FirstName         string             `bson:"first_name,omitempty" json:"first_name,omitempty"`
	LastName          string             `bson:"last_name,omitempty" json:"last_name,omitempty"`
	PasswordHash      string             `bson:"password_hash" json:"-"`                               // Bcrypt hash
	KeycloakID        string             `bson:"keycloak_id" json:"keycloak_id"`                       // UUID from Keycloak
	TenantID          string             `bson:"tenant_id" json:"tenant_id"`                           // Keycloak realm
	TenantName        string             `bson:"tenant_name" json:"tenant_name"`                       // Organization name
	Role              string             `bson:"role" json:"role"`                                     // super_admin, company_admin, user
	MachineRole       string             `bson:"machine_role,omitempty" json:"machine_role,omitempty"` // allow_sudo, non_sudo
	Groups            []string           `bson:"groups" json:"groups"`                                 // Group IDs
	EmailVerified     bool               `bson:"email_verified" json:"email_verified"`
	Enabled           bool               `bson:"enabled" json:"enabled"`
	APIKey            string             `bson:"api_key" json:"api_key,omitempty"` // For CLI/VSCode
	MustResetPassword bool               `bson:"must_reset_password,omitempty" json:"must_reset_password,omitempty"`
	CreatedAt         time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt         time.Time          `bson:"updated_at" json:"updated_at"`
	LastLoginAt       *time.Time         `bson:"last_login_at,omitempty" json:"last_login_at,omitempty"`
	LastSyncAt        *time.Time         `bson:"last_sync_at,omitempty" json:"last_sync_at,omitempty"` // Last KC sync
}

// Organization represents a company/tenant
type Organization struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name          string             `bson:"name" json:"name"` // Unique, lowercase
	DisplayName   string             `bson:"display_name" json:"display_name"`
	KeycloakRealm string             `bson:"keycloak_realm" json:"keycloak_realm"` // Keycloak realm name
	Description   string             `bson:"description,omitempty" json:"description,omitempty"`
	Enabled       bool               `bson:"enabled" json:"enabled"`
	CreatedAt     time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt     time.Time          `bson:"updated_at" json:"updated_at"`
}

// Group represents a group of users within an organization
type Group struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name        string             `bson:"name" json:"name"`
	TenantID    string             `bson:"tenant_id" json:"tenant_id"`
	KeycloakID  string             `bson:"keycloak_id" json:"keycloak_id"` // UUID from Keycloak
	Description string             `bson:"description,omitempty" json:"description,omitempty"`
	MemberIDs   []string           `bson:"member_ids" json:"member_ids"`   // User IDs (MongoDB)
	MachineIDs  []string           `bson:"machine_ids" json:"machine_ids"` // Machine IDs
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// AuditLog tracks all user actions
type AuditLog struct {
	ID             primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	UserID         primitive.ObjectID     `bson:"user_id,omitempty" json:"user_id"`
	Username       string                 `bson:"username" json:"username"`
	TenantID       string                 `bson:"tenant_id" json:"tenant_id"`
	Action         string                 `bson:"action" json:"action"`               // signup, login, create_user, etc.
	ResourceType   string                 `bson:"resource_type" json:"resource_type"` // user, organization, group, machine
	ResourceID     string                 `bson:"resource_id,omitempty" json:"resource_id,omitempty"`
	Method         string                 `bson:"method" json:"method"`                                 // GET, POST, PUT, DELETE
	Endpoint       string                 `bson:"endpoint" json:"endpoint"`                             // /api/users/:id
	RequestBody    map[string]interface{} `bson:"request_body,omitempty" json:"request_body,omitempty"` // Sanitized
	ResponseStatus int                    `bson:"response_status" json:"response_status"`
	Source         string                 `bson:"source" json:"source"` // ui, cli, vscode
	IPAddress      string                 `bson:"ip_address" json:"ip_address"`
	UserAgent      string                 `bson:"user_agent,omitempty" json:"user_agent,omitempty"`
	Browser        string                 `bson:"browser,omitempty" json:"browser,omitempty"`
	OS             string                 `bson:"os,omitempty" json:"os,omitempty"`
	Error          string                 `bson:"error,omitempty" json:"error,omitempty"`
	Timestamp      time.Time              `bson:"timestamp" json:"timestamp"`
}

// OTPSession stores OTP codes (replaces Redis)
type OTPSession struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username  string             `bson:"username" json:"username"`
	OTPCode   string             `bson:"otp_code" json:"otp_code"` // 6-digit code
	TenantID  string             `bson:"tenant_id" json:"tenant_id"`
	Attempts  int                `bson:"attempts" json:"attempts"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	ExpiresAt time.Time          `bson:"expires_at" json:"expires_at"` // TTL index
}

// BrandingConfig is a single global document controlling portal-wide white-label
// branding (logo, favicon, product name, and the default accent color new users see
// until they pick their own in their profile).
// Note: LogoURL, FaviconURL, NamePart1Color, and NamePart2Color deliberately do
// NOT use `omitempty` on their bson tags. This struct is written wholesale via
// `$set` in UpsertBranding — with omitempty, marshaling a cleared (empty-string)
// field drops it from the BSON document entirely, so $set never touches it and
// Mongo silently keeps the old value. That made "Reset to default" / removing a
// logo or favicon look like it saved but never actually cleared the stored URL.
type BrandingConfig struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	LogoURL           string             `bson:"logo_url" json:"logo_url"`
	FaviconURL        string             `bson:"favicon_url" json:"favicon_url"`
	NamePart1         string             `bson:"name_part1" json:"name_part1"`
	NamePart1Color    string             `bson:"name_part1_color" json:"name_part1_color"`
	NamePart2         string             `bson:"name_part2" json:"name_part2"`
	NamePart2Color    string             `bson:"name_part2_color" json:"name_part2_color"`
	DefaultThemeColor string             `bson:"default_theme_color" json:"default_theme_color"`
	// TerminalIdleTimeoutMinutes: how long (in minutes) a terminal session may
	// sit idle before the frontend closes it and requires a new session. Purely
	// a stored preference — the client alone reads and enforces it; there is no
	// server-side timer. Zero means "not customized yet", handled as the
	// 2-minute default at the API response layer (see brandingResponse).
	TerminalIdleTimeoutMinutes int `bson:"terminal_idle_timeout_minutes" json:"terminal_idle_timeout_minutes"`
	// DefaultThemeColorUpdatedAt is bumped ONLY when DefaultThemeColor's value
	// actually changes — deliberately separate from UpdatedAt, which changes on
	// every save (logo, name, whatever). The frontend uses this narrower
	// timestamp to decide whether a user's personal accent-color pick is still
	// "fresh" (made after the last real color change) or stale (should fall
	// back to the org default). Using the blanket UpdatedAt for that comparison
	// was a bug: saving an unrelated field like the logo would silently reset
	// everyone's personal color choice too.
	DefaultThemeColorUpdatedAt time.Time `bson:"default_theme_color_updated_at,omitempty" json:"default_theme_color_updated_at,omitempty"`
	UpdatedAt                  time.Time `bson:"updated_at" json:"updated_at"`
	UpdatedBy                  string    `bson:"updated_by,omitempty" json:"updated_by,omitempty"`
}

// MFASettings is a single global document controlling OTP/email-2FA behavior
// and the SMTP credentials used to send it. Lets a super_admin manage these
// from the UI instead of editing server env vars. A missing document (never
// configured) means "use the values config.Config loaded from the environment"
// — see effectiveMFASettings in internal/api/mfa_settings.go.
// SMTPPassword deliberately has no `omitempty` for the same reason described
// on BrandingConfig: this struct is written wholesale via `$set`, and omitempty
// would silently keep a stale password when a save intentionally clears it.
type MFASettings struct {
	ID               primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	OTPEnabled       bool               `bson:"otp_enabled" json:"otp_enabled"`
	OTPExpiryMinutes int                `bson:"otp_expiry_minutes" json:"otp_expiry_minutes"`
	SMTPHost         string             `bson:"smtp_host" json:"smtp_host"`
	SMTPPort         int                `bson:"smtp_port" json:"smtp_port"`
	SMTPUsername     string             `bson:"smtp_username" json:"smtp_username"`
	SMTPPassword     string             `bson:"smtp_password" json:"-"`
	SMTPFrom         string             `bson:"smtp_from" json:"smtp_from"`
	UpdatedAt        time.Time          `bson:"updated_at" json:"updated_at"`
	UpdatedBy        string             `bson:"updated_by,omitempty" json:"updated_by,omitempty"`
}

// OIDCSettings is a single global document controlling the Microsoft and
// GitHub "social login" buttons on the login page — whether each is shown at
// all, and the OAuth app credentials used for it. A missing document (never
// configured) means "use the values config.Config loaded from the
// environment" — see resolveOIDCSettings in internal/api/oidc_settings.go.
// The two ClientSecret fields deliberately have no `omitempty` for the same
// reason described on BrandingConfig/MFASettings: this struct is written
// wholesale via `$set`, and omitempty would silently keep a stale secret when
// a save intentionally clears it.
type OIDCSettings struct {
	ID                    primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	MicrosoftEnabled      bool               `bson:"microsoft_enabled" json:"microsoft_enabled"`
	MicrosoftClientID     string             `bson:"microsoft_client_id" json:"microsoft_client_id"`
	MicrosoftClientSecret string             `bson:"microsoft_client_secret" json:"-"`
	MicrosoftTenantID     string             `bson:"microsoft_tenant_id" json:"microsoft_tenant_id"`
	GitHubEnabled         bool               `bson:"github_enabled" json:"github_enabled"`
	GitHubClientID        string             `bson:"github_client_id" json:"github_client_id"`
	GitHubClientSecret    string             `bson:"github_client_secret" json:"-"`
	UpdatedAt             time.Time          `bson:"updated_at" json:"updated_at"`
	UpdatedBy             string             `bson:"updated_by,omitempty" json:"updated_by,omitempty"`
}

// APIKey is a personal access token (GitHub-style) that lets a user call any
// API endpoint as themselves without going through login/OTP. Only the SHA-256
// hash of the raw key is ever stored — the raw value is shown to the user
// exactly once, at creation time, and is not recoverable afterwards.
type APIKey struct {
	ID     primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID primitive.ObjectID `bson:"user_id" json:"user_id"`
	// Denormalized for display/filtering only — AuthMiddleware always re-reads
	// the live User record for role/email/etc so a role change or disabled
	// account takes effect immediately, not just on the key's next rotation.
	TenantID   string     `bson:"tenant_id" json:"tenant_id"`
	Name       string     `bson:"name" json:"name"`
	KeyHash    string     `bson:"key_hash" json:"-"`
	KeyPrefix  string     `bson:"key_prefix" json:"key_prefix"` // e.g. "vsay_a1b2c3d4" — shown in the UI list
	ExpiresAt  *time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	LastUsedAt *time.Time `bson:"last_used_at,omitempty" json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `bson:"created_at" json:"created_at"`
}

// SyncStatus tracks Keycloak sync status
type SyncStatus struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	TenantID      string             `bson:"tenant_id" json:"tenant_id"`
	LastSyncAt    time.Time          `bson:"last_sync_at" json:"last_sync_at"`
	UsersCreated  int                `bson:"users_created" json:"users_created"`
	UsersUpdated  int                `bson:"users_updated" json:"users_updated"`
	UsersDisabled int                `bson:"users_disabled" json:"users_disabled"`
	Errors        []string           `bson:"errors,omitempty" json:"errors,omitempty"`
	Status        string             `bson:"status" json:"status"` // success, partial, failed
}
