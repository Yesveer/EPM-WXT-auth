package models

import "time"

// User roles
const (
	RoleSuperAdmin   = "super_admin"
	RoleCompanyAdmin = "company_admin"
	RoleUser         = "user"
)

// Machine roles
const (
	MachineRoleAllowSudo = "allow_sudo"
	MachineRoleNonSudo   = "non_sudo"
)

// User represents a user in the system
type User struct {
	ID             string    `json:"id"`
	Username       string    `json:"username"`
	Email          string    `json:"email"`
	FirstName      string    `json:"first_name,omitempty"`
	LastName       string    `json:"last_name,omitempty"`
	Role           string    `json:"role"`
	TenantID       string    `json:"tenant_id"`       // Keycloak realm/tenant
	TenantName     string    `json:"tenant_name"`     // Company/Organization name
	Groups         []string  `json:"groups"`
	EmailVerified  bool      `json:"email_verified"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Organization represents a company/tenant
type Organization struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	Description string    `json:"description,omitempty"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Group represents a group of users within an organization
type Group struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	TenantID    string   `json:"tenant_id"`
	Members     []string `json:"members"`      // User IDs
	Machines    []string `json:"machines"`     // Machine IDs
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// SignupRequest for user registration
type SignupRequest struct {
	CompanyName     string `json:"company_name" binding:"required"`
	Username        string `json:"username" binding:"required,alphanum"`
	Email           string `json:"email" binding:"required,email"`
	Password        string `json:"password" binding:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" binding:"required,eqfield=Password"`
}

// LoginRequest for authentication
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	OTP      string `json:"otp,omitempty"` // Optional: only for UI login
}

// VerifyOTPRequest for OTP verification
type VerifyOTPRequest struct {
	Username string `json:"username" binding:"required"`
	OTP      string `json:"otp" binding:"required,len=6"`
}

// CreateUserRequest for creating users (by admin)
type CreateUserRequest struct {
	Username  string `json:"username" binding:"required,alphanum"`
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      string `json:"role" binding:"required,oneof=company_admin user"`
}

// CreateOrganizationRequest for creating organizations (by super admin)
type CreateOrganizationRequest struct {
	Name        string `json:"name" binding:"required,alphanum"`
	DisplayName string `json:"display_name" binding:"required"`
	Description string `json:"description"`
}

// CreateGroupRequest for creating groups
type CreateGroupRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

// UpdateGroupMembersRequest for adding/removing users from group
type UpdateGroupMembersRequest struct {
	UserIDs []string `json:"user_ids" binding:"required"`
}

// UpdateGroupMachinesRequest for adding/removing machines from group
type UpdateGroupMachinesRequest struct {
	MachineIDs []string `json:"machine_ids" binding:"required"`
}

// AssignRoleRequest for assigning machine roles to users
type AssignRoleRequest struct {
	UserID      string `json:"user_id" binding:"required"`
	MachineRole string `json:"machine_role" binding:"required,oneof=allow_sudo non_sudo"`
}

// AuthResponse for successful authentication
type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	User         *User  `json:"user"`
	RequiresOTP  bool   `json:"requires_otp,omitempty"`
}

// ErrorResponse for API errors
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}
