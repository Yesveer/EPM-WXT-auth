package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	RoleSuperAdmin   = "super_admin"
	RoleCompanyAdmin = "company_admin"
	RoleUser         = "user"
)

// RequireSuperAdmin checks if user has super admin role
func RequireSuperAdmin(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			logger.Warn("Role not found in context")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		if role.(string) != RoleSuperAdmin {
			username, _ := c.Get("username")
			logger.Warn("Super admin access denied",
				zap.String("username", username.(string)),
				zap.String("role", role.(string)))
			c.JSON(http.StatusForbidden, gin.H{"error": "Super admin access required"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireCompanyAdmin checks if user has company admin role
func RequireCompanyAdmin(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			logger.Warn("Role not found in context")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		if role.(string) != RoleCompanyAdmin && role.(string) != RoleSuperAdmin {
			username, _ := c.Get("username")
			logger.Warn("Company admin access denied",
				zap.String("username", username.(string)),
				zap.String("role", role.(string)))
			c.JSON(http.StatusForbidden, gin.H{"error": "Company admin access required"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAdmin checks if user has any admin role (company admin or super admin)
func RequireAdmin(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			logger.Warn("Role not found in context")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		userRole := role.(string)
		if userRole != RoleCompanyAdmin && userRole != RoleSuperAdmin {
			username, _ := c.Get("username")
			logger.Warn("Admin access denied",
				zap.String("username", username.(string)),
				zap.String("role", userRole))
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireTenant checks if user belongs to the specified tenant
func RequireTenant(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		userTenantID, exists := c.Get("tenant_id")
		if !exists {
			logger.Warn("Tenant ID not found in context")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// Get tenant ID from URL parameter if present
		targetTenantID := c.Param("tenant_id")
		if targetTenantID == "" {
			// No tenant specified in URL, allow access
			c.Next()
			return
		}

		// Super admins can access any tenant
		role, _ := c.Get("role")
		if role.(string) == RoleSuperAdmin {
			c.Next()
			return
		}

		// Regular users can only access their own tenant
		if userTenantID.(string) != targetTenantID {
			username, _ := c.Get("username")
			logger.Warn("Tenant access denied",
				zap.String("username", username.(string)),
				zap.String("user_tenant", userTenantID.(string)),
				zap.String("target_tenant", targetTenantID))
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to this tenant"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireMachineRole checks if user has required machine role
func RequireMachineRole(requiredRole string, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		machineRole, exists := c.Get("machine_role")
		if !exists {
			logger.Warn("Machine role not found in context")
			c.JSON(http.StatusForbidden, gin.H{"error": "Machine role required"})
			c.Abort()
			return
		}

		userMachineRole := machineRole.(string)
		if userMachineRole != requiredRole {
			username, _ := c.Get("username")
			logger.Warn("Machine role access denied",
				zap.String("username", username.(string)),
				zap.String("user_machine_role", userMachineRole),
				zap.String("required_role", requiredRole))
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient machine permissions",
				"required_role": requiredRole,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
