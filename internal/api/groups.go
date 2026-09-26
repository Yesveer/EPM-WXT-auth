package api

import (
	"math"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-auth/internal/database"
	"github.com/vsay/vsay-auth/internal/keycloak"
	"github.com/vsay/vsay-auth/internal/middleware"
	"github.com/vsay/vsay-auth/internal/services"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

type GroupsHandler struct {
	store         *database.Store
	kc            *keycloak.Client
	logger        *zap.Logger
	accessService *services.AccessService
}

func NewGroupsHandler(
	store *database.Store,
	kc *keycloak.Client,
	accessService *services.AccessService,
	logger *zap.Logger,
) *GroupsHandler {
	return &GroupsHandler{
		store:         store,
		kc:            kc,
		accessService: accessService,
		logger:        logger,
	}
}

// ListGroups returns all groups in the tenant
func (h *GroupsHandler) ListGroups(c *gin.Context) {
	tenantID, _ := c.Get("tenant_id")
	tid := tenantID.(string)
	limitStr := c.Query("limit")

	if limitStr == "" {
		groups, err := h.store.ListGroupsByTenant(tid)
		if err != nil {
			h.logger.Error("Failed to list groups", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list groups"})
			return
		}
		groupsResponse := make([]gin.H, 0, len(groups))
		for _, group := range groups {
			groupsResponse = append(groupsResponse, h.groupResponse(group))
		}
		c.JSON(http.StatusOK, gin.H{
			"groups": groupsResponse, "total": len(groupsResponse),
			"page": 1, "limit": len(groupsResponse), "total_pages": 1,
		})
		return
	}

	limit, _ := strconv.Atoi(limitStr)
	if limit < 1 {
		limit = 10
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	skip := (page - 1) * limit

	total, err := h.store.CountGroupsByTenant(tid)
	if err != nil {
		h.logger.Error("Failed to count groups", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list groups"})
		return
	}
	groups, err := h.store.ListGroupsByTenantPaged(tid, limit, skip)
	if err != nil {
		h.logger.Error("Failed to list groups", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list groups"})
		return
	}

	groupsResponse := make([]gin.H, 0, len(groups))
	for _, group := range groups {
		groupsResponse = append(groupsResponse, h.groupResponse(group))
	}

	totalPages := int(math.Ceil(float64(total) / float64(limit)))
	c.JSON(http.StatusOK, gin.H{
		"groups": groupsResponse, "total": total,
		"page": page, "limit": limit, "total_pages": totalPages,
	})
}

// GetGroup returns a specific group by ID
func (h *GroupsHandler) GetGroup(c *gin.Context) {
	groupIDStr := c.Param("id")
	groupID, err := primitive.ObjectIDFromHex(groupIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group ID"})
		return
	}

	group, err := h.store.GetGroupByID(groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	// Check tenant access
	role, _ := c.Get("role")
	tenantID, _ := c.Get("tenant_id")

	if role.(string) != middleware.RoleSuperAdmin && group.TenantID != tenantID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	c.JSON(http.StatusOK, h.groupResponse(group))
}

// CreateGroupRequest represents the group creation payload
type CreateGroupRequest struct {
	Name        string   `json:"name" binding:"required,min=3,max=100"`
	Description string   `json:"description,omitempty"`
	MemberIDs   []string `json:"member_ids,omitempty"`
	MachineIDs  []string `json:"machine_ids,omitempty"`
}

// CreateGroup creates a new group
func (h *GroupsHandler) CreateGroup(c *gin.Context) {
	var req CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID, _ := c.Get("tenant_id")

	// Check if group name already exists in tenant
	_, err := h.store.GetGroupByName(tenantID.(string), req.Name)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Group already exists in this tenant"})
		return
	}

	// Create group in Keycloak
	kcGroupID, err := h.kc.CreateGroup(tenantID.(string), req.Name, req.Description)
	if err != nil {
		h.logger.Error("Failed to create group in Keycloak", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create group"})
		return
	}

	// Validate member IDs
	validMemberIDs := make([]string, 0)
	for _, memberIDStr := range req.MemberIDs {
		memberID, err := primitive.ObjectIDFromHex(memberIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid member ID: " + memberIDStr})
			return
		}
		// Check if user exists and belongs to tenant
		user, err := h.store.GetUserByID(memberID)
		if err != nil || user.TenantID != tenantID.(string) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "User not found or not in tenant: " + memberIDStr})
			return
		}
		validMemberIDs = append(validMemberIDs, memberIDStr)

		// Add user to Keycloak group
		if err := h.kc.AddUserToGroup(tenantID.(string), user.KeycloakID, kcGroupID); err != nil {
			h.logger.Warn("Failed to add user to Keycloak group", zap.Error(err))
		}
	}

	// Create group in MongoDB
	group := &database.Group{
		Name:        req.Name,
		Description: req.Description,
		TenantID:    tenantID.(string),
		KeycloakID:  kcGroupID,
		MemberIDs:   validMemberIDs,
		MachineIDs:  req.MachineIDs,
	}

	if err := h.store.CreateGroup(group); err != nil {
		h.logger.Error("Failed to create group in MongoDB", zap.Error(err))
		// Try to clean up Keycloak group
		_ = h.kc.DeleteGroup(tenantID.(string), kcGroupID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create group"})
		return
	}

	h.logger.Info("Group created",
		zap.String("name", req.Name),
		zap.String("tenant", tenantID.(string)))

	c.JSON(http.StatusCreated, h.groupResponse(group))
}

// UpdateGroupRequest represents the group update payload
type UpdateGroupRequest struct {
	Name        *string `json:"name,omitempty" binding:"omitempty,min=3,max=100"`
	Description *string `json:"description,omitempty"`
}

// UpdateGroup updates an existing group
func (h *GroupsHandler) UpdateGroup(c *gin.Context) {
	groupIDStr := c.Param("id")
	groupID, err := primitive.ObjectIDFromHex(groupIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group ID"})
		return
	}

	var req UpdateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing group
	group, err := h.store.GetGroupByID(groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	// Check tenant access
	role, _ := c.Get("role")
	tenantID, _ := c.Get("tenant_id")

	if role.(string) != middleware.RoleSuperAdmin && group.TenantID != tenantID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Update fields
	if req.Name != nil {
		group.Name = *req.Name
	}
	if req.Description != nil {
		group.Description = *req.Description
	}

	// Update in MongoDB
	if err := h.store.UpdateGroup(group); err != nil {
		h.logger.Error("Failed to update group", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update group"})
		return
	}

	h.logger.Info("Group updated",
		zap.String("name", group.Name),
		zap.String("group_id", groupID.Hex()))

	c.JSON(http.StatusOK, h.groupResponse(group))
}

// DeleteGroup deletes a group
func (h *GroupsHandler) DeleteGroup(c *gin.Context) {
	groupIDStr := c.Param("id")
	groupID, err := primitive.ObjectIDFromHex(groupIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group ID"})
		return
	}

	// Get existing group
	group, err := h.store.GetGroupByID(groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	// Check tenant access
	role, _ := c.Get("role")
	tenantID, _ := c.Get("tenant_id")

	if role.(string) != middleware.RoleSuperAdmin && group.TenantID != tenantID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Delete from Keycloak
	if err := h.kc.DeleteGroup(group.TenantID, group.KeycloakID); err != nil {
		h.logger.Warn("Failed to delete group from Keycloak", zap.Error(err))
	}

	// Delete from MongoDB
	if err := h.store.DeleteGroup(groupID); err != nil {
		h.logger.Error("Failed to delete group from MongoDB", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete group"})
		return
	}

	h.logger.Info("Group deleted",
		zap.String("name", group.Name),
		zap.String("group_id", groupID.Hex()))

	c.JSON(http.StatusOK, gin.H{
		"message": "Group deleted successfully",
	})
}

// AddMemberRequest represents the add member payload
type AddMemberRequest struct {
	UserIDs []string `json:"user_ids" binding:"required,min=1"`
}

// AddMember adds users to the group
func (h *GroupsHandler) AddMember(c *gin.Context) {
	groupIDStr := c.Param("id")
	groupID, err := primitive.ObjectIDFromHex(groupIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group ID"})
		return
	}

	var req AddMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get group
	group, err := h.store.GetGroupByID(groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	// Check tenant access
	role, _ := c.Get("role")
	tenantID, _ := c.Get("tenant_id")

	if role.(string) != middleware.RoleSuperAdmin && group.TenantID != tenantID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Create a map of existing members for quick lookup
	existingMembers := make(map[string]bool)
	for _, memberID := range group.MemberIDs {
		existingMembers[memberID] = true
	}

	// Process each user
	addedCount := 0
	for _, userIDStr := range req.UserIDs {
		userID, err := primitive.ObjectIDFromHex(userIDStr)
		if err != nil {
			h.logger.Warn("Invalid user ID", zap.String("user_id", userIDStr))
			continue
		}

		// Check if user already in group
		if existingMembers[userIDStr] {
			h.logger.Debug("User already in group", zap.String("user_id", userIDStr))
			continue
		}

		// Get user
		user, err := h.store.GetUserByID(userID)
		if err != nil {
			h.logger.Warn("User not found", zap.String("user_id", userIDStr))
			continue
		}

		// Check if user belongs to same tenant
		if user.TenantID != group.TenantID {
			h.logger.Warn("User not in same tenant as group",
				zap.String("user_id", userIDStr),
				zap.String("user_tenant", user.TenantID),
				zap.String("group_tenant", group.TenantID))
			continue
		}

		// Add to Keycloak group
		if err := h.kc.AddUserToGroup(group.TenantID, user.KeycloakID, group.KeycloakID); err != nil {
			h.logger.Error("Failed to add user to Keycloak group",
				zap.String("username", user.Username),
				zap.Error(err))
			continue
		}

		// Add to MongoDB group
		group.MemberIDs = append(group.MemberIDs, userIDStr)
		existingMembers[userIDStr] = true
		addedCount++

		// Automatically grant machine access to all machines in the group
		if h.accessService != nil {
			if err := h.accessService.SyncGroupMemberMachineAccess(group.ID, userID); err != nil {
				h.logger.Warn("Failed to sync machine access for new group member",
					zap.String("username", user.Username),
					zap.String("group", group.Name),
					zap.Error(err))
				// Don't fail the request, just log the warning
			}
		}

		h.logger.Info("User added to group",
			zap.String("username", user.Username),
			zap.String("group", group.Name))
	}

	// Update group in MongoDB if any members were added
	if addedCount > 0 {
		if err := h.store.UpdateGroup(group); err != nil {
			h.logger.Error("Failed to update group in MongoDB", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add users to group"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "Users added to group successfully",
		"added_count":  addedCount,
		"group":        h.groupResponse(group),
	})
}

// RemoveMemberRequest represents the remove member payload
type RemoveMemberRequest struct {
	UserID string `json:"user_id" binding:"required"`
}

// RemoveMember removes a user from the group
func (h *GroupsHandler) RemoveMember(c *gin.Context) {
	groupIDStr := c.Param("id")
	groupID, err := primitive.ObjectIDFromHex(groupIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group ID"})
		return
	}

	var req RemoveMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := primitive.ObjectIDFromHex(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Get group
	group, err := h.store.GetGroupByID(groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	// Check tenant access
	role, _ := c.Get("role")
	tenantID, _ := c.Get("tenant_id")

	if role.(string) != middleware.RoleSuperAdmin && group.TenantID != tenantID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Get user
	user, err := h.store.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Find and remove user from group
	found := false
	userIDStr := userID.Hex()
	newMemberIDs := make([]string, 0)
	for _, memberID := range group.MemberIDs {
		if memberID != userIDStr {
			newMemberIDs = append(newMemberIDs, memberID)
		} else {
			found = true
		}
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not in group"})
		return
	}

	// Remove from Keycloak group
	if err := h.kc.RemoveUserFromGroup(group.TenantID, user.KeycloakID, group.KeycloakID); err != nil {
		h.logger.Error("Failed to remove user from Keycloak group", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove user from group"})
		return
	}

	// Update MongoDB group
	group.MemberIDs = newMemberIDs
	if err := h.store.UpdateGroup(group); err != nil {
		h.logger.Error("Failed to update group in MongoDB", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove user from group"})
		return
	}

	// Automatically revoke machine access if user doesn't have access via other groups
	if h.accessService != nil {
		if err := h.accessService.RevokeMemberMachineAccess(group.ID, userID); err != nil {
			h.logger.Warn("Failed to revoke machine access for removed group member",
				zap.String("username", user.Username),
				zap.String("group", group.Name),
				zap.Error(err))
			// Don't fail the request, just log the warning
		}
	}

	h.logger.Info("User removed from group",
		zap.String("username", user.Username),
		zap.String("group", group.Name))

	c.JSON(http.StatusOK, gin.H{
		"message": "User removed from group successfully",
		"group":   h.groupResponse(group),
	})
}

// AddMachinesRequest represents the add machines payload
type AddMachinesRequest struct {
	MachineIDs []string `json:"machine_ids" binding:"required,min=1"`
}

// AddMachines adds machines to the group
func (h *GroupsHandler) AddMachines(c *gin.Context) {
	groupIDStr := c.Param("id")
	groupID, err := primitive.ObjectIDFromHex(groupIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group ID"})
		return
	}

	var req AddMachinesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get group
	group, err := h.store.GetGroupByID(groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	// Check tenant access
	role, _ := c.Get("role")
	tenantID, _ := c.Get("tenant_id")

	if role.(string) != middleware.RoleSuperAdmin && group.TenantID != tenantID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Add machines to group (avoid duplicates)
	existingMachines := make(map[string]bool)
	for _, machineID := range group.MachineIDs {
		existingMachines[machineID] = true
	}

	newMachines := 0
	for _, machineID := range req.MachineIDs {
		if !existingMachines[machineID] {
			group.MachineIDs = append(group.MachineIDs, machineID)
			newMachines++
		}
	}

	// Update MongoDB group
	if err := h.store.UpdateGroup(group); err != nil {
		h.logger.Error("Failed to update group machines", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add machines to group"})
		return
	}

	// Automatically grant machine access to all group members for newly added machines
	if h.accessService != nil && newMachines > 0 {
		// Collect only the newly added machines
		newlyAddedMachines := make([]string, 0, newMachines)
		for _, machineID := range req.MachineIDs {
			if !existingMachines[machineID] {
				newlyAddedMachines = append(newlyAddedMachines, machineID)
			}
		}

		if len(newlyAddedMachines) > 0 {
			if err := h.accessService.SyncMachineGroupAccess(group.ID, newlyAddedMachines); err != nil {
				h.logger.Warn("Failed to sync machine access for new machines",
					zap.String("group", group.Name),
					zap.Int("machine_count", len(newlyAddedMachines)),
					zap.Error(err))
				// Don't fail the request, just log the warning
			}
		}
	}

	h.logger.Info("Machines added to group",
		zap.String("group", group.Name),
		zap.Int("new_machines", newMachines))

	c.JSON(http.StatusOK, gin.H{
		"message":      "Machines added to group successfully",
		"added_count":  newMachines,
		"total_machines": len(group.MachineIDs),
		"group":        h.groupResponse(group),
	})
}

// RemoveMachine removes a machine from the group
func (h *GroupsHandler) RemoveMachine(c *gin.Context) {
	groupIDStr := c.Param("id")
	groupID, err := primitive.ObjectIDFromHex(groupIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group ID"})
		return
	}

	machineID := c.Param("machine_id")
	if machineID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Machine ID required"})
		return
	}

	// Get group
	group, err := h.store.GetGroupByID(groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	// Check tenant access
	role, _ := c.Get("role")
	tenantID, _ := c.Get("tenant_id")

	if role.(string) != middleware.RoleSuperAdmin && group.TenantID != tenantID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Find and remove machine from group
	found := false
	newMachineIDs := make([]string, 0)
	for _, mid := range group.MachineIDs {
		if mid != machineID {
			newMachineIDs = append(newMachineIDs, mid)
		} else {
			found = true
		}
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not in group"})
		return
	}

	// Update MongoDB group
	group.MachineIDs = newMachineIDs
	if err := h.store.UpdateGroup(group); err != nil {
		h.logger.Error("Failed to remove machine from group", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove machine from group"})
		return
	}

	// Remove group from machine's GroupIDs array in backend
	if h.accessService != nil {
		if err := h.accessService.RemoveMachineFromGroupBackend(group.ID, machineID); err != nil {
			h.logger.Warn("Failed to remove group from machine in backend",
				zap.String("machine_id", machineID),
				zap.String("group_id", group.ID.Hex()),
				zap.Error(err))
			// Don't fail the request, just log the warning
		}
	}

	h.logger.Info("Machine removed from group",
		zap.String("machine_id", machineID),
		zap.String("group", group.Name))

	c.JSON(http.StatusOK, gin.H{
		"message": "Machine removed from group successfully",
		"group":   h.groupResponse(group),
	})
}

// GetGroupMembers returns list of members (users) in a group
func (h *GroupsHandler) GetGroupMembers(c *gin.Context) {
	groupIDStr := c.Param("id")
	groupID, err := primitive.ObjectIDFromHex(groupIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group ID"})
		return
	}

	group, err := h.store.GetGroupByID(groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	role, _ := c.Get("role")
	tenantID, _ := c.Get("tenant_id")
	if role.(string) != middleware.RoleSuperAdmin && group.TenantID != tenantID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	total := len(group.MemberIDs)
	limitStr := c.Query("limit")

	// Determine which slice of member IDs to process
	memberIDsToFetch := group.MemberIDs
	page := 1
	limit := total
	totalPages := 1

	if limitStr != "" {
		limit, _ = strconv.Atoi(limitStr)
		if limit < 1 {
			limit = 10
		}
		page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
		if page < 1 {
			page = 1
		}
		skip := (page - 1) * limit
		end := skip + limit
		if skip > total {
			skip = total
		}
		if end > total {
			end = total
		}
		memberIDsToFetch = group.MemberIDs[skip:end]
		totalPages = int(math.Ceil(float64(total) / float64(limit)))
	}

	members := make([]gin.H, 0, len(memberIDsToFetch))
	for _, memberIDStr := range memberIDsToFetch {
		memberID, err := primitive.ObjectIDFromHex(memberIDStr)
		if err != nil {
			h.logger.Warn("Invalid member ID in group", zap.String("member_id", memberIDStr))
			continue
		}
		user, err := h.store.GetUserByID(memberID)
		if err != nil {
			h.logger.Warn("Failed to get user", zap.String("user_id", memberIDStr), zap.Error(err))
			continue
		}
		members = append(members, gin.H{
			"id":           user.ID.Hex(),
			"username":     user.Username,
			"email":        user.Email,
			"first_name":   user.FirstName,
			"last_name":    user.LastName,
			"role":         user.Role,
			"machine_role": user.MachineRole,
			"enabled":      user.Enabled,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"members": members, "total": total,
		"page": page, "limit": limit, "total_pages": totalPages,
	})
}

// GetGroupMachines returns list of machines assigned to a group
func (h *GroupsHandler) GetGroupMachines(c *gin.Context) {
	groupIDStr := c.Param("id")
	groupID, err := primitive.ObjectIDFromHex(groupIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group ID"})
		return
	}

	group, err := h.store.GetGroupByID(groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	role, _ := c.Get("role")
	tenantID, _ := c.Get("tenant_id")
	if role.(string) != middleware.RoleSuperAdmin && group.TenantID != tenantID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	total := len(group.MachineIDs)
	limitStr := c.Query("limit")

	machineIDsToReturn := group.MachineIDs
	page := 1
	limit := total
	totalPages := 1

	if limitStr != "" {
		limit, _ = strconv.Atoi(limitStr)
		if limit < 1 {
			limit = 10
		}
		page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
		if page < 1 {
			page = 1
		}
		skip := (page - 1) * limit
		end := skip + limit
		if skip > total {
			skip = total
		}
		if end > total {
			end = total
		}
		machineIDsToReturn = group.MachineIDs[skip:end]
		totalPages = int(math.Ceil(float64(total) / float64(limit)))
	}

	machines := make([]gin.H, 0, len(machineIDsToReturn))
	for _, machineID := range machineIDsToReturn {
		machines = append(machines, gin.H{
			"agent_id": machineID,
			"name":     "",
			"status":   "",
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"machines": machines, "total": total,
		"page": page, "limit": limit, "total_pages": totalPages,
	})
}

// Helper functions

func (h *GroupsHandler) groupResponse(group *database.Group) gin.H {
	return gin.H{
		"id":          group.ID.Hex(),
		"name":        group.Name,
		"description": group.Description,
		"tenant_id":   group.TenantID,
		"keycloak_id": group.KeycloakID,
		"member_ids":  group.MemberIDs,
		"machine_ids": group.MachineIDs,
		"created_at":  group.CreatedAt,
		"updated_at":  group.UpdatedAt,
	}
}

// RegisterGroupsRoutes registers all group routes
func RegisterGroupsRoutes(r *gin.RouterGroup, handler *GroupsHandler, authMiddleware, adminMiddleware gin.HandlerFunc) {
	groups := r.Group("/groups")
	groups.Use(authMiddleware) // All group routes require authentication
	{
		groups.GET("", handler.ListGroups)                                    // List groups
		groups.GET("/:id", handler.GetGroup)                                  // Get group by ID
		groups.POST("", adminMiddleware, handler.CreateGroup)                 // Create group (admin only)
		groups.PUT("/:id", adminMiddleware, handler.UpdateGroup)              // Update group (admin only)
		groups.DELETE("/:id", adminMiddleware, handler.DeleteGroup)           // Delete group (admin only)
		groups.GET("/:id/members", handler.GetGroupMembers)                   // List group members
		groups.POST("/:id/members", adminMiddleware, handler.AddMember)       // Add member (admin only)
		groups.DELETE("/:id/members", adminMiddleware, handler.RemoveMember)  // Remove member (admin only)
		groups.GET("/:id/machines", handler.GetGroupMachines)                 // List group machines
		groups.POST("/:id/machines", adminMiddleware, handler.AddMachines)    // Add machines (admin only)
		groups.DELETE("/:id/machines/:machine_id", adminMiddleware, handler.RemoveMachine) // Remove machine (admin only)
	}
}
