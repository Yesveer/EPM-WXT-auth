package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/vsay/vsay-auth/internal/config"
	"github.com/vsay/vsay-auth/internal/database"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

// AccessService handles automatic machine access synchronization
// between vsay-auth groups and vsay-agent-backend machines
type AccessService struct {
	store         *database.Store
	config        *config.Config
	logger        *zap.Logger
	backendURL    string
	gatewaySecret string
}

// NewAccessService creates a new access service
func NewAccessService(store *database.Store, config *config.Config, logger *zap.Logger) *AccessService {
	return &AccessService{
		store:         store,
		config:        config,
		logger:        logger,
		backendURL:    config.VsayAgentBackendURL,
		gatewaySecret: config.GatewaySecret,
	}
}

// SyncGroupMemberMachineAccess grants machine access to a user when they're added to a group
// This automatically gives the user access to all machines assigned to the group
func (s *AccessService) SyncGroupMemberMachineAccess(groupID primitive.ObjectID, userID primitive.ObjectID) error {
	// Get group
	group, err := s.store.GetGroupByID(groupID)
	if err != nil {
		s.logger.Error("Failed to get group for access sync", zap.Error(err))
		return err
	}

	// Get user
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		s.logger.Error("Failed to get user for access sync", zap.Error(err))
		return err
	}

	// Grant access to all machines in the group
	successCount := 0
	errorCount := 0
	for _, machineID := range group.MachineIDs {
		if err := s.grantMachineAccess(machineID, user.Username); err != nil {
			s.logger.Warn("Failed to grant machine access",
				zap.String("machine_id", machineID),
				zap.String("username", user.Username),
				zap.Error(err))
			errorCount++
		} else {
			successCount++
		}
	}

	s.logger.Info("Group member machine access synced",
		zap.String("group", group.Name),
		zap.String("username", user.Username),
		zap.Int("success_count", successCount),
		zap.Int("error_count", errorCount))

	if errorCount > 0 && successCount == 0 {
		return fmt.Errorf("failed to grant access to any machines")
	}

	return nil
}

// SyncMachineGroupAccess grants machine access to all group members when a machine is added to a group
func (s *AccessService) SyncMachineGroupAccess(groupID primitive.ObjectID, machineIDs []string) error {
	// Get group
	group, err := s.store.GetGroupByID(groupID)
	if err != nil {
		s.logger.Error("Failed to get group for machine access sync", zap.Error(err))
		return err
	}

	// First, add group_id to each machine's GroupIDs array
	for _, machineID := range machineIDs {
		if err := s.addMachineToGroup(machineID, group.ID.Hex()); err != nil {
			s.logger.Warn("Failed to add machine to group in backend",
				zap.String("machine_id", machineID),
				zap.String("group_id", group.ID.Hex()),
				zap.Error(err))
			// Don't fail - continue with granting access
		}
	}

	// Get all members
	successCount := 0
	errorCount := 0
	for _, memberIDStr := range group.MemberIDs {
		memberID, err := primitive.ObjectIDFromHex(memberIDStr)
		if err != nil {
			s.logger.Warn("Invalid member ID", zap.String("member_id", memberIDStr))
			errorCount++
			continue
		}

		user, err := s.store.GetUserByID(memberID)
		if err != nil {
			s.logger.Warn("Failed to get user for machine sync", zap.Error(err))
			errorCount++
			continue
		}

		// Grant access to all machines for this user
		for _, machineID := range machineIDs {
			if err := s.grantMachineAccess(machineID, user.Username); err != nil {
				s.logger.Warn("Failed to grant machine access",
					zap.String("machine_id", machineID),
					zap.String("username", user.Username),
					zap.Error(err))
				errorCount++
			} else {
				successCount++
			}
		}
	}

	s.logger.Info("Machine group access synced",
		zap.String("group", group.Name),
		zap.Int("machine_count", len(machineIDs)),
		zap.Int("success_count", successCount),
		zap.Int("error_count", errorCount))

	return nil
}

// RevokeMemberMachineAccess revokes machine access from a user when they're removed from a group
// Only revokes if user doesn't have access through other groups or direct assignment
func (s *AccessService) RevokeMemberMachineAccess(groupID primitive.ObjectID, userID primitive.ObjectID) error {
	// Get group
	group, err := s.store.GetGroupByID(groupID)
	if err != nil {
		s.logger.Error("Failed to get group for access revoke", zap.Error(err))
		return err
	}

	// Get user
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		s.logger.Error("Failed to get user for access revoke", zap.Error(err))
		return err
	}

	// Get all user's groups to check if they still have access through other groups
	userGroups, err := s.store.ListGroupsByMember(userID.Hex())
	if err != nil {
		s.logger.Error("Failed to get user groups", zap.Error(err))
		return err
	}

	// For each machine in the group, check if user still has access through other groups
	successCount := 0
	skippedCount := 0
	errorCount := 0
	for _, machineID := range group.MachineIDs {
		// Check if user has access through other groups
		hasAccessViaOtherGroup := false
		for _, otherGroup := range userGroups {
			if otherGroup.ID == groupID {
				continue // Skip the group they're being removed from
			}
			for _, mid := range otherGroup.MachineIDs {
				if mid == machineID {
					hasAccessViaOtherGroup = true
					break
				}
			}
			if hasAccessViaOtherGroup {
				break
			}
		}

		if hasAccessViaOtherGroup {
			s.logger.Debug("User still has access via other group, skipping revoke",
				zap.String("machine_id", machineID),
				zap.String("username", user.Username))
			skippedCount++
			continue
		}

		// Revoke access
		if err := s.revokeMachineAccess(machineID, user.Username); err != nil {
			s.logger.Warn("Failed to revoke machine access",
				zap.String("machine_id", machineID),
				zap.String("username", user.Username),
				zap.Error(err))
			errorCount++
		} else {
			successCount++
		}
	}

	s.logger.Info("Member machine access revoked",
		zap.String("group", group.Name),
		zap.String("username", user.Username),
		zap.Int("revoked_count", successCount),
		zap.Int("skipped_count", skippedCount),
		zap.Int("error_count", errorCount))

	return nil
}

// RemoveMachineFromGroupBackend removes a machine from a group in the backend
func (s *AccessService) RemoveMachineFromGroupBackend(groupID primitive.ObjectID, machineID string) error {
	return s.removeMachineFromGroup(machineID, groupID.Hex())
}

// grantMachineAccess calls vsay-agent-backend to grant access to a machine
func (s *AccessService) grantMachineAccess(machineID, username string) error {
	url := fmt.Sprintf("%s/api/machines/%s/access/grant", s.backendURL, machineID)

	payload := map[string]string{
		"username": username,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add gateway authentication header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gateway-Token", s.gatewaySecret)
	req.Header.Set("X-Username", "system")
	req.Header.Set("X-User-ID", "system")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("backend returned status %d: %s", resp.StatusCode, string(body))
	}

	s.logger.Debug("Granted machine access",
		zap.String("machine_id", machineID),
		zap.String("username", username))

	return nil
}

// revokeMachineAccess calls vsay-agent-backend to revoke access to a machine
func (s *AccessService) revokeMachineAccess(machineID, username string) error {
	url := fmt.Sprintf("%s/api/machines/%s/access/revoke", s.backendURL, machineID)

	payload := map[string]string{
		"username": username,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add gateway authentication header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gateway-Token", s.gatewaySecret)
	req.Header.Set("X-Username", "system")
	req.Header.Set("X-User-ID", "system")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("backend returned status %d: %s", resp.StatusCode, string(body))
	}

	s.logger.Debug("Revoked machine access",
		zap.String("machine_id", machineID),
		zap.String("username", username))

	return nil
}

// addMachineToGroup calls vsay-agent-backend to add a machine to a group
func (s *AccessService) addMachineToGroup(machineID, groupID string) error {
	url := fmt.Sprintf("%s/api/machines/%s/groups/add", s.backendURL, machineID)

	payload := map[string]string{
		"group_id": groupID,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add gateway authentication header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gateway-Token", s.gatewaySecret)
	req.Header.Set("X-Username", "system")
	req.Header.Set("X-User-ID", "system")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("backend returned status %d: %s", resp.StatusCode, string(body))
	}

	s.logger.Debug("Added machine to group",
		zap.String("machine_id", machineID),
		zap.String("group_id", groupID))

	return nil
}

// removeMachineFromGroup calls vsay-agent-backend to remove a machine from a group
func (s *AccessService) removeMachineFromGroup(machineID, groupID string) error {
	url := fmt.Sprintf("%s/api/machines/%s/groups/remove", s.backendURL, machineID)

	payload := map[string]string{
		"group_id": groupID,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add gateway authentication header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gateway-Token", s.gatewaySecret)
	req.Header.Set("X-Username", "system")
	req.Header.Set("X-User-ID", "system")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("backend returned status %d: %s", resp.StatusCode, string(body))
	}

	s.logger.Debug("Removed machine from group",
		zap.String("machine_id", machineID),
		zap.String("group_id", groupID))

	return nil
}
