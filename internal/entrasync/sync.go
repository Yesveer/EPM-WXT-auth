// Package entrasync provisions users and groups from Microsoft Entra.
//
// Three rules shape everything here, and each exists because breaking it
// causes an outage rather than a bug:
//
// It never deletes. An account that leaves the directory is disabled, so the
// audit trail of what that person did survives them.
//
// It never touches an account it did not create. A break-glass admin made by
// hand is not in Entra, and switching it off because of that — on the first
// run, against a directory that might be the wrong one — is exactly the
// failure that locks everybody out of their own portal.
//
// It sets a role only at creation. Somebody promoted to administrator here
// must not be quietly demoted by the next run, half an hour later, with no
// record of why.
package entrasync

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/vsay/vsay-auth/internal/database"
	"github.com/vsay/vsay-auth/internal/graph"
)

// Directory is the slice of Microsoft Graph the sync uses.
//
// An interface so the reconciliation logic — which is where the damage would
// be done — is testable against a fake directory rather than only against
// Microsoft.
type Directory interface {
	ListUsers(ctx context.Context) ([]graph.User, error)
	ListGroups(ctx context.Context) ([]graph.Group, error)
	ListGroupMemberIDs(ctx context.Context, groupID string) ([]string, error)
}

// Store is the slice of persistence the sync uses.
//
// An interface, like Directory, so the reconciliation rules in the package
// comment can be tested — a rule that is only asserted in a comment is a rule
// that gets broken.
type Store interface {
	GetUserByEntraObjectID(tenantID, objectID string) (*database.User, error)
	GetUserByEmailAndTenant(email, tenantID string) (*database.User, error)
	CreateUser(user *database.User) error
	UpdateUser(user *database.User) error
	ListDirectoryUsers(tenantID, source string) ([]*database.User, error)
	GetGroupByEntraGroupID(tenantID, groupID string) (*database.Group, error)
	CreateGroup(group *database.Group) error
	UpdateGroup(group *database.Group) error
}

// Keycloak is the slice of the identity server the sync needs.
type Keycloak interface {
	CreateUser(realm, username, email, password, firstName, lastName string, roles []string) (string, error)
	CheckUsernameExists(username string) (bool, string, error)
}

// Syncer reconciles a tenant against its directory.
type Syncer struct {
	store  Store
	kc     Keycloak
	logger *zap.Logger
}

// New builds a Syncer.
func New(store Store, kc Keycloak, logger *zap.Logger) *Syncer {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Syncer{store: store, kc: kc, logger: logger}
}

// DefaultInterval is how often a sync runs when no interval is configured.
//
// Directory changes — somebody joins, leaves, moves team — matter within a
// working day, not within seconds, and each run is a full directory read
// against a rate-limited API.
const DefaultInterval = 60 * time.Minute

// Run reconciles one tenant.
//
// It returns counts even when it fails part-way: a run that provisioned forty
// people and then lost its connection did forty useful things, and reporting
// zero would be a lie that sends somebody looking for a bug.
func (s *Syncer) Run(ctx context.Context, settings *database.EntraSyncSettings, dir Directory) (database.EntraSyncCounts, error) {
	var counts database.EntraSyncCounts

	// Object id → local user id, built while syncing users and consumed while
	// syncing group membership.
	byObjectID := map[string]string{}

	if settings.SyncUsers {
		var err error
		counts, byObjectID, err = s.syncUsers(ctx, settings, dir, counts)
		if err != nil {
			return counts, err
		}
	} else {
		// Recorded so the portal can say "user sync is switched off" instead
		// of showing four zeros that look like a failure.
		counts.UsersSyncedOff = true

		// Groups can still be synced on their own, so the mapping has to come
		// from what is already stored.
		existing, err := s.store.ListDirectoryUsers(settings.TenantID, database.DirectorySourceEntra)
		if err != nil {
			return counts, fmt.Errorf("reading provisioned accounts: %w", err)
		}
		for _, u := range existing {
			if u.EntraObjectID != "" {
				byObjectID[u.EntraObjectID] = u.ID.Hex()
			}
		}
	}

	if settings.SyncGroups {
		var err error
		counts, err = s.syncGroups(ctx, settings, dir, byObjectID, counts)
		if err != nil {
			return counts, err
		}
	}

	return counts, nil
}

// syncUsers provisions accounts and disables leavers.
func (s *Syncer) syncUsers(
	ctx context.Context,
	settings *database.EntraSyncSettings,
	dir Directory,
	counts database.EntraSyncCounts,
) (database.EntraSyncCounts, map[string]string, error) {
	byObjectID := map[string]string{}

	directoryUsers, err := dir.ListUsers(ctx)
	if err != nil {
		return counts, byObjectID, fmt.Errorf("reading the directory: %w", err)
	}

	counts.UsersSeen = len(directoryUsers)
	seen := make(map[string]bool, len(directoryUsers))

	for _, du := range directoryUsers {
		if ctx.Err() != nil {
			return counts, byObjectID, ctx.Err()
		}

		email := du.Email()
		if email == "" || du.ID == "" {
			// Without an address there is nothing to match on and nothing to
			// sign in with. Service accounts and room mailboxes land here.
			counts.UsersSkipped++
			continue
		}
		seen[du.ID] = true

		local, err := s.findLocal(settings.TenantID, du.ID, email)
		if err != nil {
			return counts, byObjectID, err
		}

		if local == nil {
			if !du.AccountEnabled {
				// Creating an account that the directory says is already
				// disabled would provision a leaver on their way out.
				continue
			}
			created, err := s.createUser(settings, du, email)
			if err != nil {
				// One unprovisionable person — a username clash, a Keycloak
				// hiccup — must not abandon the rest of the directory. But it
				// is counted and the first reason kept: a run where EVERY
				// account failed otherwise reports a cheerful "success, 0
				// created", which is the same thing the portal shows when
				// there was simply nothing to do.
				counts.UsersFailed++
				if counts.FirstUserError == "" {
					counts.FirstUserError = email + ": " + err.Error()
				}
				s.logger.Warn("Entra sync: could not provision an account",
					zap.String("email", email), zap.Error(err))
				continue
			}
			counts.UsersCreated++
			byObjectID[du.ID] = created.ID.Hex()
			continue
		}

		byObjectID[du.ID] = local.ID.Hex()
		if s.updateUser(local, du, email) {
			counts.UsersUpdated++
		}
	}

	// Leavers. Only accounts this sync created are considered: see the package
	// comment for why an account made by hand is deliberately left alone.
	managed, err := s.store.ListDirectoryUsers(settings.TenantID, database.DirectorySourceEntra)
	if err != nil {
		return counts, byObjectID, fmt.Errorf("reading provisioned accounts: %w", err)
	}
	for _, u := range managed {
		if u.EntraObjectID == "" || seen[u.EntraObjectID] || !u.Enabled {
			continue
		}
		u.Enabled = false
		u.UpdatedAt = time.Now()
		if err := s.store.UpdateUser(u); err != nil {
			s.logger.Warn("Entra sync: could not disable a departed account",
				zap.String("email", u.Email), zap.Error(err))
			continue
		}
		counts.UsersDisabled++
		s.logger.Info("Entra sync: account disabled, no longer in the directory",
			zap.String("email", u.Email))
	}

	return counts, byObjectID, nil
}

// findLocal matches a directory account to a local one.
//
// The object id is tried first because it survives renames; the email is a
// fallback for accounts that existed before the sync was switched on. When the
// email matches, the object id is recorded so every later run uses the stable
// identity — but ownership is NOT claimed, so a hand-made account is linked
// without becoming something the sync can disable.
func (s *Syncer) findLocal(tenantID, objectID, email string) (*database.User, error) {
	local, err := s.store.GetUserByEntraObjectID(tenantID, objectID)
	if err != nil {
		return nil, fmt.Errorf("looking up a provisioned account: %w", err)
	}
	if local != nil {
		return local, nil
	}

	local, err = s.store.GetUserByEmailAndTenant(email, tenantID)
	if err != nil || local == nil {
		return nil, nil
	}

	if local.EntraObjectID == "" {
		local.EntraObjectID = objectID
		local.UpdatedAt = time.Now()
		if err := s.store.UpdateUser(local); err != nil {
			s.logger.Warn("Entra sync: could not link an existing account to the directory",
				zap.String("email", email), zap.Error(err))
		}
	}
	return local, nil
}

// createUser provisions a new account.
func (s *Syncer) createUser(settings *database.EntraSyncSettings, du graph.User, email string) (*database.User, error) {
	username, err := s.availableUsername(email)
	if err != nil {
		return nil, err
	}

	// A directory account signs in through Microsoft, so the local password is
	// never used. It is random rather than blank or predictable so that the
	// password route cannot become a way in behind the directory's back.
	password, err := randomPassword()
	if err != nil {
		return nil, err
	}

	role := settings.DefaultRole
	if role != database.RoleCompanyAdmin && role != database.RoleSuperAdmin {
		// Anything unrecognised becomes an ordinary user. A typo in a settings
		// field must never mint administrators.
		role = "user"
	}

	kcID, err := s.kc.CreateUser(settings.TenantID, username, email, password,
		du.GivenName, du.Surname, []string{role})
	if err != nil {
		return nil, fmt.Errorf("creating the account in Keycloak: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &database.User{
		Username:        username,
		Email:           email,
		PasswordHash:    string(hash),
		FirstName:       du.GivenName,
		LastName:        du.Surname,
		KeycloakID:      kcID,
		TenantID:        settings.TenantID,
		Role:            role,
		Groups:          []string{},
		EmailVerified:   true, // the directory is the authority on this
		Enabled:         du.AccountEnabled,
		APIKey:          primitive.NewObjectID().Hex(),
		EntraObjectID:   du.ID,
		DirectorySource: database.DirectorySourceEntra,
	}
	if err := s.store.CreateUser(user); err != nil {
		return nil, fmt.Errorf("storing the account: %w", err)
	}
	return user, nil
}

// updateUser applies directory changes, reporting whether anything changed.
//
// Name and enabled state only. The role is deliberately absent: see the
// package comment.
func (s *Syncer) updateUser(local *database.User, du graph.User, email string) bool {
	changed := false

	if du.GivenName != "" && local.FirstName != du.GivenName {
		local.FirstName, changed = du.GivenName, true
	}
	if du.Surname != "" && local.LastName != du.Surname {
		local.LastName, changed = du.Surname, true
	}
	if local.Email != email {
		local.Email, changed = email, true
	}
	// Only accounts the sync owns follow the directory's enabled state, so a
	// hand-made account cannot be switched off by a directory change.
	if local.DirectorySource == database.DirectorySourceEntra && local.Enabled != du.AccountEnabled {
		local.Enabled, changed = du.AccountEnabled, true
	}
	if local.EntraObjectID != du.ID {
		local.EntraObjectID, changed = du.ID, true
	}

	if !changed {
		return false
	}
	local.UpdatedAt = time.Now()
	if err := s.store.UpdateUser(local); err != nil {
		s.logger.Warn("Entra sync: could not update an account",
			zap.String("email", email), zap.Error(err))
		return false
	}
	return true
}

// availableUsername picks a username that is not already taken.
//
// The email is used whole, because a local part collides across domains and
// Keycloak usernames are unique across every realm on the server.
func (s *Syncer) availableUsername(email string) (string, error) {
	exists, _, err := s.kc.CheckUsernameExists(email)
	if err != nil {
		return "", fmt.Errorf("checking the username: %w", err)
	}
	if !exists {
		return email, nil
	}
	return "", fmt.Errorf("the username %q is already taken by another account", email)
}

// randomPassword returns a password nobody knows.
func randomPassword() (string, error) {
	var buf [24]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generating a password: %w", err)
	}
	// Mixed case, digits and a symbol, so it satisfies any realm password
	// policy without having to read the policy.
	return "Aa1!" + base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// syncGroups reconciles groups and their membership.
func (s *Syncer) syncGroups(
	ctx context.Context,
	settings *database.EntraSyncSettings,
	dir Directory,
	byObjectID map[string]string,
	counts database.EntraSyncCounts,
) (database.EntraSyncCounts, error) {
	directoryGroups, err := dir.ListGroups(ctx)
	if err != nil {
		return counts, fmt.Errorf("reading directory groups: %w", err)
	}

	filter := strings.ToLower(strings.TrimSpace(settings.GroupFilter))

	for _, dg := range directoryGroups {
		if ctx.Err() != nil {
			return counts, ctx.Err()
		}
		if dg.ID == "" {
			continue
		}
		if filter != "" && !strings.HasPrefix(strings.ToLower(dg.Name()), filter) {
			continue
		}

		memberObjectIDs, err := dir.ListGroupMemberIDs(ctx, dg.ID)
		if err != nil {
			// One unreadable group should cost that group, not the rest.
			s.logger.Warn("Entra sync: could not read a group's members",
				zap.String("group", dg.Name()), zap.Error(err))
			continue
		}

		members := make([]string, 0, len(memberObjectIDs))
		for _, objectID := range memberObjectIDs {
			if localID, ok := byObjectID[objectID]; ok {
				members = append(members, localID)
			}
			// A member with no local account is skipped rather than invented.
			// It happens when user sync is off, or the person has no address.
		}

		created, err := s.upsertGroup(settings.TenantID, dg, members)
		if err != nil {
			s.logger.Warn("Entra sync: could not store a group",
				zap.String("group", dg.Name()), zap.Error(err))
			continue
		}
		if created {
			counts.GroupsCreated++
		} else {
			counts.GroupsUpdated++
		}
	}

	return counts, nil
}

// upsertGroup creates or updates one group, reporting whether it was created.
//
// Groups are matched on their directory id, never on name: a renamed group
// matched by name would become a second group, and every policy scoped to the
// first would quietly stop applying to anybody.
func (s *Syncer) upsertGroup(tenantID string, dg graph.Group, members []string) (bool, error) {
	existing, err := s.store.GetGroupByEntraGroupID(tenantID, dg.ID)
	if err != nil {
		return false, err
	}

	if existing == nil {
		group := &database.Group{
			Name:            dg.Name(),
			TenantID:        tenantID,
			Description:     dg.Description,
			MemberIDs:       members,
			MachineIDs:      []string{},
			EntraGroupID:    dg.ID,
			DirectorySource: database.DirectorySourceEntra,
		}
		if err := s.store.CreateGroup(group); err != nil {
			return false, err
		}
		return true, nil
	}

	existing.Name = dg.Name()
	existing.Description = dg.Description
	// Membership is replaced, not merged: the directory is the authority, and
	// merging would make it impossible to ever remove somebody from a group.
	existing.MemberIDs = members
	existing.EntraGroupID = dg.ID
	existing.DirectorySource = database.DirectorySourceEntra
	existing.UpdatedAt = time.Now()

	// MachineIDs are left untouched — which machines a group covers is a local
	// decision this product makes, not something Entra knows about.
	return false, s.store.UpdateGroup(existing)
}
