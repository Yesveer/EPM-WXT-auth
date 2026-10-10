package database

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Directory-synchronisation settings and lookups.

// GetEntraSyncSettings returns a tenant's settings, or nil when never
// configured.
func (s *Store) GetEntraSyncSettings(tenantID string) (*EntraSyncSettings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var settings EntraSyncSettings
	err := s.db.database.Collection("entra_sync_settings").
		FindOne(ctx, bson.M{"tenant_id": tenantID}).Decode(&settings)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &settings, nil
}

// ListEntraSyncSettings returns every tenant's settings, for the scheduler.
func (s *Store) ListEntraSyncSettings() ([]*EntraSyncSettings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cursor, err := s.db.database.Collection("entra_sync_settings").Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var out []*EntraSyncSettings
	if err := cursor.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// UpsertEntraSyncSettings writes a tenant's configuration.
//
// Only the configuration fields are written, never the last-run results — the
// two are updated by different actors (an admin saving a form, and the sync
// finishing a run) and a whole-document write from either would wipe the
// other's work.
func (s *Store) UpsertEntraSyncSettings(settings *EntraSyncSettings) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	settings.UpdatedAt = time.Now()

	_, err := s.db.database.Collection("entra_sync_settings").UpdateOne(ctx,
		bson.M{"tenant_id": settings.TenantID},
		bson.M{"$set": bson.M{
			"enabled":             settings.Enabled,
			"directory_tenant_id": settings.DirectoryTenantID,
			"client_id":           settings.ClientID,
			"client_secret":       settings.ClientSecret,
			"sync_users":          settings.SyncUsers,
			"sync_groups":         settings.SyncGroups,
			"interval_minutes":    settings.IntervalMinutes,
			"default_role":        settings.DefaultRole,
			"group_filter":        settings.GroupFilter,
			"updated_at":          settings.UpdatedAt,
			"updated_by":          settings.UpdatedBy,
		}},
		options.Update().SetUpsert(true))
	return err
}

// RecordEntraSyncRun stores the outcome of one run.
func (s *Store) RecordEntraSyncRun(tenantID, status, errMsg string, counts EntraSyncCounts) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	now := time.Now()
	_, err := s.db.database.Collection("entra_sync_settings").UpdateOne(ctx,
		bson.M{"tenant_id": tenantID},
		bson.M{"$set": bson.M{
			"last_run_at":         now,
			"last_status":         status,
			"last_error":          errMsg,
			"last_users_created":  counts.UsersCreated,
			"last_users_updated":  counts.UsersUpdated,
			"last_users_disabled": counts.UsersDisabled,
			"last_groups_created": counts.GroupsCreated,
			"last_groups_updated": counts.GroupsUpdated,
			"last_users_seen":     counts.UsersSeen,
			"last_users_skipped":  counts.UsersSkipped,
			"last_users_failed":   counts.UsersFailed,
			"last_user_error":     counts.FirstUserError,
			"last_users_sync_off": counts.UsersSyncedOff,
		}},
		options.Update().SetUpsert(true))
	return err
}

// EntraSyncCounts is what one run did.
//
// It records what was ATTEMPTED as well as what succeeded. Counting only
// successes makes four zeros mean five different things — the toggle was off,
// the directory returned nobody, everyone was skipped, everyone failed to
// provision, or there was genuinely nothing to do — and an operator cannot
// tell which. The failure case is the one that matters: a run where every
// account failed still reports "success" unless the attempt is counted too.
type EntraSyncCounts struct {
	UsersCreated  int
	UsersUpdated  int
	UsersDisabled int
	GroupsCreated int
	GroupsUpdated int

	// UsersSeen is how many accounts the directory returned.
	UsersSeen int

	// UsersSkipped is how many had no usable address — service accounts and
	// room mailboxes, which cannot be matched or signed in as.
	UsersSkipped int

	// UsersFailed is how many could not be provisioned, and FirstUserError is
	// why the first of them failed. Without these, a Keycloak outage looks
	// exactly like a directory with nothing new in it.
	UsersFailed    int
	FirstUserError string

	// UsersSyncedOff records that user synchronisation was switched off, so
	// the zeros below it are a setting rather than a result.
	UsersSyncedOff bool
}

// GetUserByEntraObjectID finds a locally-provisioned account by its directory
// identity, which is the only identifier that survives a rename.
func (s *Store) GetUserByEntraObjectID(tenantID, objectID string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user User
	err := s.db.database.Collection("users").FindOne(ctx, bson.M{
		"tenant_id": tenantID, "entra_object_id": objectID,
	}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetGroupByEntraGroupID finds a synced group by its directory identity.
func (s *Store) GetGroupByEntraGroupID(tenantID, groupID string) (*Group, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var group Group
	err := s.db.database.Collection("groups").FindOne(ctx, bson.M{
		"tenant_id": tenantID, "entra_group_id": groupID,
	}).Decode(&group)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &group, nil
}

// ListDirectoryUsers returns the tenant's accounts that the sync owns.
//
// Used to find people who have left the directory. Accounts created here by
// hand are deliberately excluded: they were never in Entra, and disabling them
// for it would switch off the break-glass admin the first time a sync ran.
func (s *Store) ListDirectoryUsers(tenantID, source string) ([]*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cursor, err := s.db.database.Collection("users").Find(ctx, bson.M{
		"tenant_id": tenantID, "directory_source": source,
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var out []*User
	if err := cursor.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}
