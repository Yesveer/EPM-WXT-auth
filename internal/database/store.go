package database

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Store provides database operations
type Store struct {
	db *MongoDB
}

func NewStore(db *MongoDB) *Store {
	return &Store{db: db}
}

// ========== User Operations ==========

func (s *Store) CreateUser(user *User) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	result, err := s.db.database.Collection("users").InsertOne(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	user.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

func (s *Store) GetUserByID(id primitive.ObjectID) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := s.db.database.Collection("users").FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &user, nil
}

func (s *Store) GetUserByUsername(username string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := s.db.database.Collection("users").FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &user, nil
}

func (s *Store) GetUserByEmail(email string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := s.db.database.Collection("users").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &user, nil
}

func (s *Store) GetUsersByEmail(email string) ([]*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := s.db.database.Collection("users").Find(ctx, bson.M{"email": email})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("user not found")
	}
	return users, nil
}

func (s *Store) GetUserByEmailAndTenant(email, tenantID string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := s.db.database.Collection("users").FindOne(ctx, bson.M{
		"email":     email,
		"tenant_id": tenantID,
	}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &user, nil
}

func (s *Store) GetUserByKeycloakID(keycloakID string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := s.db.database.Collection("users").FindOne(ctx, bson.M{"keycloak_id": keycloakID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &user, nil
}

func (s *Store) GetUserByAPIKey(apiKey string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := s.db.database.Collection("users").FindOne(ctx, bson.M{"api_key": apiKey}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &user, nil
}

func (s *Store) UpdateUser(user *User) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user.UpdatedAt = time.Now()

	_, err := s.db.database.Collection("users").UpdateOne(
		ctx,
		bson.M{"_id": user.ID},
		bson.M{"$set": user},
	)
	return err
}

func (s *Store) UpdateUserLastLogin(userID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	_, err := s.db.database.Collection("users").UpdateOne(
		ctx,
		bson.M{"_id": userID},
		bson.M{
			"$set": bson.M{
				"last_login_at": now,
				"updated_at":    now,
			},
		},
	)
	return err
}

func (s *Store) UpdateUserPassword(userID primitive.ObjectID, newHash string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	_, err := s.db.database.Collection("users").UpdateOne(
		ctx,
		bson.M{"_id": userID},
		bson.M{
			"$set": bson.M{
				"password_hash":       newHash,
				"must_reset_password": false,
				"updated_at":          now,
			},
		},
	)
	return err
}

func (s *Store) UpdateUserSyncTime(userID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	_, err := s.db.database.Collection("users").UpdateOne(
		ctx,
		bson.M{"_id": userID},
		bson.M{
			"$set": bson.M{
				"last_sync_at": now,
				"updated_at":   now,
			},
		},
	)
	return err
}

func (s *Store) DeleteUser(id primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.database.Collection("users").DeleteOne(ctx, bson.M{"_id": id})
	return err
}

func (s *Store) ListUsersByTenant(tenantID string) ([]*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := s.db.database.Collection("users").Find(ctx, bson.M{"tenant_id": tenantID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, err
	}
	return users, nil
}

// userSearchFilter builds the tenant listing filter, optionally narrowed by a
// search term.
//
// The term is matched against the fields an admin would actually type —
// username, email, and either name — anchored nowhere, because somebody
// looking for "priya" should find "Priya Sharma" and "priya.s@corp.com" alike.
//
// Regex metacharacters are escaped: without that, a search box becomes a way
// to run arbitrary patterns against the whole collection, and a stray "(" just
// returns an error instead of results.
func userSearchFilter(tenantID, search string) bson.M {
	filter := bson.M{"tenant_id": tenantID}

	search = strings.TrimSpace(search)
	if search == "" {
		return filter
	}

	escaped := regexp.QuoteMeta(search)
	filter["$or"] = []bson.M{
		{"username": bson.M{"$regex": escaped, "$options": "i"}},
		{"email": bson.M{"$regex": escaped, "$options": "i"}},
		{"first_name": bson.M{"$regex": escaped, "$options": "i"}},
		{"last_name": bson.M{"$regex": escaped, "$options": "i"}},
	}
	return filter
}

// SearchUsersByTenantPaged lists one page of a tenant's users, narrowed by an
// optional search term.
//
// Searching has to happen here rather than in the browser: the page only ever
// holds one page of users, so filtering it client-side finds nobody who
// happens to be on page three.
func (s *Store) SearchUsersByTenantPaged(tenantID, search string, limit, skip int) ([]*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().SetLimit(int64(limit)).SetSkip(int64(skip)).
		SetSort(bson.D{{Key: "created_at", Value: -1}})

	cursor, err := s.db.database.Collection("users").
		Find(ctx, userSearchFilter(tenantID, search), opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, err
	}
	return users, nil
}

// CountUsersByTenantSearch counts the users a search would return, so the
// page count reflects the filtered set rather than the whole tenant.
func (s *Store) CountUsersByTenantSearch(tenantID, search string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.db.database.Collection("users").
		CountDocuments(ctx, userSearchFilter(tenantID, search))
}

func (s *Store) ListUsersByTenantPaged(tenantID string, limit, skip int) ([]*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().SetLimit(int64(limit)).SetSkip(int64(skip)).SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := s.db.database.Collection("users").Find(ctx, bson.M{"tenant_id": tenantID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func (s *Store) CountUsersByTenant(tenantID string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.db.database.Collection("users").CountDocuments(ctx, bson.M{"tenant_id": tenantID})
}

func (s *Store) ListAllUsers() ([]*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := s.db.database.Collection("users").Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func (s *Store) CountUsers() (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.db.database.Collection("users").CountDocuments(ctx, bson.M{})
}

func (s *Store) UsernameExists(username string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	count, err := s.db.database.Collection("users").CountDocuments(ctx, bson.M{"username": username})
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ========== Organization Operations ==========

func (s *Store) CreateOrganization(org *Organization) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	org.CreatedAt = time.Now()
	org.UpdatedAt = time.Now()

	result, err := s.db.database.Collection("organizations").InsertOne(ctx, org)
	if err != nil {
		return fmt.Errorf("failed to create organization: %w", err)
	}

	org.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

func (s *Store) GetOrganizationByID(id primitive.ObjectID) (*Organization, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var org Organization
	err := s.db.database.Collection("organizations").FindOne(ctx, bson.M{"_id": id}).Decode(&org)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("organization not found")
		}
		return nil, err
	}
	return &org, nil
}

func (s *Store) GetOrganizationByName(name string) (*Organization, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var org Organization
	err := s.db.database.Collection("organizations").FindOne(ctx, bson.M{"name": name}).Decode(&org)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("organization not found")
		}
		return nil, err
	}
	return &org, nil
}

func (s *Store) GetOrganizationByRealm(realm string) (*Organization, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var org Organization
	err := s.db.database.Collection("organizations").FindOne(ctx, bson.M{"keycloak_realm": realm}).Decode(&org)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("organization not found")
		}
		return nil, err
	}
	return &org, nil
}

func (s *Store) UpdateOrganization(org *Organization) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	org.UpdatedAt = time.Now()

	_, err := s.db.database.Collection("organizations").UpdateOne(
		ctx,
		bson.M{"_id": org.ID},
		bson.M{"$set": org},
	)
	return err
}

func (s *Store) DeleteOrganization(id primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.database.Collection("organizations").DeleteOne(ctx, bson.M{"_id": id})
	return err
}

func (s *Store) ListOrganizations() ([]*Organization, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := s.db.database.Collection("organizations").Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var orgs []*Organization
	if err := cursor.All(ctx, &orgs); err != nil {
		return nil, err
	}
	return orgs, nil
}

func (s *Store) ListOrganizationsPaged(limit, skip int) ([]*Organization, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(int64(limit)).SetSkip(int64(skip))
	cursor, err := s.db.database.Collection("organizations").Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var orgs []*Organization
	if err := cursor.All(ctx, &orgs); err != nil {
		return nil, err
	}
	return orgs, nil
}

func (s *Store) CountOrganizations() (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.db.database.Collection("organizations").CountDocuments(ctx, bson.M{})
}

// ========== Group Operations ==========

func (s *Store) CreateGroup(group *Group) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	group.CreatedAt = time.Now()
	group.UpdatedAt = time.Now()

	result, err := s.db.database.Collection("groups").InsertOne(ctx, group)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}

	group.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

func (s *Store) GetGroupByID(id primitive.ObjectID) (*Group, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var group Group
	err := s.db.database.Collection("groups").FindOne(ctx, bson.M{"_id": id}).Decode(&group)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("group not found")
		}
		return nil, err
	}
	return &group, nil
}

func (s *Store) GetGroupByKeycloakID(keycloakID string) (*Group, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var group Group
	err := s.db.database.Collection("groups").FindOne(ctx, bson.M{"keycloak_id": keycloakID}).Decode(&group)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("group not found")
		}
		return nil, err
	}
	return &group, nil
}

func (s *Store) GetGroupByName(tenantID, name string) (*Group, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var group Group
	err := s.db.database.Collection("groups").FindOne(ctx, bson.M{"tenant_id": tenantID, "name": name}).Decode(&group)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("group not found")
		}
		return nil, err
	}
	return &group, nil
}

func (s *Store) UpdateGroup(group *Group) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	group.UpdatedAt = time.Now()

	_, err := s.db.database.Collection("groups").UpdateOne(
		ctx,
		bson.M{"_id": group.ID},
		bson.M{"$set": group},
	)
	return err
}

func (s *Store) DeleteGroup(id primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.database.Collection("groups").DeleteOne(ctx, bson.M{"_id": id})
	return err
}

func (s *Store) ListGroupsByTenant(tenantID string) ([]*Group, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := s.db.database.Collection("groups").Find(ctx, bson.M{"tenant_id": tenantID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var groups []*Group
	if err := cursor.All(ctx, &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

// groupSearchFilter builds the tenant listing filter, optionally narrowed by a
// search term.
//
// Matched against name and description — the two things an admin reads in the
// table — unanchored, so "team" finds "Pune Team". Regex metacharacters are
// escaped for the same reason they are in userSearchFilter: an unescaped search
// box runs arbitrary patterns against the collection, and a stray "(" returns
// an error rather than results.
func groupSearchFilter(tenantID, search string) bson.M {
	filter := bson.M{"tenant_id": tenantID}

	search = strings.TrimSpace(search)
	if search == "" {
		return filter
	}

	escaped := regexp.QuoteMeta(search)
	filter["$or"] = []bson.M{
		{"name": bson.M{"$regex": escaped, "$options": "i"}},
		{"description": bson.M{"$regex": escaped, "$options": "i"}},
	}
	return filter
}

// SearchGroupsByTenantPaged lists one page of a tenant's groups, narrowed by an
// optional search term.
//
// Server-side for the same reason as the user search: the browser holds one
// page, so filtering there finds nothing on page three.
func (s *Store) SearchGroupsByTenantPaged(tenantID, search string, limit, skip int) ([]*Group, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().SetLimit(int64(limit)).SetSkip(int64(skip)).
		SetSort(bson.D{{Key: "created_at", Value: -1}})

	cursor, err := s.db.database.Collection("groups").
		Find(ctx, groupSearchFilter(tenantID, search), opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var groups []*Group
	if err := cursor.All(ctx, &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

// CountGroupsByTenantSearch counts what a search would return, so the page
// count reflects the filtered set rather than the whole tenant.
func (s *Store) CountGroupsByTenantSearch(tenantID, search string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.db.database.Collection("groups").
		CountDocuments(ctx, groupSearchFilter(tenantID, search))
}

func (s *Store) ListGroupsByTenantPaged(tenantID string, limit, skip int) ([]*Group, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().SetLimit(int64(limit)).SetSkip(int64(skip)).SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := s.db.database.Collection("groups").Find(ctx, bson.M{"tenant_id": tenantID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var groups []*Group
	if err := cursor.All(ctx, &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

func (s *Store) CountGroupsByTenant(tenantID string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.db.database.Collection("groups").CountDocuments(ctx, bson.M{"tenant_id": tenantID})
}

func (s *Store) ListGroupsByMember(memberID string) ([]*Group, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Find groups where member_ids array contains the given memberID
	cursor, err := s.db.database.Collection("groups").Find(ctx, bson.M{"member_ids": memberID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var groups []*Group
	if err := cursor.All(ctx, &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

// ========== Audit Log Operations ==========

func (s *Store) CreateAuditLog(log *AuditLog) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Timestamp = time.Now()

	_, err := s.db.database.Collection("audit_logs").InsertOne(ctx, log)
	return err
}

func (s *Store) GetAuditLogsByUser(userID primitive.ObjectID, limit int) ([]*AuditLog, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetLimit(int64(limit))

	cursor, err := s.db.database.Collection("audit_logs").Find(
		ctx,
		bson.M{"user_id": userID},
		opts,
	)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []*AuditLog
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}

func (s *Store) GetAuditLogsByTenant(tenantID string, limit int) ([]*AuditLog, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetLimit(int64(limit))

	cursor, err := s.db.database.Collection("audit_logs").Find(
		ctx,
		bson.M{"tenant_id": tenantID},
		opts,
	)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []*AuditLog
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}

func (s *Store) GetAuditLogsByAction(action string, limit int) ([]*AuditLog, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetLimit(int64(limit))

	cursor, err := s.db.database.Collection("audit_logs").Find(
		ctx,
		bson.M{"action": action},
		opts,
	)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []*AuditLog
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}

func (s *Store) GetAllAuditLogs(limit int) ([]*AuditLog, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetLimit(int64(limit))

	cursor, err := s.db.database.Collection("audit_logs").Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []*AuditLog
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}

// Paged variants used by the audit API for server-side pagination.

func (s *Store) GetAuditLogsByTenantPaged(tenantID string, limit, skip int) ([]*AuditLog, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{}
	if tenantID != "" {
		filter["tenant_id"] = tenantID
	}
	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetLimit(int64(limit)).
		SetSkip(int64(skip))

	cursor, err := s.db.database.Collection("audit_logs").Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []*AuditLog
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}

func (s *Store) CountAuditLogs(tenantID string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{}
	if tenantID != "" {
		filter["tenant_id"] = tenantID
	}
	return s.db.database.Collection("audit_logs").CountDocuments(ctx, filter)
}

// ========== OTP Operations ==========

func (s *Store) CreateOTPSession(session *OTPSession) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session.CreatedAt = time.Now()

	// Delete any existing OTP for this username
	_, _ = s.db.database.Collection("otp_sessions").DeleteMany(ctx, bson.M{"username": session.Username})

	_, err := s.db.database.Collection("otp_sessions").InsertOne(ctx, session)
	return err
}

func (s *Store) GetOTPSession(username string) (*OTPSession, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var session OTPSession
	err := s.db.database.Collection("otp_sessions").FindOne(
		ctx,
		bson.M{
			"username":   username,
			"expires_at": bson.M{"$gt": time.Now()},
		},
	).Decode(&session)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("OTP session not found or expired")
		}
		return nil, err
	}
	return &session, nil
}

func (s *Store) IncrementOTPAttempts(username string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.database.Collection("otp_sessions").UpdateOne(
		ctx,
		bson.M{"username": username},
		bson.M{"$inc": bson.M{"attempts": 1}},
	)
	return err
}

func (s *Store) DeleteOTPSession(username string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.database.Collection("otp_sessions").DeleteMany(ctx, bson.M{"username": username})
	return err
}

// ========== Sync Status Operations ==========

func (s *Store) CreateSyncStatus(status *SyncStatus) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.database.Collection("sync_status").InsertOne(ctx, status)
	return err
}

func (s *Store) GetLastSyncStatus(tenantID string) (*SyncStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.FindOne().SetSort(bson.D{{Key: "last_sync_at", Value: -1}})

	var status SyncStatus
	err := s.db.database.Collection("sync_status").FindOne(
		ctx,
		bson.M{"tenant_id": tenantID},
		opts,
	).Decode(&status)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil // No sync status yet
		}
		return nil, err
	}
	return &status, nil
}

// ========== Branding Operations ==========
// A single global document — one deployment, one look, no tenant scoping.

func (s *Store) GetBranding() (*BrandingConfig, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var cfg BrandingConfig
	err := s.db.database.Collection("branding").FindOne(ctx, bson.M{}).Decode(&cfg)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil // caller falls back to defaults
		}
		return nil, err
	}
	return &cfg, nil
}

// UpsertBranding writes the single branding document, creating it on first save.
func (s *Store) UpsertBranding(cfg *BrandingConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg.UpdatedAt = time.Now()
	opts := options.Update().SetUpsert(true)
	_, err := s.db.database.Collection("branding").UpdateOne(
		ctx,
		bson.M{},
		bson.M{"$set": cfg},
		opts,
	)
	return err
}

// ========== MFA Settings Operations ==========
// A single global document — one deployment, one OTP/SMTP configuration.

func (s *Store) GetMFASettings() (*MFASettings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var settings MFASettings
	err := s.db.database.Collection("mfa_settings").FindOne(ctx, bson.M{}).Decode(&settings)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil // caller falls back to env-loaded config.Config defaults
		}
		return nil, err
	}
	return &settings, nil
}

// UpsertMFASettings writes the single MFA settings document, creating it on first save.
func (s *Store) UpsertMFASettings(settings *MFASettings) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	settings.UpdatedAt = time.Now()
	opts := options.Update().SetUpsert(true)
	_, err := s.db.database.Collection("mfa_settings").UpdateOne(
		ctx,
		bson.M{},
		bson.M{"$set": settings},
		opts,
	)
	return err
}

// ========== OIDC Settings Operations ==========
// A single global document — one deployment, one set of social-login credentials.

func (s *Store) GetOIDCSettings() (*OIDCSettings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var settings OIDCSettings
	err := s.db.database.Collection("oidc_settings").FindOne(ctx, bson.M{}).Decode(&settings)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil // caller falls back to env-loaded config.Config defaults
		}
		return nil, err
	}
	return &settings, nil
}

// UpsertOIDCSettings writes the single OIDC settings document, creating it on first save.
func (s *Store) UpsertOIDCSettings(settings *OIDCSettings) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	settings.UpdatedAt = time.Now()
	opts := options.Update().SetUpsert(true)
	_, err := s.db.database.Collection("oidc_settings").UpdateOne(
		ctx,
		bson.M{},
		bson.M{"$set": settings},
		opts,
	)
	return err
}

// ========== API Key Operations ==========

func (s *Store) CreateAPIKey(key *APIKey) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key.CreatedAt = time.Now()

	result, err := s.db.database.Collection("api_keys").InsertOne(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to create api key: %w", err)
	}
	key.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

func (s *Store) GetAPIKeyByHash(hash string) (*APIKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var key APIKey
	err := s.db.database.Collection("api_keys").FindOne(ctx, bson.M{"key_hash": hash}).Decode(&key)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &key, nil
}

func (s *Store) GetAPIKeyByID(id primitive.ObjectID) (*APIKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var key APIKey
	err := s.db.database.Collection("api_keys").FindOne(ctx, bson.M{"_id": id}).Decode(&key)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &key, nil
}

func (s *Store) ListAPIKeysByUser(userID primitive.ObjectID) ([]*APIKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := s.db.database.Collection("api_keys").Find(ctx, bson.M{"user_id": userID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	keys := make([]*APIKey, 0)
	if err := cursor.All(ctx, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func (s *Store) CountAPIKeysByUser(userID primitive.ObjectID) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.db.database.Collection("api_keys").CountDocuments(ctx, bson.M{"user_id": userID})
}

func (s *Store) DeleteAPIKey(id primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.database.Collection("api_keys").DeleteOne(ctx, bson.M{"_id": id})
	return err
}

// UpdateAPIKeyLastUsed is called fire-and-forget from AuthMiddleware on every
// successful API-key request — best-effort usage tracking, never blocks or
// fails the request it's attached to.
func (s *Store) UpdateAPIKeyLastUsed(id primitive.ObjectID, t time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.database.Collection("api_keys").UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{"$set": bson.M{"last_used_at": t}},
	)
	return err
}
