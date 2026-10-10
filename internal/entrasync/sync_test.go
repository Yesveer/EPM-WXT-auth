package entrasync

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/vsay/vsay-auth/internal/database"
	"github.com/vsay/vsay-auth/internal/graph"
)

// fakeStore holds users and groups in memory.
type fakeStore struct {
	users  []*database.User
	groups []*database.Group
}

func (f *fakeStore) GetUserByEntraObjectID(tenantID, objectID string) (*database.User, error) {
	for _, u := range f.users {
		if u.TenantID == tenantID && u.EntraObjectID == objectID && objectID != "" {
			return u, nil
		}
	}
	return nil, nil
}

func (f *fakeStore) GetUserByEmailAndTenant(email, tenantID string) (*database.User, error) {
	for _, u := range f.users {
		if u.TenantID == tenantID && strings.EqualFold(u.Email, email) {
			return u, nil
		}
	}
	return nil, nil
}

func (f *fakeStore) CreateUser(user *database.User) error {
	user.ID = primitive.NewObjectID()
	f.users = append(f.users, user)
	return nil
}

func (f *fakeStore) UpdateUser(user *database.User) error { return nil }

func (f *fakeStore) ListDirectoryUsers(tenantID, source string) ([]*database.User, error) {
	var out []*database.User
	for _, u := range f.users {
		if u.TenantID == tenantID && u.DirectorySource == source {
			out = append(out, u)
		}
	}
	return out, nil
}

func (f *fakeStore) GetGroupByEntraGroupID(tenantID, groupID string) (*database.Group, error) {
	for _, g := range f.groups {
		if g.TenantID == tenantID && g.EntraGroupID == groupID && groupID != "" {
			return g, nil
		}
	}
	return nil, nil
}

func (f *fakeStore) GetGroupByTenantAndName(tenantID, name string) (*database.Group, error) {
	for _, g := range f.groups {
		if g.TenantID == tenantID && g.Name == name {
			return g, nil
		}
	}
	return nil, nil
}

// CreateGroup enforces the unique index the real groups collection carries on
// {tenant_id, name}. A fake that silently accepts a duplicate cannot reproduce
// the production failure it exists to pin.
func (f *fakeStore) CreateGroup(group *database.Group) error {
	for _, g := range f.groups {
		if g.TenantID == group.TenantID && g.Name == group.Name {
			return errors.New("E11000 duplicate key error collection: groups index: tenant_id_1_name_1")
		}
	}
	group.ID = primitive.NewObjectID()
	f.groups = append(f.groups, group)
	return nil
}

func (f *fakeStore) UpdateGroup(group *database.Group) error {
	for i, g := range f.groups {
		if g.ID == group.ID {
			f.groups[i] = group
			return nil
		}
	}
	return errors.New("group not found")
}

func (f *fakeStore) groupByName(name string) *database.Group {
	for _, g := range f.groups {
		if g.Name == name {
			return g
		}
	}
	return nil
}

func (f *fakeStore) userByEmail(email string) *database.User {
	for _, u := range f.users {
		if strings.EqualFold(u.Email, email) {
			return u
		}
	}
	return nil
}

// fakeKeycloak accepts everything unless told otherwise.
type fakeKeycloak struct {
	taken     map[string]bool
	createErr error
	created   []string
}

func (f *fakeKeycloak) CreateUser(_, username, _, _, _, _ string, _ []string) (string, error) {
	if f.createErr != nil {
		return "", f.createErr
	}
	f.created = append(f.created, username)
	return "kc-" + username, nil
}

func (f *fakeKeycloak) CheckUsernameExists(username string) (bool, string, error) {
	return f.taken[username], "", nil
}

// fakeDirectory is a stand-in for Entra.
type fakeDirectory struct {
	users   []graph.User
	groups  []graph.Group
	members map[string][]string
	err     error
}

func (f *fakeDirectory) ListUsers(context.Context) ([]graph.User, error) {
	return f.users, f.err
}
func (f *fakeDirectory) ListGroups(context.Context) ([]graph.Group, error) {
	return f.groups, f.err
}
func (f *fakeDirectory) ListGroupMemberIDs(_ context.Context, groupID string) ([]string, error) {
	return f.members[groupID], nil
}

func settings() *database.EntraSyncSettings {
	return &database.EntraSyncSettings{
		TenantID: "t1", Enabled: true, SyncUsers: true, SyncGroups: true, DefaultRole: "user",
	}
}

func newSyncer(store Store, kc Keycloak) *Syncer {
	return New(store, kc, nil)
}

func TestNewPeopleAreProvisioned(t *testing.T) {
	store := &fakeStore{}
	kc := &fakeKeycloak{taken: map[string]bool{}}
	dir := &fakeDirectory{users: []graph.User{
		{ID: "o1", Mail: "Alice@Example.com", GivenName: "Alice", Surname: "A", AccountEnabled: true},
		{ID: "o2", UserPrincipalName: "bob@example.com", GivenName: "Bob", AccountEnabled: true},
	}}

	counts, err := newSyncer(store, kc).Run(context.Background(), settings(), dir)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if counts.UsersCreated != 2 {
		t.Fatalf("created %d accounts, want 2", counts.UsersCreated)
	}

	alice := store.userByEmail("alice@example.com")
	if alice == nil {
		t.Fatal("Alice was not provisioned")
	}
	if alice.EntraObjectID != "o1" {
		t.Errorf("EntraObjectID = %q — the directory id is the only identity that survives a rename", alice.EntraObjectID)
	}
	if alice.DirectorySource != database.DirectorySourceEntra {
		t.Errorf("DirectorySource = %q", alice.DirectorySource)
	}

	// A person with no mailbox has only a userPrincipalName; skipping them
	// would silently leave contractors unprovisioned.
	if store.userByEmail("bob@example.com") == nil {
		t.Error("the UPN-only account was not provisioned")
	}
}

// The rule that stops a misconfigured sync locking everybody out of their own
// portal: an account made by hand is not in Entra and must survive that.
func TestHandMadeAccountsAreNeverDisabled(t *testing.T) {
	admin := &database.User{
		ID: primitive.NewObjectID(), TenantID: "t1", Email: "admin@example.com",
		Role: database.RoleCompanyAdmin, Enabled: true,
		// Linked to the directory by a previous run — which is what happens to
		// any pre-existing account whose email matches — but NOT owned by the
		// sync, because the sync did not create it. The object id is set here
		// deliberately: without it the account would be skipped for an
		// unrelated reason and this test would prove nothing.
		EntraObjectID: "o-admin",
		// No DirectorySource: created here, not by the sync.
	}
	store := &fakeStore{users: []*database.User{admin}}

	// A directory that does not contain the admin at all.
	dir := &fakeDirectory{users: []graph.User{
		{ID: "o1", Mail: "someone@example.com", AccountEnabled: true},
	}}

	counts, err := newSyncer(store, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), settings(), dir)
	if err != nil {
		t.Fatal(err)
	}

	if !admin.Enabled {
		t.Fatal("a hand-made admin was disabled because it is absent from the directory")
	}
	if counts.UsersDisabled != 0 {
		t.Errorf("UsersDisabled = %d, want 0", counts.UsersDisabled)
	}
}

// A leaver must lose access, but the record of what they did must survive.
func TestDepartedPeopleAreDisabledNotDeleted(t *testing.T) {
	leaver := &database.User{
		ID: primitive.NewObjectID(), TenantID: "t1", Email: "gone@example.com",
		EntraObjectID: "o-gone", DirectorySource: database.DirectorySourceEntra, Enabled: true,
	}
	store := &fakeStore{users: []*database.User{leaver}}
	dir := &fakeDirectory{users: []graph.User{}} // no longer in the directory

	counts, err := newSyncer(store, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), settings(), dir)
	if err != nil {
		t.Fatal(err)
	}

	if leaver.Enabled {
		t.Error("a departed account is still enabled")
	}
	if counts.UsersDisabled != 1 {
		t.Errorf("UsersDisabled = %d, want 1", counts.UsersDisabled)
	}
	if len(store.users) != 1 {
		t.Error("the account was deleted — the audit trail of what that person did goes with it")
	}
}

// Somebody promoted to administrator here must not be quietly demoted half an
// hour later by a sync, with no record of why.
func TestLocalRolePromotionSurvivesASync(t *testing.T) {
	promoted := &database.User{
		ID: primitive.NewObjectID(), TenantID: "t1", Email: "person@example.com",
		EntraObjectID: "o1", DirectorySource: database.DirectorySourceEntra,
		Role: database.RoleCompanyAdmin, Enabled: true,
	}
	store := &fakeStore{users: []*database.User{promoted}}
	dir := &fakeDirectory{users: []graph.User{
		{ID: "o1", Mail: "person@example.com", AccountEnabled: true},
	}}

	if _, err := newSyncer(store, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), settings(), dir); err != nil {
		t.Fatal(err)
	}

	if promoted.Role != database.RoleCompanyAdmin {
		t.Errorf("Role = %q — a local promotion was overwritten by the sync", promoted.Role)
	}
}

// A typo in a settings field must never mint administrators.
func TestUnknownDefaultRoleBecomesAnOrdinaryUser(t *testing.T) {
	store := &fakeStore{}
	cfg := settings()
	cfg.DefaultRole = "administrator" // not a real role in this system

	dir := &fakeDirectory{users: []graph.User{{ID: "o1", Mail: "a@x.com", AccountEnabled: true}}}
	if _, err := newSyncer(store, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), cfg, dir); err != nil {
		t.Fatal(err)
	}

	if got := store.userByEmail("a@x.com").Role; got != "user" {
		t.Errorf("Role = %q, want user", got)
	}
}

// Provisioning somebody the directory already says is disabled would create a
// leaver on their way out.
func TestAlreadyDisabledDirectoryAccountsAreNotCreated(t *testing.T) {
	store := &fakeStore{}
	dir := &fakeDirectory{users: []graph.User{
		{ID: "o1", Mail: "left@example.com", AccountEnabled: false},
	}}

	counts, err := newSyncer(store, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), settings(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if counts.UsersCreated != 0 || len(store.users) != 0 {
		t.Error("an account disabled in the directory was provisioned anyway")
	}
}

// An account that existed before the sync was switched on gets linked by
// email, so later runs use the stable identity — but it is not taken over.
func TestExistingAccountIsLinkedWithoutBeingTakenOver(t *testing.T) {
	existing := &database.User{
		ID: primitive.NewObjectID(), TenantID: "t1", Email: "person@example.com", Enabled: true,
	}
	store := &fakeStore{users: []*database.User{existing}}
	dir := &fakeDirectory{users: []graph.User{
		{ID: "o1", Mail: "person@example.com", AccountEnabled: true},
	}}

	if _, err := newSyncer(store, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), settings(), dir); err != nil {
		t.Fatal(err)
	}

	if existing.EntraObjectID != "o1" {
		t.Errorf("EntraObjectID = %q, want the account linked to the directory", existing.EntraObjectID)
	}
	if existing.DirectorySource == database.DirectorySourceEntra {
		t.Error("the sync took ownership of an account it did not create, so it could now disable it")
	}
	if len(store.users) != 1 {
		t.Errorf("a duplicate account was created: %d users", len(store.users))
	}
}

// One unprovisionable person must not abandon the rest of the directory.
func TestOneFailureDoesNotStopTheRun(t *testing.T) {
	store := &fakeStore{}
	kc := &fakeKeycloak{taken: map[string]bool{"clash@example.com": true}}
	dir := &fakeDirectory{users: []graph.User{
		{ID: "o1", Mail: "clash@example.com", AccountEnabled: true},
		{ID: "o2", Mail: "fine@example.com", AccountEnabled: true},
	}}

	counts, err := newSyncer(store, kc).Run(context.Background(), settings(), dir)
	if err != nil {
		t.Fatalf("one clash aborted the whole run: %v", err)
	}
	if counts.UsersCreated != 1 {
		t.Errorf("created %d, want the one that could be created", counts.UsersCreated)
	}
	if store.userByEmail("fine@example.com") == nil {
		t.Error("the provisionable account was skipped")
	}
}

func TestGroupsAndMembershipAreSynced(t *testing.T) {
	store := &fakeStore{}
	dir := &fakeDirectory{
		users: []graph.User{
			{ID: "o1", Mail: "a@x.com", AccountEnabled: true},
			{ID: "o2", Mail: "b@x.com", AccountEnabled: true},
		},
		groups:  []graph.Group{{ID: "g1", DisplayName: "Finance"}},
		members: map[string][]string{"g1": {"o1", "o2"}},
	}

	counts, err := newSyncer(store, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), settings(), dir)
	if err != nil {
		t.Fatal(err)
	}

	if counts.GroupsCreated != 1 {
		t.Fatalf("created %d groups, want 1", counts.GroupsCreated)
	}
	group := store.groups[0]
	if group.Name != "Finance" || group.EntraGroupID != "g1" {
		t.Errorf("group = %+v", group)
	}
	if len(group.MemberIDs) != 2 {
		t.Errorf("group has %d members, want 2", len(group.MemberIDs))
	}
}

// A renamed group matched by name would become a SECOND group, and every
// policy scoped to the first would quietly stop applying to anybody.
func TestRenamedGroupIsUpdatedNotDuplicated(t *testing.T) {
	existing := &database.Group{
		ID: primitive.NewObjectID(), TenantID: "t1", Name: "Finance",
		EntraGroupID: "g1", DirectorySource: database.DirectorySourceEntra,
		MachineIDs: []string{"agent-1", "agent-2"},
	}
	store := &fakeStore{groups: []*database.Group{existing}}
	dir := &fakeDirectory{
		groups:  []graph.Group{{ID: "g1", DisplayName: "Finance and Legal"}},
		members: map[string][]string{"g1": {}},
	}

	cfg := settings()
	cfg.SyncUsers = false

	counts, err := newSyncer(store, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), cfg, dir)
	if err != nil {
		t.Fatal(err)
	}

	if counts.GroupsCreated != 0 || len(store.groups) != 1 {
		t.Fatalf("a renamed group was duplicated: %d groups", len(store.groups))
	}
	if existing.Name != "Finance and Legal" {
		t.Errorf("Name = %q, want the new name", existing.Name)
	}
	// Which machines a group covers is a local decision Entra knows nothing
	// about, so a sync must not clear it.
	if len(existing.MachineIDs) != 2 {
		t.Errorf("the group's machines were cleared by the sync: %v", existing.MachineIDs)
	}
}

// The production failure this fixes: six groups existed locally by name with
// no directory id, so every run tried to CREATE them and the unique index on
// {tenant_id, name} rejected all six — on every sync, forever.
func TestExistingGroupOfTheSameNameIsAdoptedNotRecreated(t *testing.T) {
	handMade := &database.Group{
		ID: primitive.NewObjectID(), TenantID: "t1", Name: "Dflare",
		MachineIDs: []string{"agent-1"},
	}
	store := &fakeStore{groups: []*database.Group{handMade}}
	dir := &fakeDirectory{
		groups:  []graph.Group{{ID: "g9", DisplayName: "Dflare"}},
		members: map[string][]string{"g9": {}},
	}

	cfg := settings()
	cfg.SyncUsers = false

	counts, err := newSyncer(store, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), cfg, dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(store.groups) != 1 {
		t.Fatalf("groups = %d, want the one that was already there", len(store.groups))
	}
	if counts.GroupsUpdated != 1 || counts.GroupsCreated != 0 {
		t.Errorf("created %d updated %d, want 0 and 1", counts.GroupsCreated, counts.GroupsUpdated)
	}
	// Recording the id is the whole point: without it the next run comes back
	// through the name path and the one after that, forever.
	if got := store.groupByName("Dflare"); got == nil || got.EntraGroupID != "g9" {
		t.Errorf("the adopted group did not keep the directory id: %+v", got)
	}
	if len(handMade.MachineIDs) != 1 {
		t.Errorf("adoption cleared the group's machines: %v", handMade.MachineIDs)
	}
}

// Adoption must not become a way for one directory group to take over another
// group's members just because the names happen to match.
func TestGroupHeldByADifferentDirectoryIDIsNotHijacked(t *testing.T) {
	other := &database.Group{
		ID: primitive.NewObjectID(), TenantID: "t1", Name: "Pune Team",
		EntraGroupID: "g-original", DirectorySource: database.DirectorySourceEntra,
		MemberIDs: []string{"u1"},
	}
	store := &fakeStore{groups: []*database.Group{other}}
	dir := &fakeDirectory{
		groups:  []graph.Group{{ID: "g-different", DisplayName: "Pune Team"}},
		members: map[string][]string{"g-different": {}},
	}

	cfg := settings()
	cfg.SyncUsers = false

	counts, err := newSyncer(store, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), cfg, dir)
	if err != nil {
		t.Fatal(err)
	}

	if counts.GroupsCreated != 0 || counts.GroupsUpdated != 0 {
		t.Errorf("the clashing group was stored anyway: created %d updated %d",
			counts.GroupsCreated, counts.GroupsUpdated)
	}
	if other.EntraGroupID != "g-original" || len(other.MemberIDs) != 1 {
		t.Errorf("an unrelated group was hijacked: %+v", other)
	}
}

// Membership is replaced rather than merged, or somebody could never be
// removed from a group.
func TestGroupMembershipIsReplacedNotMerged(t *testing.T) {
	existing := &database.Group{
		ID: primitive.NewObjectID(), TenantID: "t1", Name: "Finance",
		EntraGroupID: "g1", DirectorySource: database.DirectorySourceEntra,
		MemberIDs: []string{"old-member-1", "old-member-2"},
	}
	store := &fakeStore{groups: []*database.Group{existing}}
	dir := &fakeDirectory{
		groups:  []graph.Group{{ID: "g1", DisplayName: "Finance"}},
		members: map[string][]string{"g1": {}},
	}

	cfg := settings()
	cfg.SyncUsers = false

	if _, err := newSyncer(store, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), cfg, dir); err != nil {
		t.Fatal(err)
	}

	if len(existing.MemberIDs) != 0 {
		t.Errorf("members = %v, want everyone removed as the directory says", existing.MemberIDs)
	}
}

// A directory with hundreds of distribution lists would bury the handful an
// operator actually writes policy against.
func TestGroupFilterLimitsWhatIsSynced(t *testing.T) {
	store := &fakeStore{}
	cfg := settings()
	cfg.SyncUsers = false
	cfg.GroupFilter = "EPM-"

	dir := &fakeDirectory{
		groups: []graph.Group{
			{ID: "g1", DisplayName: "EPM-Finance"},
			{ID: "g2", DisplayName: "All Staff Social Club"},
			{ID: "g3", DisplayName: "epm-engineering"}, // case must not matter
		},
		members: map[string][]string{},
	}

	counts, err := newSyncer(store, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	if counts.GroupsCreated != 2 {
		t.Errorf("synced %d groups, want the 2 matching the filter", counts.GroupsCreated)
	}
}

// A run that provisioned forty people and then lost its connection did forty
// useful things; reporting zero sends somebody looking for a bug.
func TestCountsSurviveAFailure(t *testing.T) {
	store := &fakeStore{}
	dir := &fakeDirectory{
		users:  []graph.User{{ID: "o1", Mail: "a@x.com", AccountEnabled: true}},
		groups: nil,
		err:    nil,
	}

	// Users succeed; the group listing then fails.
	failing := &failingGroupsDirectory{fakeDirectory: dir}
	counts, err := newSyncer(store, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), settings(), failing)

	if err == nil {
		t.Fatal("the group failure was not reported")
	}
	if counts.UsersCreated != 1 {
		t.Errorf("UsersCreated = %d — work already done was not reported", counts.UsersCreated)
	}
}

type failingGroupsDirectory struct{ *fakeDirectory }

func (f *failingGroupsDirectory) ListGroups(context.Context) ([]graph.Group, error) {
	return nil, errors.New("graph unavailable")
}

// Service accounts and room mailboxes have no address to match or sign in with.
func TestAccountsWithNoAddressAreSkipped(t *testing.T) {
	store := &fakeStore{}
	dir := &fakeDirectory{users: []graph.User{
		{ID: "o1", DisplayName: "Meeting Room 3", AccountEnabled: true},
	}}

	counts, err := newSyncer(store, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), settings(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if counts.UsersCreated != 0 {
		t.Error("an account with no address was provisioned")
	}
}

// Four zeros mean five different things. Without the attempt counts an
// operator cannot tell a switched-off toggle from a directory outage from a
// Keycloak failure — all three show "success, 0 created".
func TestRunReportsWhatItAttempted(t *testing.T) {
	store := &fakeStore{}
	dir := &fakeDirectory{users: []graph.User{
		{ID: "o1", Mail: "a@x.com", AccountEnabled: true},
		{ID: "o2", Mail: "b@x.com", AccountEnabled: true},
		{ID: "o3", DisplayName: "Meeting Room 3", AccountEnabled: true}, // no address
	}}

	counts, err := newSyncer(store, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), settings(), dir)
	if err != nil {
		t.Fatal(err)
	}

	if counts.UsersSeen != 3 {
		t.Errorf("UsersSeen = %d, want 3 — the directory returned three accounts", counts.UsersSeen)
	}
	if counts.UsersSkipped != 1 {
		t.Errorf("UsersSkipped = %d, want 1 — the room mailbox has no address", counts.UsersSkipped)
	}
	if counts.UsersCreated != 2 {
		t.Errorf("UsersCreated = %d, want 2", counts.UsersCreated)
	}
	if counts.UsersFailed != 0 {
		t.Errorf("UsersFailed = %d, want 0", counts.UsersFailed)
	}
}

// The case that currently reads as success: every account fails to provision,
// and the portal shows "0 created" exactly as it would for a quiet directory.
func TestEveryAccountFailingIsVisible(t *testing.T) {
	store := &fakeStore{}
	kc := &fakeKeycloak{taken: map[string]bool{}, createErr: errors.New("keycloak: connection refused")}
	dir := &fakeDirectory{users: []graph.User{
		{ID: "o1", Mail: "a@x.com", AccountEnabled: true},
		{ID: "o2", Mail: "b@x.com", AccountEnabled: true},
	}}

	counts, err := newSyncer(store, kc).Run(context.Background(), settings(), dir)
	if err != nil {
		t.Fatal(err)
	}

	if counts.UsersCreated != 0 {
		t.Fatalf("UsersCreated = %d", counts.UsersCreated)
	}
	if counts.UsersSeen != 2 {
		t.Errorf("UsersSeen = %d, want 2 — the accounts were read even though none could be made", counts.UsersSeen)
	}
	if counts.UsersFailed != 2 {
		t.Errorf("UsersFailed = %d, want 2", counts.UsersFailed)
	}
	// The reason has to travel, or the operator is left guessing.
	if !strings.Contains(counts.FirstUserError, "connection refused") {
		t.Errorf("FirstUserError = %q, want the underlying reason", counts.FirstUserError)
	}
}

// Zeros caused by a setting must not look like zeros caused by a failure.
func TestSyncOffIsReportedAsASetting(t *testing.T) {
	cfg := settings()
	cfg.SyncUsers = false

	counts, err := newSyncer(&fakeStore{}, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), cfg, &fakeDirectory{groups: []graph.Group{}, members: map[string][]string{}})
	if err != nil {
		t.Fatal(err)
	}

	if !counts.UsersSyncedOff {
		t.Error("user sync was off but the run did not say so")
	}

	// And it must NOT be set when the sync did run.
	on, err := newSyncer(&fakeStore{}, &fakeKeycloak{taken: map[string]bool{}}).
		Run(context.Background(), settings(), &fakeDirectory{})
	if err != nil {
		t.Fatal(err)
	}
	if on.UsersSyncedOff {
		t.Error("user sync ran but was reported as switched off")
	}
}
