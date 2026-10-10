package graph

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeGraph stands in for Microsoft: a token endpoint plus whatever directory
// responses a test needs.
type fakeGraph struct {
	server    *httptest.Server
	tokenHits int
	// pages maps a path to the sequence of responses it returns.
	handler func(w http.ResponseWriter, r *http.Request)
}

func newFakeGraph(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *fakeGraph {
	t.Helper()
	f := &fakeGraph{handler: handler}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
			f.tokenHits++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
			return
		}
		f.handler(w, r)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeGraph) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{
		TenantID: "tenant", ClientID: "client", ClientSecret: "secret",
		LoginHost: f.server.URL, GraphHost: f.server.URL,
		HTTPClient: f.server.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNewRequiresCredentials(t *testing.T) {
	cases := map[string]Config{
		"no tenant": {ClientID: "c", ClientSecret: "s"},
		"no client": {TenantID: "t", ClientSecret: "s"},
		"no secret": {TenantID: "t", ClientID: "c"},
		"blank":     {TenantID: "  ", ClientID: "c", ClientSecret: "s"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Error("accepted an incomplete configuration")
			}
		})
	}
}

func TestListUsersFollowsPaging(t *testing.T) {
	var (
		calls   int
		baseURL string
	)
	f := newFakeGraph(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "2" {
			_, _ = fmt.Fprint(w, `{"value":[{"id":"u3","mail":"c@x.com","accountEnabled":true}]}`)
			return
		}
		// First page points at the second.
		_, _ = fmt.Fprintf(w, `{"value":[
			{"id":"u1","mail":"a@x.com","accountEnabled":true},
			{"id":"u2","mail":"b@x.com","accountEnabled":false}
		],"@odata.nextLink":"%s/users?page=2"}`, baseURL)
	})
	baseURL = f.server.URL

	users, err := f.client(t).ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}

	// A directory larger than one page is the normal case, not an edge case —
	// stopping at the first page would silently sync a fraction of the staff.
	if len(users) != 3 {
		t.Fatalf("got %d users across two pages, want 3", len(users))
	}
	if calls != 2 {
		t.Errorf("made %d directory calls, want 2", calls)
	}
	if !users[0].AccountEnabled || users[1].AccountEnabled {
		t.Error("accountEnabled did not survive")
	}
}

// Tokens last an hour and a sync makes many calls. Re-authenticating per call
// would turn one sync into hundreds of authentications against a rate-limited
// endpoint.
func TestTokenIsReusedAcrossCalls(t *testing.T) {
	f := newFakeGraph(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[]}`))
	})

	c := f.client(t)
	for i := 0; i < 5; i++ {
		if _, err := c.ListUsers(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if f.tokenHits != 1 {
		t.Errorf("authenticated %d times for 5 calls, want 1", f.tokenHits)
	}
}

// A 403 here has one overwhelmingly likely cause, and "403" tells an operator
// nothing while the real reason tells them everything.
func TestForbiddenExplainsTheMissingConsent(t *testing.T) {
	f := newFakeGraph(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}`))
	})

	_, err := f.client(t).ListUsers(context.Background())
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if !strings.Contains(err.Error(), "admin consent") {
		t.Errorf("the error does not mention admin consent: %v", err)
	}
}

// "Sync failed" is useless; "your client secret expired" is actionable, and
// Microsoft tells us which it is.
func TestCredentialFailureSurfacesMicrosoftsReason(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000222: The provided client secret keys for app are expired.\r\nTrace ID: abc"}`))
	}))
	defer server.Close()

	c, err := New(Config{
		TenantID: "t", ClientID: "c", ClientSecret: "s",
		LoginHost: server.URL, GraphHost: server.URL, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.ListUsers(context.Background())
	if err == nil {
		t.Fatal("expired credentials were reported as success")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error does not say the secret expired: %v", err)
	}
	// The trace id is noise to the reader and must not swamp the reason.
	if strings.Contains(err.Error(), "Trace ID") {
		t.Errorf("error carries Microsoft's trace id: %v", err)
	}
}

// Groups can contain nested groups, service principals and devices. Treating
// any of those as a person would invent accounts that do not exist.
func TestOnlyUserMembersAreReturned(t *testing.T) {
	f := newFakeGraph(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[
			{"id":"u1","@odata.type":"#microsoft.graph.user"},
			{"id":"g1","@odata.type":"#microsoft.graph.group"},
			{"id":"sp1","@odata.type":"#microsoft.graph.servicePrincipal"},
			{"id":"d1","@odata.type":"#microsoft.graph.device"},
			{"id":"u2","@odata.type":"#microsoft.graph.user"}
		]}`))
	})

	ids, err := f.client(t).ListGroupMemberIDs(context.Background(), "group-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "u1" || ids[1] != "u2" {
		t.Errorf("members = %v, want only the two users", ids)
	}
}

// A paging bug that never advances would otherwise loop forever against a
// paid API.
func TestPagingIsBounded(t *testing.T) {
	var (
		calls   int
		baseURL string
	)
	f := newFakeGraph(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		// Always points at itself: the shape of a server-side paging bug.
		_, _ = fmt.Fprintf(w, `{"value":[{"id":"u1"}],"@odata.nextLink":"%s/users"}`, baseURL)
	})
	baseURL = f.server.URL

	if _, err := f.client(t).ListUsers(context.Background()); err != nil {
		t.Fatalf("ListUsers: %v", err)
	}

	if calls > maxPages {
		t.Errorf("made %d calls, want no more than %d", calls, maxPages)
	}
}

func TestUserEmailAndName(t *testing.T) {
	// mail is the real mailbox and wins when present.
	both := User{Mail: "Person@Example.com", UserPrincipalName: "person@example.onmicrosoft.com"}
	if got := both.Email(); got != "person@example.com" {
		t.Errorf("Email() = %q, want the lowercased mail", got)
	}

	// Accounts without an Exchange licence have no mail at all; the UPN is
	// then the only address there is, and skipping them would silently leave
	// those people unprovisioned.
	upnOnly := User{UserPrincipalName: "Contractor@example.com"}
	if got := upnOnly.Email(); got != "contractor@example.com" {
		t.Errorf("Email() = %q, want the UPN", got)
	}

	cases := map[string]User{
		"Full Name": {DisplayName: "Full Name"},
		"Given Sur": {GivenName: "Given", Surname: "Sur"},
		"a@b.com":   {Mail: "a@b.com"},
	}
	for want, u := range cases {
		if got := u.Name(); got != want {
			t.Errorf("Name() = %q, want %q", got, want)
		}
	}
}

func TestGroupNameFallsBack(t *testing.T) {
	cases := map[string]Group{
		"Finance":  {DisplayName: "Finance"},
		"fin-team": {MailNickname: "fin-team"},
		"abc-123":  {ID: "abc-123"},
	}
	for want, g := range cases {
		if got := g.Name(); got != want {
			t.Errorf("Name() = %q, want %q", got, want)
		}
	}
}

func TestTestConnectionProvesPermissionsNotJustAuth(t *testing.T) {
	// Authentication succeeding while permissions were never consented is the
	// most common half-configured state, so the test call must exercise a
	// directory read rather than only fetching a token.
	f := newFakeGraph(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"message":"Insufficient privileges"}}`))
	})

	if err := f.client(t).TestConnection(context.Background()); !errors.Is(err, ErrForbidden) {
		t.Errorf("TestConnection accepted a tenant with no consented permissions: %v", err)
	}
}

func TestSelectOnlyTheFieldsWeUse(t *testing.T) {
	var gotQuery string
	f := newFakeGraph(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[]}`))
	})

	if _, err := f.client(t).ListUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Graph returns a generous default set otherwise, which on a large
	// directory is megabytes per page of data immediately discarded.
	if !strings.Contains(gotQuery, "%24select=") && !strings.Contains(gotQuery, "$select=") {
		t.Errorf("the request did not restrict its fields: %q", gotQuery)
	}
	for _, field := range []string{"accountEnabled", "mail", "userPrincipalName"} {
		decoded, _ := url.QueryUnescape(gotQuery)
		if !strings.Contains(decoded, field) {
			t.Errorf("query does not request %q: %q", field, decoded)
		}
	}
}
