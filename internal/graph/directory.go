package graph

import (
	"context"
	"fmt"
	"strings"
)

// User is a directory account, reduced to what provisioning needs.
type User struct {
	// ID is the Entra object id. It is the only stable identity: a person's
	// mail and userPrincipalName both change when they marry, move team or the
	// organisation renames its domain.
	ID string `json:"id"`

	DisplayName       string `json:"displayName"`
	GivenName         string `json:"givenName"`
	Surname           string `json:"surname"`
	Mail              string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"`

	// AccountEnabled false means the person has been disabled in Entra —
	// usually because they left. Provisioning must honour it or a leaver keeps
	// their access here after losing it everywhere else.
	AccountEnabled bool `json:"accountEnabled"`
}

// Email returns the address to match a local account by.
//
// mail is the real mailbox and is preferred, but plenty of directories leave
// it empty for accounts that have no Exchange licence, where the
// userPrincipalName is the only address there is.
func (u User) Email() string {
	if mail := strings.TrimSpace(u.Mail); mail != "" {
		return strings.ToLower(mail)
	}
	return strings.ToLower(strings.TrimSpace(u.UserPrincipalName))
}

// Name returns a display name, falling back through what the directory has.
func (u User) Name() string {
	if n := strings.TrimSpace(u.DisplayName); n != "" {
		return n
	}
	if n := strings.TrimSpace(u.GivenName + " " + u.Surname); n != "" {
		return n
	}
	return u.Email()
}

// Group is a directory group.
type Group struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	// MailNickname is the short name, useful when two groups share a display
	// name — which Entra permits.
	MailNickname string `json:"mailNickname"`
}

// Name returns the group's display name, falling back to its short name.
func (g Group) Name() string {
	if n := strings.TrimSpace(g.DisplayName); n != "" {
		return n
	}
	if n := strings.TrimSpace(g.MailNickname); n != "" {
		return n
	}
	return g.ID
}

// userPage and groupPage are Graph's paged envelopes.
type userPage struct {
	Value    []User `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

type groupPage struct {
	Value    []Group `json:"value"`
	NextLink string  `json:"@odata.nextLink"`
}

type memberPage struct {
	Value []struct {
		ID   string `json:"id"`
		Type string `json:"@odata.type"`
	} `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

// ListUsers returns every user in the directory.
//
// Only the fields provisioning uses are requested. Graph returns a generous
// default set otherwise, and on a large directory the difference is megabytes
// per page of data that is then thrown away.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	next := fmt.Sprintf(
		"%s/users?$select=id,displayName,givenName,surname,mail,userPrincipalName,accountEnabled&$top=%d",
		c.graphHost(), pageSize)

	var users []User
	for page := 0; next != "" && page < maxPages; page++ {
		var out userPage
		if err := c.get(ctx, next, &out); err != nil {
			return nil, err
		}
		users = append(users, out.Value...)
		next = out.NextLink
	}
	return users, nil
}

// ListGroups returns every group in the directory.
func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	next := fmt.Sprintf(
		"%s/groups?$select=id,displayName,description,mailNickname&$top=%d",
		c.graphHost(), pageSize)

	var groups []Group
	for page := 0; next != "" && page < maxPages; page++ {
		var out groupPage
		if err := c.get(ctx, next, &out); err != nil {
			return nil, err
		}
		groups = append(groups, out.Value...)
		next = out.NextLink
	}
	return groups, nil
}

// ListGroupMemberIDs returns the object ids of a group's direct user members.
//
// Direct members only. Entra groups can nest, and resolving that is a
// recursive walk with cycles to guard against; it is deliberately left out
// rather than half-done, and the sync reports it as a limitation so nobody
// assumes a nested group's members were included.
//
// Non-user members — nested groups, service principals, devices — are skipped
// rather than treated as people.
func (c *Client) ListGroupMemberIDs(ctx context.Context, groupID string) ([]string, error) {
	next := fmt.Sprintf("%s/groups/%s/members?$select=id&$top=%d",
		c.graphHost(), groupID, pageSize)

	var ids []string
	for page := 0; next != "" && page < maxPages; page++ {
		var out memberPage
		if err := c.get(ctx, next, &out); err != nil {
			return nil, err
		}
		for _, m := range out.Value {
			if m.ID == "" {
				continue
			}
			// Graph tags each member with its type. Anything that is not a
			// user is not a person and must not become one here.
			if m.Type != "" && !strings.EqualFold(m.Type, "#microsoft.graph.user") {
				continue
			}
			ids = append(ids, m.ID)
		}
		next = out.NextLink
	}
	return ids, nil
}

// TestConnection verifies the credentials and permissions without syncing.
//
// It asks for a single user: enough to prove authentication works AND that
// the application permissions were consented, which is the step operators
// most often miss.
func (c *Client) TestConnection(ctx context.Context) error {
	var out userPage
	return c.get(ctx, c.graphHost()+"/users?$select=id&$top=1", &out)
}
