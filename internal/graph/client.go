// Package graph is a small Microsoft Graph client, limited to what directory
// synchronisation needs: listing users, groups and group membership.
//
// It uses the client-credentials flow — the application acts as itself, not on
// behalf of a signed-in person — because a sync runs on a schedule with nobody
// present. That requires APPLICATION permissions granted with admin consent in
// Entra (User.Read.All and Group.Read.All); delegated permissions, which are
// what the sign-in button uses, will not work here and fail with a 403 that
// says very little. See ErrForbidden below.
package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultLoginHost = "https://login.microsoftonline.com"
	defaultGraphHost = "https://graph.microsoft.com/v1.0"

	// graphScope requests every application permission the app has been
	// granted. Graph does not accept a list of individual scopes for the
	// client-credentials flow.
	graphScope = "https://graph.microsoft.com/.default"

	// pageSize is what Graph is asked for per page. Graph caps it at 999 for
	// these collections and silently returns fewer; asking for the maximum
	// keeps a 5,000-person directory to six round trips rather than fifty.
	pageSize = 999

	// maxPages bounds a listing. A directory larger than this is real, but a
	// paging bug that never advances is far more likely, and an unbounded loop
	// against a paid API is not a failure mode worth having.
	maxPages = 200
)

// ErrForbidden is returned when Graph rejects the call for lack of permission.
//
// It is distinguished from other failures because it is almost always the same
// one cause — application permissions were never granted admin consent — and
// an operator reading "403" learns nothing, while reading that learns
// everything.
var ErrForbidden = fmt.Errorf("Microsoft Graph refused the request: the app registration needs the User.Read.All and Group.Read.All APPLICATION permissions, granted with admin consent")

// Config identifies the Entra application to authenticate as.
type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string

	// LoginHost and GraphHost exist so tests can point at a local server.
	// Empty means the real Microsoft endpoints.
	LoginHost string
	GraphHost string

	// HTTPClient is optional; a sensible timeout is applied when nil.
	HTTPClient *http.Client
}

// Client talks to Microsoft Graph.
type Client struct {
	cfg  Config
	http *http.Client

	mu        sync.Mutex
	token     string
	tokenTill time.Time
}

// New builds a client. It does not contact Microsoft.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.TenantID) == "" {
		return nil, fmt.Errorf("a directory (tenant) ID is required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, fmt.Errorf("an application (client) ID is required")
	}
	if strings.TrimSpace(cfg.ClientSecret) == "" {
		return nil, fmt.Errorf("a client secret is required")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{cfg: cfg, http: httpClient}, nil
}

func (c *Client) loginHost() string {
	if c.cfg.LoginHost != "" {
		return strings.TrimSuffix(c.cfg.LoginHost, "/")
	}
	return defaultLoginHost
}

func (c *Client) graphHost() string {
	if c.cfg.GraphHost != "" {
		return strings.TrimSuffix(c.cfg.GraphHost, "/")
	}
	return defaultGraphHost
}

// accessToken returns a cached token, fetching a new one when needed.
//
// Tokens last an hour and a full sync makes many calls, so re-fetching per
// request would turn one sync into hundreds of needless authentications
// against a rate-limited endpoint.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Renew a minute early rather than on the exact boundary, so a token does
	// not expire in flight between the check and the call that uses it.
	if c.token != "" && time.Now().Before(c.tokenTill.Add(-time.Minute)) {
		return c.token, nil
	}

	form := url.Values{
		"client_id":     {c.cfg.ClientID},
		"client_secret": {c.cfg.ClientSecret},
		"scope":         {graphScope},
		"grant_type":    {"client_credentials"},
	}
	endpoint := c.loginHost() + "/" + url.PathEscape(c.cfg.TenantID) + "/oauth2/v2.0/token"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("contacting Microsoft to authenticate: %w", err)
	}
	defer drainAndClose(resp)

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		// Microsoft's token endpoint returns a precise reason; surfacing it is
		// the difference between "sync failed" and "your secret expired".
		return "", fmt.Errorf("Microsoft rejected the credentials: %s", tokenError(body, resp.StatusCode))
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("Microsoft returned a token response we could not read")
	}

	c.token = out.AccessToken
	c.tokenTill = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return c.token, nil
}

// tokenError extracts the human-readable part of a token failure.
func tokenError(body []byte, status int) string {
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &e) == nil && e.Description != "" {
		// The description is multi-line and begins with a correlation id that
		// means nothing to the reader; the first line carries the reason.
		if line, _, found := strings.Cut(e.Description, "\n"); found {
			return strings.TrimSpace(line)
		}
		return strings.TrimSpace(e.Description)
	}
	if e.Error != "" {
		return e.Error
	}
	return fmt.Sprintf("HTTP %d", status)
}

// get performs one authenticated Graph request.
func (c *Client) get(ctx context.Context, rawURL string, out any) error {
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	// Entra requires this header to return the accountEnabled property and a
	// few others on directory objects.
	req.Header.Set("ConsistencyLevel", "eventual")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("contacting Microsoft Graph: %w", err)
	}
	defer drainAndClose(resp)

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))

	switch {
	case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusUnauthorized:
		return ErrForbidden
	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("Microsoft Graph is rate-limiting this request; the sync will retry on its next run")
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return fmt.Errorf("Microsoft Graph returned %d: %s", resp.StatusCode, graphError(body))
	}

	return json.Unmarshal(body, out)
}

// graphError extracts Graph's own message from an error body.
func graphError(body []byte) string {
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		return e.Error.Message
	}
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) > 200 {
		trimmed = trimmed[:200]
	}
	return trimmed
}

func drainAndClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
}
