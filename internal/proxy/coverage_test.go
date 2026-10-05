package proxy

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// backendRepo is where vsay-agent-backend sits relative to this package when
// both repositories are checked out side by side.
const backendRepo = "../../../vsay-agent-backend"

// Every backend endpoint the portal calls reaches it through this proxy. A
// backend route with no proxy route in front of it is not a compile error and
// not a startup error — it is a 404 that only shows up when somebody uses the
// feature. These tests read the backend's own route registrations and check
// each one has a way in.

var (
	// auth.GET("/machines", ...) — routes on the backend's /api group.
	backendAPIRoute = regexp.MustCompile(`\bauth\.(GET|POST|PUT|DELETE|PATCH)\("([^"]+)"`)
	// r.POST("/agent/logs", ...) — root-level routes.
	backendRootRoute = regexp.MustCompile(`(?m)^\tr\.(GET|POST|PUT|DELETE|PATCH)\("([^"]+)"`)
)

type route struct{ method, path string }

func (r route) String() string { return r.method + " " + r.path }

// normalise makes two spellings of the same route comparable. The repositories
// name their path parameters differently (:id vs :machine_id), which does not
// affect routing.
func normalise(path string) string {
	return regexp.MustCompile(`:[A-Za-z_]+`).ReplaceAllString(path, ":p")
}

// registeredRoutes builds a real gin engine with the proxy's routes on it, so
// the test compares against what actually gets registered rather than against
// a second reading of the same source file.
func registeredRoutes(t *testing.T) map[string]bool {
	t.Helper()
	gin.SetMode(gin.TestMode)

	p, err := NewProxy("http://127.0.0.1:1", "test-secret", zap.NewNop())
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	router := gin.New()
	RegisterPublicProxyRoutes(router, p)
	RegisterProxyRoutes(router.Group("/api"), p, func(c *gin.Context) { c.Next() })

	out := map[string]bool{}
	for _, r := range router.Routes() {
		out[r.Method+" "+normalise(r.Path)] = true
	}
	return out
}

func backendSource(t *testing.T) string {
	t.Helper()
	path := filepath.Join(backendRepo, "cmd", "server", "main.go")
	data, err := os.ReadFile(path) // #nosec G304 -- fixed test fixture path
	if err != nil {
		t.Skipf("backend source not available at %s — proxy coverage is unverified in this checkout", path)
	}
	return string(data)
}

func TestEveryBackendAPIRouteIsProxied(t *testing.T) {
	src := backendSource(t)
	proxied := registeredRoutes(t)

	matches := backendAPIRoute.FindAllStringSubmatch(src, -1)
	if len(matches) == 0 {
		t.Fatal("found no backend /api routes — the parser no longer matches the backend's style")
	}

	var missing []string
	for _, m := range matches {
		// The backend's group is /api and so is the proxy's, so the full path
		// is what a caller actually requests.
		want := m[1] + " " + normalise("/api"+m[2])
		if !proxied[want] {
			missing = append(missing, want)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d backend route(s) have no proxy route, so calling them returns 404:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// Agents reach the backend through this proxy too, using the same host they use
// for sign-cert. A missing route here means agents silently fail to deliver.
func TestEveryAgentRouteIsProxied(t *testing.T) {
	src := backendSource(t)
	proxied := registeredRoutes(t)

	matches := backendRootRoute.FindAllStringSubmatch(src, -1)
	if len(matches) == 0 {
		t.Fatal("found no backend root routes — the parser no longer matches the backend's style")
	}

	var missing []string
	for _, m := range matches {
		path := m[2]
		// Only the agent-facing ones. /health, /metrics and friends are
		// deliberately not exposed through the proxy.
		if !strings.HasPrefix(path, "/agent/") {
			continue
		}
		want := m[1] + " " + normalise(path)
		if !proxied[want] {
			missing = append(missing, want)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d agent route(s) have no proxy route, so agents cannot reach them:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// The routes this change added, named explicitly so a regression is reported as
// the specific feature that broke rather than as a count.
func TestLogRoutesAreProxied(t *testing.T) {
	proxied := registeredRoutes(t)

	for _, r := range []route{
		{"POST", "/agent/logs"},              // agents shipping endpoint logs
		{"GET", "/api/config/log-shipping"},  // portal reading the policy
		{"POST", "/api/config/log-shipping"}, // portal saving the policy
	} {
		if !proxied[r.method+" "+r.path] {
			t.Errorf("%s is not proxied", r)
		}
	}
}
