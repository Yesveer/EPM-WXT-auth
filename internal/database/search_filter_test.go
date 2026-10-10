package database

import (
	"regexp"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

// orClauses pulls the $or branches out of a search filter.
func orClauses(t *testing.T, filter bson.M) []bson.M {
	t.Helper()
	clauses, ok := filter["$or"].([]bson.M)
	if !ok {
		t.Fatalf("filter has no $or clauses: %v", filter)
	}
	return clauses
}

// An empty box must not narrow the listing, or the first render of the page —
// before anybody has typed — would show nothing.
func TestEmptySearchDoesNotNarrowTheListing(t *testing.T) {
	for name, filter := range map[string]bson.M{
		"users":  userSearchFilter("t1", "   "),
		"groups": groupSearchFilter("t1", "   "),
	} {
		if filter["tenant_id"] != "t1" {
			t.Errorf("%s: tenant scope lost: %v", name, filter)
		}
		if _, narrowed := filter["$or"]; narrowed {
			t.Errorf("%s: a blank search still narrowed the query: %v", name, filter)
		}
	}
}

// The tenant scope is the only thing standing between a search box and another
// customer's data, so it survives alongside the search, never instead of it.
func TestSearchKeepsTheTenantScope(t *testing.T) {
	for name, filter := range map[string]bson.M{
		"users":  userSearchFilter("t1", "priya"),
		"groups": groupSearchFilter("t1", "finance"),
	} {
		if filter["tenant_id"] != "t1" {
			t.Errorf("%s: tenant scope lost: %v", name, filter)
		}
		if filter["$or"] == nil {
			t.Errorf("%s: search term was ignored: %v", name, filter)
		}
	}
}

func TestGroupSearchCoversNameAndDescription(t *testing.T) {
	clauses := orClauses(t, groupSearchFilter("t1", "team"))
	if len(clauses) != 2 {
		t.Fatalf("searched %d fields, want name and description", len(clauses))
	}
	fields := map[string]bool{}
	for _, c := range clauses {
		for field := range c {
			fields[field] = true
		}
	}
	for _, want := range []string{"name", "description"} {
		if !fields[want] {
			t.Errorf("%q is not searched; fields = %v", want, fields)
		}
	}
}

// Without escaping, the search box runs arbitrary patterns against the whole
// collection, and a stray "(" returns an error instead of results.
func TestSearchTermsAreEscapedBeforeTheyBecomeRegexes(t *testing.T) {
	term := "a(b)|.*"
	for name, filter := range map[string]bson.M{
		"users":  userSearchFilter("t1", term),
		"groups": groupSearchFilter("t1", term),
	} {
		clauses := orClauses(t, filter)
		for _, c := range clauses {
			for field, cond := range c {
				pattern := cond.(bson.M)["$regex"].(string)
				if pattern == term {
					t.Errorf("%s: %s took the term unescaped: %q", name, field, pattern)
				}
				re, err := regexp.Compile(pattern)
				if err != nil {
					t.Errorf("%s: %s produced an invalid pattern %q: %v", name, field, pattern, err)
					continue
				}
				// Escaped properly, the pattern matches the literal text the
				// user typed and nothing cleverer.
				if !re.MatchString(term) {
					t.Errorf("%s: %s pattern %q does not match the typed term", name, field, pattern)
				}
				if re.MatchString("anything else") {
					t.Errorf("%s: %s pattern %q still behaves as a regex", name, field, pattern)
				}
			}
		}
	}
}
