package entrasync

import (
	"testing"
	"time"

	"github.com/vsay/vsay-auth/internal/database"
)

func scheduler() *Scheduler {
	return NewScheduler(nil, nil, nil, nil)
}

// A tenant that has never run must run on the next tick, which is also what
// makes a restart pick up changes made while the service was down.
func TestATenantThatHasNeverRunIsDue(t *testing.T) {
	if !scheduler().due(&database.EntraSyncSettings{TenantID: "t1"}) {
		t.Error("a tenant with no recorded run was not considered due")
	}
}

func TestATenantIsNotDueUntilItsIntervalElapses(t *testing.T) {
	s := scheduler()
	settings := &database.EntraSyncSettings{TenantID: "t1", IntervalMinutes: 60}

	s.lastRun["t1"] = time.Now().Add(-30 * time.Minute)
	if s.due(settings) {
		t.Error("a tenant was due after half of its 60-minute interval")
	}

	s.lastRun["t1"] = time.Now().Add(-61 * time.Minute)
	if !s.due(settings) {
		t.Error("a tenant was not due after its interval elapsed")
	}
}

// Each run is a full directory read against a rate-limited API, so an
// over-eager setting must be floored rather than obeyed into a throttle.
func TestVeryShortIntervalsAreFloored(t *testing.T) {
	s := scheduler()
	settings := &database.EntraSyncSettings{TenantID: "t1", IntervalMinutes: 1}

	s.lastRun["t1"] = time.Now().Add(-2 * time.Minute)
	if s.due(settings) {
		t.Error("a one-minute interval was obeyed; Microsoft would throttle this")
	}

	s.lastRun["t1"] = time.Now().Add(-6 * time.Minute)
	if !s.due(settings) {
		t.Error("the floored interval never came due")
	}
}

func TestUnsetIntervalUsesTheDefault(t *testing.T) {
	s := scheduler()
	settings := &database.EntraSyncSettings{TenantID: "t1"} // no interval

	s.lastRun["t1"] = time.Now().Add(-DefaultInterval + time.Minute)
	if s.due(settings) {
		t.Error("a tenant was due before the default interval elapsed")
	}

	s.lastRun["t1"] = time.Now().Add(-DefaultInterval - time.Minute)
	if !s.due(settings) {
		t.Error("the default interval never came due")
	}
}

// The scheduler ticks more often than any tenant's interval, so a five-minute
// setting is honoured roughly on time rather than up to an hour late.
func TestTheTickIsFinerThanTheShortestAllowedInterval(t *testing.T) {
	if scheduler().interval > 5*time.Minute {
		t.Errorf("tick is %s, which is coarser than the minimum interval a tenant can set",
			scheduler().interval)
	}
}
