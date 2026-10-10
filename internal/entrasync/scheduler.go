package entrasync

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/vsay/vsay-auth/internal/database"
	"github.com/vsay/vsay-auth/internal/graph"
)

// SettingsSource supplies the tenants to sync and records the outcome.
type SettingsSource interface {
	ListEntraSyncSettings() ([]*database.EntraSyncSettings, error)
	RecordEntraSyncRun(tenantID, status, errMsg string, counts database.EntraSyncCounts) error
}

// CredentialResolver turns a tenant's settings into Graph credentials,
// applying the fallback to the shared sign-in registration.
type CredentialResolver func(*database.EntraSyncSettings) graph.Config

// Scheduler runs directory syncs on each tenant's own interval.
type Scheduler struct {
	syncer   *Syncer
	source   SettingsSource
	resolve  CredentialResolver
	logger   *zap.Logger
	interval time.Duration

	// lastRun is kept in memory rather than read back from the database each
	// tick. A restart therefore syncs every enabled tenant once on startup,
	// which is the behaviour you want anyway: the directory may well have
	// changed while the service was down.
	lastRun map[string]time.Time
}

// NewScheduler builds the periodic runner.
func NewScheduler(syncer *Syncer, source SettingsSource, resolve CredentialResolver, logger *zap.Logger) *Scheduler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Scheduler{
		syncer: syncer, source: source, resolve: resolve, logger: logger,
		// The tick is finer than any tenant's interval so that a five-minute
		// setting is honoured roughly on time rather than up to an hour late.
		interval: 5 * time.Minute,
		lastRun:  map[string]time.Time{},
	}
}

// Run ticks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	s.logger.Info("Directory sync scheduler started")

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("Directory sync scheduler stopped")
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

// tick syncs every tenant that is due.
func (s *Scheduler) tick(ctx context.Context) {
	all, err := s.source.ListEntraSyncSettings()
	if err != nil {
		s.logger.Warn("Directory sync: could not list tenants", zap.Error(err))
		return
	}

	for _, settings := range all {
		if ctx.Err() != nil {
			return
		}
		if !settings.Enabled || (!settings.SyncUsers && !settings.SyncGroups) {
			continue
		}
		if !s.due(settings) {
			continue
		}
		s.runOne(ctx, settings)
	}
}

// due reports whether a tenant's interval has elapsed.
func (s *Scheduler) due(settings *database.EntraSyncSettings) bool {
	interval := DefaultInterval
	if settings.IntervalMinutes > 0 {
		interval = time.Duration(settings.IntervalMinutes) * time.Minute
	}
	// A floor, because each run is a full directory read against a
	// rate-limited API and a one-minute setting would simply get throttled.
	if interval < 5*time.Minute {
		interval = 5 * time.Minute
	}

	last, ran := s.lastRun[settings.TenantID]
	return !ran || time.Since(last) >= interval
}

// runOne syncs a single tenant and records the result.
func (s *Scheduler) runOne(ctx context.Context, settings *database.EntraSyncSettings) {
	s.lastRun[settings.TenantID] = time.Now()

	client, err := graph.New(s.resolve(settings))
	if err != nil {
		s.record(settings.TenantID, "failed", err.Error(), database.EntraSyncCounts{})
		return
	}

	runCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	counts, runErr := s.syncer.Run(runCtx, settings, client)

	status, errMsg := "success", ""
	if runErr != nil {
		errMsg = runErr.Error()
		status = "failed"
		if counts.UsersCreated+counts.UsersUpdated+counts.GroupsCreated+counts.GroupsUpdated > 0 {
			// Work was done before it broke, and reporting that as a flat
			// failure sends an operator looking for a problem that is not there.
			status = "partial"
		}
		s.logger.Warn("Directory sync finished with an error",
			zap.String("tenant", settings.TenantID), zap.Error(runErr))
	} else {
		s.logger.Info("Directory sync finished",
			zap.String("tenant", settings.TenantID),
			zap.Int("users_created", counts.UsersCreated),
			zap.Int("users_updated", counts.UsersUpdated),
			zap.Int("users_disabled", counts.UsersDisabled),
			zap.Int("groups_created", counts.GroupsCreated),
			zap.Int("groups_updated", counts.GroupsUpdated))
	}

	s.record(settings.TenantID, status, errMsg, counts)
}

func (s *Scheduler) record(tenantID, status, errMsg string, counts database.EntraSyncCounts) {
	if err := s.source.RecordEntraSyncRun(tenantID, status, errMsg, counts); err != nil {
		s.logger.Warn("Directory sync: could not record the run",
			zap.String("tenant", tenantID), zap.Error(err))
	}
}
