package directory

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Scheduler runs periodic directory syncs
type Scheduler struct {
	db      *database.PostgresDB
	logger  *zap.Logger
	engine  *SyncEngine
	redis   *redis.Client // optional; gates the tick so only one replica syncs
	stopCh  chan struct{}
	running map[string]bool
	mu      sync.Mutex
}

// NewScheduler creates a new sync scheduler
func NewScheduler(db *database.PostgresDB, engine *SyncEngine, logger *zap.Logger) *Scheduler {
	return &Scheduler{
		db:      db,
		logger:  logger.With(zap.String("component", "scheduler")),
		engine:  engine,
		stopCh:  make(chan struct{}),
		running: make(map[string]bool),
	}
}

// Start begins the scheduling loop
func (s *Scheduler) Start(ctx context.Context) {
	ctx = orgctx.WithBypassRLS(ctx)
	s.logger.Info("Directory sync scheduler started")

	// Leader-gated: across replicas only one runs the scheduled syncs each tick,
	// so an LDAP/AD directory isn't synced by every replica simultaneously.
	leader.RunPeriodic(ctx, s.redis, s.logger, "directory:sync", 60*time.Second, s.checkAndRunSyncs)

	select {
	case <-ctx.Done():
	case <-s.stopCh:
	}
}

// Stop halts the scheduler
func (s *Scheduler) Stop() {
	close(s.stopCh)
}

// TriggerSync manually triggers a sync for a directory
func (s *Scheduler) TriggerSync(ctx context.Context, directoryID string, fullSync bool) error {
	s.mu.Lock()
	if s.running[directoryID] {
		s.mu.Unlock()
		return nil // already running
	}
	s.running[directoryID] = true
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.running, directoryID)
			s.mu.Unlock()
		}()

		// Use a background context — the triggering HTTP request context may be canceled
		// mid-sync. directory_integrations (and the user/group tables the sync writes)
		// are FORCE-RLS under the non-owner app role, so the sweep must run under
		// bypass RLS; RunSync re-scopes each write to the integration's own org.
		bgCtx := orgctx.WithBypassRLS(context.Background())

		dirType, configBytes, err := s.loadDirectoryConfig(bgCtx, directoryID)
		if err != nil {
			s.logger.Error("Failed to load directory config for sync", zap.String("id", directoryID), zap.Error(err))
			return
		}

		if _, err := s.engine.RunSync(bgCtx, directoryID, dirType, configBytes, fullSync); err != nil {
			s.logger.Error("Directory sync failed", zap.String("id", directoryID), zap.Error(err))
		}
	}()

	return nil
}

// syncConfig holds the common sync scheduling fields extracted from any directory config type
type syncConfig struct {
	SyncEnabled  bool `json:"sync_enabled"`
	SyncInterval int  `json:"sync_interval"`
}

func (s *Scheduler) checkAndRunSyncs(ctx context.Context) {
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore background scheduler enumerates every org's enabled integrations; RunSync resolves + scopes each by its own org
		`SELECT id, type, config FROM directory_integrations WHERE enabled = true`)
	if err != nil {
		s.logger.Error("Failed to query directories for scheduling", zap.Error(err))
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id, dirType string
		var configBytes []byte
		if err := rows.Scan(&id, &dirType, &configBytes); err != nil {
			continue
		}

		// Extract common sync scheduling fields from any config type
		var sc syncConfig
		if err := json.Unmarshal(configBytes, &sc); err != nil {
			continue
		}

		if !sc.SyncEnabled || sc.SyncInterval <= 0 {
			continue
		}

		// Check if sync is due
		var lastSyncAt *time.Time
		s.db.Pool.QueryRow(ctx,
			//orgscope:ignore background scheduler, keyed by globally-unique directory_id; no single request org
			`SELECT last_sync_at FROM directory_sync_state WHERE directory_id = $1`, id).Scan(&lastSyncAt)

		syncDue := false
		fullSync := false
		if lastSyncAt == nil {
			// Never synced — do full sync
			syncDue = true
			fullSync = true
		} else {
			elapsed := time.Since(*lastSyncAt)
			if elapsed >= time.Duration(sc.SyncInterval)*time.Minute {
				syncDue = true
				// Do a full sync once per day, incremental otherwise
				if elapsed >= 24*time.Hour {
					fullSync = true
				}
			}
		}

		if syncDue {
			s.mu.Lock()
			alreadyRunning := s.running[id]
			s.mu.Unlock()

			if !alreadyRunning {
				s.logger.Info("Triggering scheduled sync",
					zap.String("directory_id", id),
					zap.String("type", dirType),
					zap.Bool("full", fullSync),
				)
				s.TriggerSync(ctx, id, fullSync)
			}
		}
	}
}

func (s *Scheduler) loadDirectoryConfig(ctx context.Context, directoryID string) (string, []byte, error) {
	var dirType string
	var configBytes []byte
	err := s.db.Pool.QueryRow(ctx,
		//orgscope:ignore background scheduler, keyed by globally-unique directory_id; RunSync resolves + scopes the sync by the integration's org
		`SELECT type, config FROM directory_integrations WHERE id = $1`, directoryID).Scan(&dirType, &configBytes)
	if err != nil {
		return "", nil, err
	}
	return dirType, configBytes, nil
}
