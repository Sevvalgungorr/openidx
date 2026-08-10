package admin

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// systemActorID is the actor passed to the executor when the background
// processor (rather than a logged-in admin) runs a DSAR.
//
// It is deliberately EMPTY. data_subject_requests.processed_by is a nullable
// uuid column, so a descriptive string like "system-dsar-processor" cannot be
// stored there: the UPDATE fails with SQLSTATE 22P02 and the request stays
// pending, which means the processor retries it every tick forever. That is
// exactly what was happening in production — 864 identical failures in 24h
// against 3 stuck export requests, none of which could ever complete.
//
// The executor maps an empty actor to NULL (see nilIfEmpty), and NULL is the
// honest value: no human processed this request. "Which admin did it" is
// answered by processed_by; "was it automated" is answered by processed_by
// being NULL while the request is completed. The audit trail keeps the full
// story either way.
const systemActorID = ""

// dsarAutoExecutableTypes is the allow-list of DSAR types the background
// processor will run unattended. We auto-execute `export` because it's
// non-destructive — the subject is just receiving their own data — and
// because the longer it sits in `pending` the worse our GDPR Article 12
// "without undue delay" obligation looks.
//
// `delete` and `restrict` deliberately stay manual: they change account
// state irreversibly (or visibly), and the operator should sign off on the
// exact moment they happen. A misfiring scheduler that wiped accounts on
// its own would be a far worse incident than a few hours of latency on
// admin click-through.
var dsarAutoExecutableTypes = map[string]struct{}{
	"export": {},
}

// StartDSARProcessor starts a background goroutine that periodically picks
// up pending DSARs and executes them. Modeled after the existing
// `StartRoleExpirationChecker` pattern in internal/identity, so the cmd/
// wiring is a single one-line call alongside the other background workers.
//
// The processor only auto-executes the types in `dsarAutoExecutableTypes`;
// destructive types (delete, restrict) stay manual and the processor logs
// a count of how many were skipped so admins can spot a queue building up.
func (s *Service) StartDSARProcessor(ctx context.Context, interval time.Duration) {
	ctx = orgctx.WithBypassRLS(ctx)
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	s.logger.Info("DSAR processor started",
		zap.Duration("interval", interval),
		zap.Any("auto_execute_types", keys(dsarAutoExecutableTypes)))

	// Leader-gated: process pending data-subject requests once per interval
	// cluster-wide (avoids N replicas each executing the same DSAR).
	var rdb *redis.Client
	if s.redis != nil {
		rdb = s.redis.Client
	}
	// Drain the backlog once on startup, but only on the instance that wins the
	// tick lock so a restart doesn't trigger N concurrent drains.
	if leader.IsLeaderForTick(ctx, rdb, "admin:dsar", interval) {
		s.processPendingDSARs(ctx)
	}
	leader.RunPeriodic(ctx, rdb, s.logger, "admin:dsar", interval, s.processPendingDSARs)
}

// processPendingDSARs is the per-tick body: enumerate pending requests,
// execute the auto-runnable ones, record stats. Each request runs against
// a per-iteration context with a generous timeout so a slow DB query on
// one request can't wedge the processor.
func (s *Service) processPendingDSARs(ctx context.Context) {
	tickCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	// Background cross-org sweep: process pending DSARs across all orgs. org_id is
	// selected so each request is executed under its own org's context (the ticker
	// has no request org), keeping the shared ExecuteDSAR path correctly scoped.
	rows, err := s.db.Pool.Query(tickCtx,
		`SELECT id, user_id, request_type, org_id FROM data_subject_requests
		 WHERE status = 'pending'
		 ORDER BY created_at ASC
		 LIMIT 100`)
	if err != nil {
		s.logger.Error("DSAR processor: failed to list pending requests", zap.Error(err))
		return
	}
	defer rows.Close()

	type job struct {
		id, userID, requestType, orgID string
	}
	var batch []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.id, &j.userID, &j.requestType, &j.orgID); err != nil {
			s.logger.Warn("DSAR processor: failed to scan pending row", zap.Error(err))
			continue
		}
		batch = append(batch, j)
	}
	if err := rows.Err(); err != nil {
		s.logger.Warn("DSAR processor: row iteration error", zap.Error(err))
	}
	// Release the rows iterator before we start kicking off per-request
	// work — each execute call runs more queries against the same pool.
	rows.Close()

	if len(batch) == 0 {
		return
	}

	var executed, skipped, failed int
	for _, j := range batch {
		if _, autoOK := dsarAutoExecutableTypes[j.requestType]; !autoOK {
			skipped++
			continue
		}
		// Re-fetch the full DSAR row for the executor — its delete/export
		// helpers want a *DataSubjectRequest with the same shape as the
		// gin handler path.
		dsar := DataSubjectRequest{
			ID:          j.id,
			UserID:      j.userID,
			RequestType: j.requestType,
			Status:      "pending",
		}
		// Use a per-request context with a shorter deadline so one stuck
		// request can't burn the whole tick budget.
		reqCtx, reqCancel := context.WithTimeout(ctx, 2*time.Minute)
		// Execute under the DSAR's own org so the shared executor stays scoped.
		reqCtx = orgctx.With(reqCtx, orgctx.Org{ID: j.orgID})
		_, err := s.ExecuteDSAR(reqCtx, &dsar, systemActorID)
		reqCancel()
		if err != nil {
			failed++
			s.logger.Error("DSAR processor: execution failed",
				zap.String("dsar_id", j.id),
				zap.String("user_id", j.userID),
				zap.String("request_type", j.requestType),
				zap.Error(err))
			continue
		}
		executed++
	}

	s.logger.Info("DSAR processor tick",
		zap.Int("pending_seen", len(batch)),
		zap.Int("executed", executed),
		zap.Int("skipped_for_manual_review", skipped),
		zap.Int("failed", failed))
}

// keys returns the keys of a set-shaped map as a slice for logging.
func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
