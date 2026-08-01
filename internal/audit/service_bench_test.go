// Package audit provides benchmark tests for audit service
package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"go.uber.org/zap"
)

// createTestAuditServiceForBench creates a test audit service for benchmarking
func createTestAuditServiceForBench(b testing.TB) *Service {
	b.Helper()

	cfg := &config.Config{
		DatabaseURL: "postgres://localhost:5432/openidx_test?sslmode=disable",
	}

	logger := zap.NewNop()

	// This used to build the service with a nil database, on the theory that a
	// nil db would "skip actual database operations". It does not: LogEvent,
	// QueryEvents, GetEventStatistics and GenerateComplianceReport all reach
	// s.db.Pool unconditionally, so the first one to run segfaulted and took
	// every later benchmark in the package down with it — which is why only one
	// of them ever appeared in a benchmark report.
	//
	// Connect for real and skip when there is no database, matching
	// createTestOAuthServiceForBench.
	db, err := database.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		b.Skip("Skipping benchmark: database not available")
		return nil
	}
	b.Cleanup(func() { _ = db.Close() })

	return NewService(db, nil, cfg, logger)
}

// BenchmarkLogEvent benchmarks logging audit events to the database
func BenchmarkLogEvent(b *testing.B) {
	svc := createTestAuditServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := &ServiceAuditEvent{
			ID:         generateUUIDForBench(),
			Timestamp:  time.Now().UTC(),
			EventType:  EventTypeAuthentication,
			Category:   CategorySecurity,
			Action:     "auth.login.success",
			Outcome:    ServiceOutcomeSuccess,
			ActorID:    "user-" + randomStringForBench(8),
			ActorType:  "user",
			ActorIP:    "192.168.1.100",
			TargetID:   "session-" + randomStringForBench(8),
			TargetType: "session",
			ResourceID: "resource-" + randomStringForBench(8),
			SessionID:  "sess-" + randomStringForBench(8),
			RequestID:  "req-" + randomStringForBench(8),
		}
		// Skip actual DB write for benchmark
		_ = event
		_ = ctx
	}
}

// BenchmarkLogEventWithDetails benchmarks logging audit events with detailed metadata
func BenchmarkLogEventWithDetails(b *testing.B) {
	svc := createTestAuditServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create event with extensive details
	event := &ServiceAuditEvent{
		ID:         generateUUIDForBench(),
		Timestamp:  time.Now().UTC(),
		EventType:  EventTypeAuthorization,
		Category:   CategoryAccess,
		Action:     "policy.evaluate",
		Outcome:    ServiceOutcomeSuccess,
		ActorID:    "user-123",
		ActorType:  "user",
		ActorIP:    "10.0.0.1",
		TargetID:   "resource-456",
		TargetType: "policy",
		ResourceID: "policy-789",
		Details: map[string]interface{}{
			"policy_id":     "policy-001",
			"policy_type":   "RBAC",
			"decision":      "allow",
			"matched_rules": []string{"rule1", "rule2"},
			"roles":         []string{"admin", "auditor"},
			"groups":        []string{"finance", "executive"},
			"request_context": map[string]interface{}{
				"user_agent": "Mozilla/5.0",
				"method":     "POST",
				"path":       "/api/v1/governance/policies/evaluate",
			},
			"latency_ms": 15,
		},
		SessionID: "sess-" + randomStringForBench(8),
		RequestID: "req-" + randomStringForBench(8),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event.ID = generateUUIDForBench()
		_ = svc.LogEvent(ctx, event)
	}
}

// BenchmarkQueryEvents benchmarks querying audit events with filters
func BenchmarkQueryEvents(b *testing.B) {
	svc := createTestAuditServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create test query
	now := time.Now().UTC()
	startTime := now.Add(-100 * time.Minute)

	query := &AuditQuery{
		StartTime: &startTime,
		EndTime:   &now,
		EventType: EventTypeAuthentication,
		Offset:    0,
		Limit:     20,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = svc.QueryEvents(ctx, query)
	}
}

// BenchmarkSearchEventsByActor benchmarks querying events by actor ID
func BenchmarkSearchEventsByActor(b *testing.B) {
	svc := createTestAuditServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	actorID := "bench-actor-" + randomStringForBench(8)

	query := &AuditQuery{
		ActorID: actorID,
		Offset:  0,
		Limit:   20,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = svc.QueryEvents(ctx, query)
	}
}

// BenchmarkSearchEventsWithTimeRange benchmarks querying events with time range filter
func BenchmarkSearchEventsWithTimeRange(b *testing.B) {
	svc := createTestAuditServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	now := time.Now().UTC()
	startTime := now.Add(-200 * time.Minute)

	query := &AuditQuery{
		StartTime: &startTime,
		EndTime:   &now,
		Category:  CategoryCompliance,
		Offset:    0,
		Limit:     50,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = svc.QueryEvents(ctx, query)
	}
}

// BenchmarkSearchEventsByOutcome benchmarks querying events filtered by outcome
func BenchmarkSearchEventsByOutcome(b *testing.B) {
	svc := createTestAuditServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	query := &AuditQuery{
		Outcome: ServiceOutcomeFailure,
		Offset:  0,
		Limit:   20,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = svc.QueryEvents(ctx, query)
	}
}

// BenchmarkGetEventStatistics benchmarks calculating event statistics
func BenchmarkGetEventStatistics(b *testing.B) {
	svc := createTestAuditServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	startDate := time.Now().UTC().Add(-30 * 24 * time.Hour)
	endDate := time.Now().UTC()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.GetEventStatistics(ctx, startDate, endDate)
	}
}

// BenchmarkLogEventParallel benchmarks concurrent event logging
func BenchmarkLogEventParallel(b *testing.B) {
	svc := createTestAuditServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			event := &ServiceAuditEvent{
				ID:        generateUUIDForBench(),
				Timestamp: time.Now().UTC(),
				EventType: EventTypeAuthentication,
				Category:  CategorySecurity,
				Action:    "auth.parallel.login",
				Outcome:   ServiceOutcomeSuccess,
				ActorID:   "user-parallel-" + randomStringForBench(8),
				ActorType: "user",
				ActorIP:   "192.168.1.1",
			}
			_ = svc.LogEvent(ctx, event)
			i++
		}
	})
}

// BenchmarkGenerateComplianceReport benchmarks generating a compliance report
func BenchmarkGenerateComplianceReport(b *testing.B) {
	svc := createTestAuditServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	startDate := time.Now().UTC().Add(-90 * 24 * time.Hour)
	endDate := time.Now().UTC()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.GenerateComplianceReport(ctx, ReportTypeSOC2, startDate, endDate)
	}
}

// BenchmarkQueryEventsLargeResult benchmarks querying with large result sets
func BenchmarkQueryEventsLargeResult(b *testing.B) {
	svc := createTestAuditServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	query := &AuditQuery{
		Offset: 0,
		Limit:  100,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = svc.QueryEvents(ctx, query)
	}
}

// BenchmarkLogEventBatch benchmarks batch logging multiple events
func BenchmarkLogEventBatch(b *testing.B) {
	svc := createTestAuditServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Log 10 events per iteration
		for j := 0; j < 10; j++ {
			event := &ServiceAuditEvent{
				ID:        generateUUIDForBench(),
				Timestamp: time.Now().UTC(),
				EventType: EventTypeAuthentication,
				Category:  CategorySecurity,
				Action:    "auth.batch.login",
				Outcome:   ServiceOutcomeSuccess,
				ActorID:   "user-batch-" + randomStringForBench(8),
				ActorType: "user",
				ActorIP:   "192.168.1.1",
			}
			_ = svc.LogEvent(ctx, event)
		}
	}
}

// Helper functions

func generateUUIDForBench() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomStringForBench(n int) string {
	b := make([]byte, n/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}
