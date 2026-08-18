// Package governance provides benchmark tests for governance service
package governance

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

// createTestGovernanceServiceForBench creates a test governance service for benchmarking
func createTestGovernanceServiceForBench(b testing.TB) *Service {
	b.Helper()

	cfg := &config.Config{
		DatabaseURL: "postgres://localhost:5432/openidx_test?sslmode=disable",
	}

	logger := zap.NewNop()

	db, err := database.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		b.Skip("Skipping benchmark: database not available")
	}

	redis, err := database.NewRedis("redis://localhost:6379")
	if err != nil {
		b.Skip("Skipping benchmark: redis not available")
	}

	return NewService(db, redis, cfg, logger)
}

// BenchmarkEvaluatePolicy benchmarks policy evaluation performance
func BenchmarkEvaluatePolicy(b *testing.B) {
	svc := createTestGovernanceServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create test policies of different types
	policyTypes := []PolicyType{
		PolicyTypeSoD,
		PolicyTypeTimebound,
		PolicyTypeLocation,
		PolicyTypeRiskBased,
		PolicyTypeConditionalAccess,
	}

	var policyIDs []string
	now := time.Now()

	for _, pType := range policyTypes {
		policyID := "bench_policy_" + randomString(8)

		rules := make([]PolicyRule, 2)
		for i := range rules {
			rules[i] = PolicyRule{
				Condition: map[string]interface{}{
					"attribute": "role",
					"operator":  "equals",
					"value":     "admin",
				},
				Effect: "deny",
			}
		}

		_, err := svc.db.Pool.Exec(ctx, `
			INSERT INTO policies (id, name, description, type, enabled, rules, created_at, updated_at)
			VALUES ($1, $2, $3, $4, true, $5, $6, $6)
		`, policyID, "Benchmark Policy "+pType, "Policy for benchmarking", pType, rules, now)

		if err == nil {
			policyIDs = append(policyIDs, policyID)
		}
	}

	b.Cleanup(func() {
		for _, id := range policyIDs {
			svc.db.Pool.Exec(ctx, "DELETE FROM policies WHERE id = $1", id)
		}
	})

	// Test request
	request := map[string]interface{}{
		"user_id":   "user123",
		"role":      "admin",
		"ip":        "192.168.1.1",
		"timestamp": time.Now().Unix(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Rotate through different policy types
		policyID := policyIDs[i%len(policyIDs)]
		_, _ = svc.EvaluatePolicy(ctx, policyID, request)
	}
}

// BenchmarkEvaluateSoDPolicy benchmarks Separation of Duty policy evaluation
func BenchmarkEvaluateSoDPolicy(b *testing.B) {
	svc := createTestGovernanceServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	policyID := "bench_sod_policy_" + randomString(8)
	now := time.Now()

	rules := []PolicyRule{
		{
			Condition: map[string]interface{}{
				"conflicting_roles": []string{"admin", "auditor"},
			},
			Effect: "deny",
		},
	}

	svc.db.Pool.Exec(ctx, `
		INSERT INTO policies (id, name, description, type, enabled, rules, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, $5, $6, $6)
	`, policyID, "SoD Policy", "Separation of Duty policy", PolicyTypeSoD, rules, now)

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM policies WHERE id = $1", policyID)
	})

	request := map[string]interface{}{
		"user_id": "user123",
		"roles":   []string{"admin", "user"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.evaluateSoDPolicy(ctx, &Policy{ID: policyID, Type: PolicyTypeSoD, Rules: rules, Enabled: true}, request)
	}
}

// BenchmarkEvaluateTimeboundPolicy benchmarks time-bound policy evaluation
func BenchmarkEvaluateTimeboundPolicy(b *testing.B) {
	svc := createTestGovernanceServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	policyID := "bench_time_policy_" + randomString(8)
	now := time.Now()

	rules := []PolicyRule{
		{
			Condition: map[string]interface{}{
				"start_hour": 9,
				"end_hour":   17,
				"timezone":   "UTC",
			},
			Effect: "allow",
		},
	}

	svc.db.Pool.Exec(ctx, `
		INSERT INTO policies (id, name, description, type, enabled, rules, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, $5, $6, $6)
	`, policyID, "Timebound Policy", "Time-based access policy", PolicyTypeTimebound, rules, now)

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM policies WHERE id = $1", policyID)
	})

	request := map[string]interface{}{
		"user_id":   "user123",
		"timestamp": now.Unix(),
		"timezone":  "UTC",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.evaluateTimeboundPolicy(ctx, &Policy{ID: policyID, Type: PolicyTypeTimebound, Rules: rules, Enabled: true}, request)
	}
}

// BenchmarkCreateReview benchmarks creating an access review
func BenchmarkCreateReview(b *testing.B) {
	svc := createTestGovernanceServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create a reviewer user
	reviewerID := "bench_reviewer_" + randomString(8)
	now := time.Now()

	svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, true, true, $4, $4)
	`, reviewerID, reviewerID, reviewerID+"@example.com", now)

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM access_reviews WHERE reviewer_id = $1", reviewerID)
		svc.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", reviewerID)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		review := &AccessReview{
			ID:          "bench_review_" + randomString(8),
			Name:        "Benchmark Review " + randomString(4),
			Description: "Access review for benchmarking",
			Type:        ReviewTypeUserAccess,
			Status:      ReviewStatusPending,
			ReviewerID:  reviewerID,
			StartDate:   now,
			EndDate:     now.Add(30 * 24 * time.Hour),
		}
		_ = svc.CreateAccessReview(ctx, review)
	}
}

// BenchmarkListAccessReviews benchmarks listing access reviews
func BenchmarkListAccessReviews(b *testing.B) {
	svc := createTestGovernanceServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create test reviews
	const reviewCount = 50
	reviewerID := "bench_list_reviewer_" + randomString(8)
	now := time.Now()

	svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, true, true, $4, $4)
	`, reviewerID, reviewerID, reviewerID+"@example.com", now)

	for i := 0; i < reviewCount; i++ {
		svc.db.Pool.Exec(ctx, `
			INSERT INTO access_reviews (id, name, description, type, status, reviewer_id, start_date, end_date, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $7)
		`, "bench_review_list_"+randomString(8), "Review "+randomString(4), "Description", ReviewTypeUserAccess, ReviewStatusPending, reviewerID, now, now.Add(30*24*time.Hour))
	}

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM access_reviews WHERE reviewer_id = $1", reviewerID)
		svc.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", reviewerID)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = svc.ListAccessReviews(ctx, 0, 20, "")
	}
}

// BenchmarkSubmitReviewDecision benchmarks submitting a review decision
func BenchmarkSubmitReviewDecision(b *testing.B) {
	svc := createTestGovernanceServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create a test review with items
	reviewID := "bench_decision_review_" + randomString(8)
	reviewerID := "bench_decision_reviewer_" + randomString(8)
	now := time.Now()

	svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, true, true, $4, $4)
	`, reviewerID, reviewerID, reviewerID+"@example.com", now)

	svc.db.Pool.Exec(ctx, `
		INSERT INTO access_reviews (id, name, description, type, status, reviewer_id, start_date, end_date, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $7)
	`, reviewID, "Decision Review", "For benchmarking", ReviewTypeUserAccess, ReviewStatusInProgress, reviewerID, now, now.Add(30*24*time.Hour))

	// Create review items
	const itemCount = 10
	for i := 0; i < itemCount; i++ {
		svc.db.Pool.Exec(ctx, `
			INSERT INTO access_review_items (id, review_id, target_id, target_type, decision, decided_by, decided_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, "bench_item_"+randomString(8), reviewID, "user"+randomString(4), "user", ReviewDecisionPending, "", nil)
	}

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM access_review_items WHERE review_id = $1", reviewID)
		svc.db.Pool.Exec(ctx, "DELETE FROM access_reviews WHERE id = $1", reviewID)
		svc.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", reviewerID)
	})

	// Get item IDs
	var itemIDs []string
	rows, _ := svc.db.Pool.Query(ctx, `
		SELECT id FROM access_review_items WHERE review_id = $1 LIMIT $2
	`, reviewID, itemCount)
	defer rows.Close()
	for rows.Next() {
		var id string
		rows.Scan(&id)
		itemIDs = append(itemIDs, id)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		itemID := itemIDs[i%len(itemIDs)]
		_ = svc.SubmitReviewDecision(ctx, reviewID, itemID, ReviewDecisionApproved, "Benchmark decision", reviewerID)
	}
}

// BenchmarkCreatePolicy benchmarks creating policies
func BenchmarkCreatePolicy(b *testing.B) {
	svc := createTestGovernanceServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		policy := &Policy{
			ID:          "bench_policy_create_" + randomString(8),
			Name:        "Benchmark Policy " + randomString(4),
			Description: "Policy for benchmarking",
			Type:        PolicyTypeSoD,
			Enabled:     true,
			Rules: []PolicyRule{
				{
					Condition: map[string]interface{}{
						"role": "admin",
					},
					Effect: "allow",
				},
			},
		}
		_ = svc.CreatePolicy(ctx, policy)
	}
}

// BenchmarkListPolicies benchmarks listing policies
func BenchmarkListPolicies(b *testing.B) {
	svc := createTestGovernanceServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create test policies
	const policyCount = 50
	now := time.Now()

	for i := 0; i < policyCount; i++ {
		svc.db.Pool.Exec(ctx, `
			INSERT INTO policies (id, name, description, type, enabled, rules, created_at, updated_at)
			VALUES ($1, $2, $3, $4, true, $5, $6, $6)
		`, "bench_policy_list_"+randomString(8), "Policy "+randomString(4), "Description", PolicyTypeSoD, []PolicyRule{{}}, now)
	}

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM policies WHERE id LIKE 'bench_policy_list_%'")
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = svc.ListPolicies(ctx, 0, 20)
	}
}

// BenchmarkEvaluateABACPolicies benchmarks ABAC policy evaluation
func BenchmarkEvaluateABACPolicies(b *testing.B) {
	svc := createTestGovernanceServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create test ABAC policies
	const policyCount = 10
	now := time.Now()

	for i := 0; i < policyCount; i++ {
		svc.db.Pool.Exec(ctx, `
			INSERT INTO abac_policies (id, name, description, resource_type, effect, enabled, conditions, created_at, updated_at, org_id)
			VALUES ($1, $2, $3, $4, $5, true, $6, $7, $7, '00000000-0000-0000-0000-000000000010')
		`, "bench_abac_"+randomString(8), "ABAC Policy "+randomString(4), "Description", "document", "allow", `[{"attribute":"department","operator":"equals","value":"finance"}]`, now)
	}

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM abac_policies WHERE id LIKE 'bench_abac_%'")
	})

	// Test request
	req := ABACEvaluationRequest{
		ResourceType: "document",
		ResourceID:   "doc123",
		UserAttributes: map[string]interface{}{
			"user_id":    "user123",
			"department": "finance",
			"role":       "analyst",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = svc.EvaluateABACPolicies(ctx, req)
	}
}

// BenchmarkGetAccessReview benchmarks retrieving a single access review
func BenchmarkGetAccessReview(b *testing.B) {
	svc := createTestGovernanceServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	reviewID := "bench_get_review_" + randomString(8)
	reviewerID := "bench_get_reviewer_" + randomString(8)
	now := time.Now()

	svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, true, true, $4, $4)
	`, reviewerID, reviewerID, reviewerID+"@example.com", now)

	svc.db.Pool.Exec(ctx, `
		INSERT INTO access_reviews (id, name, description, type, status, reviewer_id, start_date, end_date, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $7)
	`, reviewID, "Get Review", "For benchmarking", ReviewTypeUserAccess, ReviewStatusPending, reviewerID, now, now.Add(30*24*time.Hour))

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM access_reviews WHERE id = $1", reviewID)
		svc.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", reviewerID)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.GetAccessReview(ctx, reviewID)
	}
}

// BenchmarkBatchSubmitDecisions benchmarks batch submitting review decisions
func BenchmarkBatchSubmitDecisions(b *testing.B) {
	svc := createTestGovernanceServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	reviewID := "bench_batch_review_" + randomString(8)
	reviewerID := "bench_batch_reviewer_" + randomString(8)
	now := time.Now()

	svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, true, true, $4, $4)
	`, reviewerID, reviewerID, reviewerID+"@example.com", now)

	svc.db.Pool.Exec(ctx, `
		INSERT INTO access_reviews (id, name, description, type, status, reviewer_id, start_date, end_date, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $7)
	`, reviewID, "Batch Review", "For benchmarking", ReviewTypeUserAccess, ReviewStatusInProgress, reviewerID, now, now.Add(30*24*time.Hour))

	// Create review items
	const itemCount = 50
	var itemIDs []string
	for i := 0; i < itemCount; i++ {
		itemID := "bench_batch_item_" + randomString(8)
		itemIDs = append(itemIDs, itemID)
		svc.db.Pool.Exec(ctx, `
			INSERT INTO access_review_items (id, review_id, target_id, target_type, decision, decided_by, decided_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, itemID, reviewID, "user"+randomString(4), "user", ReviewDecisionPending, "", nil)
	}

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM access_review_items WHERE review_id = $1", reviewID)
		svc.db.Pool.Exec(ctx, "DELETE FROM access_reviews WHERE id = $1", reviewID)
		svc.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", reviewerID)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = svc.BatchSubmitDecisions(ctx, reviewID, itemIDs, ReviewDecisionApproved, "Batch approve", reviewerID)
	}
}

// Helper functions

func randomString(n int) string {
	b := make([]byte, n/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}
