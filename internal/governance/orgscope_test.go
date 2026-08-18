package governance

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// v1.7.0 org-scoping contract: governance methods that touch a tenant-scoped
// table (access_reviews, review_items, policies, policy_rules, access_requests,
// access_request_approvals, approval_policies, user_roles, group_memberships,
// user_application_assignments, users, roles, audit_events) read the org from
// context and refuse to run without one. The guard fires before any DB access,
// so these hold with a nil pool. Governance endpoints run behind the resolver,
// so the request always carries an org; the deliberately cross-org paths are the
// background sweeps (campaign scheduler/deadlines, JIT expiry, request
// escalation), which derive each row's org from the data.
func TestGovernance_Service_requireOrgContext(t *testing.T) {
	s := &Service{logger: zap.NewNop()}
	ctx := context.Background()

	t.Run("CreateAccessReview", func(t *testing.T) {
		requireNoOrg(t, s.CreateAccessReview(ctx, &AccessReview{}))
	})
	t.Run("GetAccessReview", func(t *testing.T) {
		_, err := s.GetAccessReview(ctx, "r-1")
		requireNoOrg(t, err)
	})
	t.Run("ListAccessReviews", func(t *testing.T) {
		_, _, err := s.ListAccessReviews(ctx, 0, 10, "")
		requireNoOrg(t, err)
	})
	t.Run("SubmitReviewDecision", func(t *testing.T) {
		requireNoOrg(t, s.SubmitReviewDecision(ctx, "r-1", "i-1", ReviewDecisionApproved, "", "by"))
	})
	t.Run("UpdateAccessReview", func(t *testing.T) {
		requireNoOrg(t, s.UpdateAccessReview(ctx, "r-1", &AccessReview{}))
	})
	t.Run("UpdateReviewStatus", func(t *testing.T) {
		requireNoOrg(t, s.UpdateReviewStatus(ctx, "r-1", ReviewStatusInProgress))
	})
	t.Run("ListReviewItems", func(t *testing.T) {
		_, _, err := s.ListReviewItems(ctx, "r-1", 0, 10, "")
		requireNoOrg(t, err)
	})
	t.Run("BatchSubmitDecisions", func(t *testing.T) {
		requireNoOrg(t, s.BatchSubmitDecisions(ctx, "r-1", []string{"i-1"}, ReviewDecisionApproved, "", "by"))
	})
	t.Run("RunCampaign", func(t *testing.T) {
		_, err := s.RunCampaign(ctx, "c-1")
		requireNoOrg(t, err)
	})
	t.Run("CreatePolicy", func(t *testing.T) {
		requireNoOrg(t, s.CreatePolicy(ctx, &Policy{}))
	})
	t.Run("GetPolicy", func(t *testing.T) {
		_, err := s.GetPolicy(ctx, "p-1")
		requireNoOrg(t, err)
	})
	t.Run("ListPolicies", func(t *testing.T) {
		_, _, err := s.ListPolicies(ctx, 0, 10)
		requireNoOrg(t, err)
	})
	t.Run("UpdatePolicy", func(t *testing.T) {
		requireNoOrg(t, s.UpdatePolicy(ctx, "p-1", &Policy{}))
	})
	t.Run("DeletePolicy", func(t *testing.T) {
		requireNoOrg(t, s.DeletePolicy(ctx, "p-1"))
	})
}

func TestGovernance_RequestService_requireOrgContext(t *testing.T) {
	s := &RequestService{logger: zap.NewNop()}
	ctx := context.Background()

	chain := ApprovalChainConfig{Steps: []ApprovalStep{{Order: 1, Type: ApprovalStepTypeAuto}}}

	t.Run("SubmitRequest", func(t *testing.T) {
		_, err := s.SubmitRequest(ctx, "u-1", "role-1", "justification", chain)
		requireNoOrg(t, err)
	})
	t.Run("ApproveRequest", func(t *testing.T) {
		_, err := s.ApproveRequest(ctx, "r-1", "a-1", "")
		requireNoOrg(t, err)
	})
	t.Run("DenyRequest", func(t *testing.T) {
		_, err := s.DenyRequest(ctx, "r-1", "a-1", "")
		requireNoOrg(t, err)
	})
	t.Run("CancelRequest", func(t *testing.T) {
		requireNoOrg(t, s.CancelRequest(ctx, "r-1", "u-1"))
	})
	t.Run("GetPendingApprovalsForUser", func(t *testing.T) {
		_, err := s.GetPendingApprovalsForUser(ctx, "u-1")
		requireNoOrg(t, err)
	})
}

func requireNoOrg(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, orgctx.ErrNoOrgContext) {
		t.Fatalf("err = %v, want orgctx.ErrNoOrgContext", err)
	}
}
