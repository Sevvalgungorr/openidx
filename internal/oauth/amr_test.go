package oauth

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// TestSessionAuthMethodsGuards covers the nil-safe guards on the amr helpers:
// no DB, empty/absent session id, and no org context all return nil / no-op
// rather than panicking (so token generation never breaks over amr).
func TestSessionAuthMethodsGuards(t *testing.T) {
	s := &Service{logger: zap.NewNop()} // no db, no orgctx
	ctx := context.Background()

	if got := s.sessionAuthMethods(ctx, nil); got != nil {
		t.Errorf("empty sid: got %v, want nil", got)
	}
	if got := s.sessionAuthMethods(ctx, []string{""}); got != nil {
		t.Errorf("blank sid: got %v, want nil", got)
	}
	if got := s.sessionAuthMethods(ctx, []string{"sid"}); got != nil {
		t.Errorf("nil db: got %v, want nil", got)
	}

	// recordSessionAuthMethods must not panic on the no-op paths.
	s.recordSessionAuthMethods(ctx, "", []string{"pwd"})
	s.recordSessionAuthMethods(ctx, "sid", nil)
	s.recordSessionAuthMethods(ctx, "sid", []string{"pwd"}) // nil db → logged warn, no panic
}
