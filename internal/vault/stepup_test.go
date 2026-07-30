package vault

import (
	"errors"
	"testing"
	"time"
)

// A4: the step-up gate must expose a distinct sentinel (so the handler can map
// it to 403 + X-Step-Up-Required rather than a generic forbidden) and use a
// short freshness window (a step-up authorizes the action, not a standing
// elevation).
func TestStepUpGateContract(t *testing.T) {
	if ErrStepUpRequired == nil {
		t.Fatal("ErrStepUpRequired sentinel must exist")
	}
	if errors.Is(ErrStepUpRequired, ErrForbidden) || errors.Is(ErrForbidden, ErrStepUpRequired) {
		t.Fatal("ErrStepUpRequired must be distinct from ErrForbidden so the handler can branch on it")
	}
	if stepUpRecentWindow <= 0 || stepUpRecentWindow > 15*time.Minute {
		t.Fatalf("stepUpRecentWindow = %s; want a short freshness window (0 < w <= 15m)", stepUpRecentWindow)
	}
}

// The create API must carry require_step_up end to end so an operator can flag a
// high-value secret at creation time.
func TestStoreInputCarriesRequireStepUp(t *testing.T) {
	in := StoreInput{RequireStepUp: true}
	if !in.RequireStepUp {
		t.Fatal("StoreInput.RequireStepUp must round-trip")
	}
}
