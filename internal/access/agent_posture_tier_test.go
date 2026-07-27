package access

import (
	"context"
	"testing"
)

func hasAttr(attrs []string, want string) bool {
	for _, a := range attrs {
		if a == want {
			return true
		}
	}
	return false
}

func TestDeviceTrustAttrs(t *testing.T) {
	tests := []struct {
		name         string
		attrs        []string
		want         bool
		wantChanged  bool
		wantHasTrust bool
	}{
		{"grant to empty", nil, true, true, true},
		{"grant when missing", []string{"enrolled-users", "browzer-users"}, true, true, true},
		{"already trusted -> no change", []string{"enrolled-users", "device-trusted"}, true, false, true},
		{"revoke when present", []string{"enrolled-users", "device-trusted"}, false, true, false},
		{"not trusted, want revoke -> no change", []string{"enrolled-users"}, false, false, false},
		{"revoke from only-trust", []string{"device-trusted"}, false, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next, changed := deviceTrustAttrs(tt.attrs, tt.want)
			if changed != tt.wantChanged {
				t.Errorf("changed = %v, want %v (next=%v)", changed, tt.wantChanged, next)
			}
			if got := hasAttr(next, "device-trusted"); got != tt.wantHasTrust {
				t.Errorf("device-trusted present = %v, want %v (next=%v)", got, tt.wantHasTrust, next)
			}
			// Non-trust attributes must be preserved exactly.
			for _, a := range tt.attrs {
				if a != "device-trusted" && !hasAttr(next, a) {
					t.Errorf("dropped non-trust attribute %q (next=%v)", a, next)
				}
			}
			// The trust attribute must never appear more than once.
			count := 0
			for _, a := range next {
				if a == "device-trusted" {
					count++
				}
			}
			if count > 1 {
				t.Errorf("device-trusted duplicated %d times (next=%v)", count, next)
			}
		})
	}
}

// applyPostureDeviceTrust must be a safe no-op when the gate is off / unconfigured
// (the default). With a nil ZitiManager the handler must not panic and must do
// nothing — this guards the "single-tenant installs unchanged" contract.
func TestApplyPostureDeviceTrust_OffIsNoop(t *testing.T) {
	h := newTestAgentHandler() // nil db + nil zm
	// Should return immediately without panicking regardless of status.
	h.applyPostureDeviceTrust(context.Background(), "agent-x", "compliant")
	h.applyPostureDeviceTrust(context.Background(), "agent-x", "non_compliant")
}
