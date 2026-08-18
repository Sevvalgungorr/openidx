package access

import (
	"testing"

	"github.com/openidx/openidx/internal/common/config"
)

func TestDecideAutoTrust(t *testing.T) {
	const org = "org-1"
	cfg := func(mode, knownOrgs string, requirePosture bool) *config.Config {
		return &config.Config{
			DeviceAutotrustMode:           mode,
			DeviceAutotrustKnownOrgs:      knownOrgs,
			DeviceAutotrustRequirePosture: requirePosture,
		}
	}

	tests := []struct {
		name        string
		cfg         *config.Config
		mfa         bool
		postureOK   bool
		wantTrusted bool
		wantMode    string
	}{
		{"nil cfg", nil, true, true, false, "off"},
		{"off mode", cfg("off", "", false), true, true, false, "off"},
		{"enforce + mfa, no constraints", cfg("enforce", "", false), true, false, true, "enforce"},
		{"enforce but no mfa", cfg("enforce", "", false), false, true, false, "enforce"},
		{"enforce + mfa, require posture but not ok", cfg("enforce", "", true), true, false, false, "enforce"},
		{"enforce + mfa, require posture ok", cfg("enforce", "", true), true, true, true, "enforce"},
		{"enforce + mfa, org not allow-listed", cfg("enforce", "other-org", false), true, true, false, "enforce"},
		{"enforce + mfa, org allow-listed", cfg("enforce", "a,org-1,b", false), true, true, true, "enforce"},
		{"observe never trusts", cfg("observe", "", false), true, true, false, "observe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trusted, mode := decideAutoTrust(tt.cfg, nil, tt.mfa, tt.postureOK, org)
			if trusted != tt.wantTrusted || mode != tt.wantMode {
				t.Errorf("got (trusted=%v, mode=%q), want (trusted=%v, mode=%q)",
					trusted, mode, tt.wantTrusted, tt.wantMode)
			}
		})
	}
}

func TestAMRIndicatesMFA(t *testing.T) {
	cases := []struct {
		amr  []string
		want bool
	}{
		{nil, false},
		{[]string{"pwd"}, false},
		{[]string{"pwd", "otp"}, true},
		{[]string{"mfa"}, true},
		{[]string{"webauthn"}, true},
		{[]string{"PWD", "TOTP"}, true},
		{[]string{"unknown"}, false},
	}
	for _, c := range cases {
		if got := amrIndicatesMFA(c.amr); got != c.want {
			t.Errorf("amrIndicatesMFA(%v) = %v, want %v", c.amr, got, c.want)
		}
	}
}
