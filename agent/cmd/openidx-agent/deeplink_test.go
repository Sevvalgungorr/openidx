package main

import (
	"reflect"
	"testing"
)

func TestDeepLinkToArgs(t *testing.T) {
	tests := []struct {
		raw      string
		wantArgs []string
		wantOK   bool
	}{
		{
			"openidx://enroll?code=abc123&server=https://openidx.tdv.org",
			[]string{"enroll", "--code", "abc123", "--server", "https://openidx.tdv.org"},
			true,
		},
		{"openidx://enroll?code=abc123", []string{"enroll", "--code", "abc123"}, true},
		{"openidx://enroll?server=https://x", nil, false}, // no code
		{"openidx://other?code=abc", nil, false},          // wrong host
		{"https://openidx.tdv.org", nil, false},           // not our scheme
		{"::::not a url", nil, false},
	}
	for _, tt := range tests {
		gotArgs, gotOK := deepLinkToArgs(tt.raw)
		if gotOK != tt.wantOK || (tt.wantOK && !reflect.DeepEqual(gotArgs, tt.wantArgs)) {
			t.Errorf("deepLinkToArgs(%q) = (%v, %v), want (%v, %v)",
				tt.raw, gotArgs, gotOK, tt.wantArgs, tt.wantOK)
		}
	}
}
