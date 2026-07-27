package access

import "testing"

// localtest-style stale JWT (iss/ctrls = ziti-controller.localtest.me:1280) and
// a good one (ctrl.tdv.org:1280). Payloads are the real base64url segments; the
// signature is irrelevant because the helper parses unverified.
const (
	// {"iss":"https://ziti-controller.localtest.me:1280","ctrls":["tls:ziti-controller.localtest.me:1280"],"exp":9999999999}
	jwtLocaltest = "eyJhbGciOiJub25lIn0." +
		"eyJpc3MiOiJodHRwczovL3ppdGktY29udHJvbGxlci5sb2NhbHRlc3QubWU6MTI4MCIsImN0cmxzIjpbInRsczp6aXRpLWNvbnRyb2xsZXIubG9jYWx0ZXN0Lm1lOjEyODAiXSwiZXhwIjo5OTk5OTk5OTk5fQ." +
		"sig"
	// {"iss":"https://ctrl.tdv.org:1280","ctrls":["tls:ctrl.tdv.org:1280"],"exp":9999999999}
	jwtPublic = "eyJhbGciOiJub25lIn0." +
		"eyJpc3MiOiJodHRwczovL2N0cmwudGR2Lm9yZzoxMjgwIiwiY3RybHMiOlsidGxzOmN0cmwudGR2Lm9yZzoxMjgwIl0sImV4cCI6OTk5OTk5OTk5OX0." +
		"sig"
)

func TestEnrollmentJWTAddressStale(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		wantAddr string
		want     bool
	}{
		{"empty wantAddr disables check", jwtLocaltest, "", false},
		{"localtest token vs public host is stale", jwtLocaltest, "ctrl.tdv.org:1280", true},
		{"localtest token vs public host (no port) is stale", jwtLocaltest, "ctrl.tdv.org", true},
		{"public token vs public host is fresh", jwtPublic, "ctrl.tdv.org:1280", false},
		{"public token vs same host different port is fresh (host match)", jwtPublic, "ctrl.tdv.org:8441", false},
		{"public token vs different host is stale", jwtPublic, "other.example.com", true},
		{"case-insensitive host match is fresh", jwtPublic, "CTRL.TDV.ORG:1280", false},
		{"garbage token is not flagged (left to expiry check)", "not-a-jwt", "ctrl.tdv.org", false},
		{"empty token is not flagged", "", "ctrl.tdv.org", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := enrollmentJWTAddressStale(tt.token, tt.wantAddr); got != tt.want {
				t.Errorf("enrollmentJWTAddressStale(%q, %q) = %v, want %v", tt.name, tt.wantAddr, got, tt.want)
			}
		})
	}
}

func TestHostOnly(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"ctrl.tdv.org:1280", "ctrl.tdv.org"},
		{"ctrl.tdv.org", "ctrl.tdv.org"},
		// hostOnly expects the scheme already stripped by the caller; given a bare
		// host:port it returns the host. (The iss path strips "https://" first.)
		{"host:notaport", "host:notaport"},
		{"host:1280/path", "host"},
		{"  ctrl.tdv.org:1280  ", "ctrl.tdv.org"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := hostOnly(tt.in); got != tt.want {
			t.Errorf("hostOnly(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
