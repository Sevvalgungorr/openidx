package access

import (
	"strings"
	"testing"
)

func TestAllocateLoopbackPort(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		used []int
		base int
		max  int
		want int
	}{
		{"empty picks base", nil, 14000, 14999, 14000},
		{"skips taken prefix", []int{14000, 14001}, 14000, 14999, 14002},
		{"fills lowest gap", []int{14000, 14002}, 14000, 14999, 14001},
		{"out-of-window used ignored", []int{22, 3389}, 14000, 14999, 14000},
		{"exhausted returns 0", []int{14000, 14001}, 14000, 14001, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := allocateLoopbackPort(tc.used, tc.base, tc.max); got != tc.want {
				t.Fatalf("allocateLoopbackPort(%v,%d,%d) = %d, want %d", tc.used, tc.base, tc.max, got, tc.want)
			}
		})
	}
}

// The whole point of ziti reach: in ziti mode guacd must dial the broker's
// loopback intercept, never the real target; direct mode dials the target.
func TestPamLaunchEntryDialTarget(t *testing.T) {
	t.Parallel()

	direct := pamLaunchEntry{Hostname: "dc01.corp", Port: 3389, ReachMode: "direct"}
	if h, p := direct.dialTarget(); h != "dc01.corp" || p != 3389 {
		t.Fatalf("direct dialTarget = %s:%d, want dc01.corp:3389", h, p)
	}

	ziti := pamLaunchEntry{Hostname: "dc01.corp", Port: 3389, ReachMode: "ziti", ZitiInterceptPort: 14007}
	if h, p := ziti.dialTarget(); h != pamZitiInterceptHost || p != 14007 {
		t.Fatalf("ziti dialTarget = %s:%d, want %s:14007 — target must NOT be dialed directly", h, p, pamZitiInterceptHost)
	}
	// The intercept host must be non-loopback: ziti-edge-tunnel (TUN mode) cannot
	// intercept 127.0.0.0/8 because the kernel short-circuits loopback.
	if strings.HasPrefix(pamZitiInterceptHost, "127.") {
		t.Fatalf("pamZitiInterceptHost = %s is loopback; TUN-mode tunnel cannot intercept it", pamZitiInterceptHost)
	}

	// A ziti entry with no assigned intercept port must fall back to the real
	// target rather than dial the intercept host with port 0.
	broken := pamLaunchEntry{Hostname: "dc01.corp", Port: 3389, ReachMode: "ziti", ZitiInterceptPort: 0}
	if h, p := broken.dialTarget(); h != "dc01.corp" || p != 3389 {
		t.Fatalf("ziti-without-port dialTarget = %s:%d, want fallback dc01.corp:3389", h, p)
	}
}

// A connection's per-entry choice (reach_mode) must route to the matching
// dedicated broker: ziti → the OpenZiti broker, direct/empty → the direct
// broker; and a missing broker must resolve to nil so connect fails closed
// rather than launching through the wrong data plane.
func TestBrokerFor(t *testing.T) {
	t.Parallel()

	direct := &GuacamoleClient{}
	ziti := &GuacamoleClient{}

	both := &Service{guacamoleClient: direct, guacamoleZitiClient: ziti}
	if both.brokerFor("direct") != direct {
		t.Fatal("direct reach must use the direct broker")
	}
	if both.brokerFor("") != direct {
		t.Fatal("empty reach must default to the direct broker")
	}
	if both.brokerFor("ziti") != ziti {
		t.Fatal("ziti reach must use the dedicated ziti broker")
	}

	// Ziti chosen but no ziti broker configured → nil (fail closed).
	directOnly := &Service{guacamoleClient: direct}
	if directOnly.brokerFor("ziti") != nil {
		t.Fatal("ziti reach with no ziti broker must be nil, not the direct broker")
	}
	// Direct chosen but no direct broker configured → nil.
	zitiOnly := &Service{guacamoleZitiClient: ziti}
	if zitiOnly.brokerFor("direct") != nil {
		t.Fatal("direct reach with no direct broker must be nil")
	}
}

func TestPamZitiServiceName(t *testing.T) {
	t.Parallel()

	got := pamZitiServiceName("abc-123")
	if got != "openidx-pam-abc-123" {
		t.Fatalf("pamZitiServiceName = %q", got)
	}
	// The service name must carry the openidx- prefix TeardownZitiServiceByName
	// keys its openidx-bind-/openidx-dial-/openidx-serp- cleanup off.
	if got[:8] != "openidx-" {
		t.Fatalf("service name %q lacks openidx- prefix required for teardown", got)
	}
}
