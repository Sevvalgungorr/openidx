package access

import "testing"

func TestExpandSubnet(t *testing.T) {
	t.Run("/29 skips network+broadcast", func(t *testing.T) {
		got, err := expandSubnet(subnetSpec{CIDR: "10.0.5.0/29", Port: 22, NamePrefix: "ssh", Ziti: true})
		if err != nil {
			t.Fatal(err)
		}
		// /29 = 8 addrs, minus network (.0) + broadcast (.7) = 6 hosts.
		if len(got) != 6 {
			t.Fatalf("want 6 hosts, got %d: %+v", len(got), got)
		}
		if got[0].Name != "ssh-10.0.5.1" || got[0].ToURL != "tcp://10.0.5.1:22" || !got[0].Ziti {
			t.Errorf("first host = %+v", got[0])
		}
		if got[5].ToURL != "tcp://10.0.5.6:22" {
			t.Errorf("last host = %+v", got[5])
		}
	})

	t.Run("/32 single host, no end-skip", func(t *testing.T) {
		got, err := expandSubnet(subnetSpec{CIDR: "10.0.0.9/32", Port: 443, Protocol: "https"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].ToURL != "https://10.0.0.9:443" {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("rejects too-large subnet", func(t *testing.T) {
		if _, err := expandSubnet(subnetSpec{CIDR: "10.0.0.0/16", Port: 22}); err == nil {
			t.Error("expected error for /16")
		}
	})

	t.Run("rejects bad input", func(t *testing.T) {
		if _, err := expandSubnet(subnetSpec{CIDR: "not-a-cidr", Port: 22}); err == nil {
			t.Error("expected cidr error")
		}
		if _, err := expandSubnet(subnetSpec{CIDR: "10.0.0.0/30", Port: 0}); err == nil {
			t.Error("expected port error")
		}
	})
}

func TestRouteTypeForURL(t *testing.T) {
	cases := map[string]string{
		"http://x:80": "http",
		"https://x":   "http",
		"tcp://x:22":  "tcp",
		"10.0.0.1:22": "tcp",
	}
	for in, want := range cases {
		if got := routeTypeForURL(in); got != want {
			t.Errorf("routeTypeForURL(%q) = %q, want %q", in, got, want)
		}
	}
}
