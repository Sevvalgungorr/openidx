package updater

import "testing"

func TestArtifactExt(t *testing.T) {
	cases := []struct{ url, want string }{
		{"https://x/OpenIDX-1.2.0.msi", ".msi"},
		{"https://x/OpenIDX-1.2.0.pkg", ".pkg"},
		{"https://x/openidx_1.2.0_amd64.deb", ".deb"},
		{"https://x/OpenIDX-1.2.0.AppImage", ".appimage"},
		{"https://x/OpenIDX-1.2.0.AppImage?token=abc#frag", ".appimage"},
		{"https://x/openidx-agent", ".bin"},
		{"https://x/download?file=openidx", ".bin"},
	}
	for _, c := range cases {
		if got := artifactExt(c.url); got != c.want {
			t.Errorf("artifactExt(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}

func TestNewer(t *testing.T) {
	cases := []struct {
		current, candidate string
		want               bool
	}{
		{"1.0.0", "1.0.1", true},
		{"1.2.0", "1.10.0", true},
		{"1.2.0", "1.2.0", false},
		{"1.3.0", "1.2.9", false},
		{"dev", "1.0.0", true},
		{"", "0.1.0", true},
		{"2.0.0", "1.9.9", false},
		{"1.0.0-91", "1.0.0-92", true},
	}
	for _, c := range cases {
		if got := Newer(c.current, c.candidate); got != c.want {
			t.Errorf("Newer(%q,%q)=%v want %v", c.current, c.candidate, got, c.want)
		}
	}
}
