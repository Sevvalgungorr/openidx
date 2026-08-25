package sso

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMobileLoginSaveLoadRoundTrip verifies that a persisted MobileLogin reloads
// with identical PKCE material, state, and server URL — the property the mobile
// cold-start callback relies on to complete the code exchange after a restart.
func TestMobileLoginSaveLoadRoundTrip(t *testing.T) {
	m, _, err := StartMobileLogin("https://openidx.test/")
	if err != nil {
		t.Fatalf("StartMobileLogin: %v", err)
	}

	path := filepath.Join(t.TempDir(), "login_pending.json")
	if err := m.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perms = %o, want 600", perm)
	}

	loaded, err := LoadMobileLogin(path)
	if err != nil {
		t.Fatalf("LoadMobileLogin: %v", err)
	}
	if loaded.verifier != m.verifier {
		t.Errorf("verifier = %q, want %q", loaded.verifier, m.verifier)
	}
	if loaded.state != m.state {
		t.Errorf("state = %q, want %q", loaded.state, m.state)
	}
	if loaded.serverURL != m.serverURL {
		t.Errorf("serverURL = %q, want %q", loaded.serverURL, m.serverURL)
	}
}

func TestLoadMobileLoginMissingFile(t *testing.T) {
	if _, err := LoadMobileLogin(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error loading a missing file")
	}
}
