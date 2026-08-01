package access

import (
	"encoding/json"
	"testing"
)

func TestBuildPamGuacParams(t *testing.T) {
	t.Parallel()

	t.Run("password injection with identity", func(t *testing.T) {
		p := buildPamGuacParams("password", "administrator", "CORP", []byte("s3cret"), nil, false, "", "")
		if p["username"] != "administrator" || p["domain"] != "CORP" || p["password"] != "s3cret" {
			t.Fatalf("unexpected params: %v", p)
		}
		if _, ok := p["private-key"]; ok {
			t.Fatal("password secret must not set private-key")
		}
	})

	t.Run("ssh_key injects as private-key", func(t *testing.T) {
		p := buildPamGuacParams("ssh_key", "root", "", []byte("-----BEGIN KEY-----"), nil, false, "", "")
		if p["private-key"] != "-----BEGIN KEY-----" {
			t.Fatalf("private-key missing: %v", p)
		}
		if _, ok := p["password"]; ok {
			t.Fatal("ssh_key secret must not set password")
		}
	})

	t.Run("no credential leaves auth params unset", func(t *testing.T) {
		p := buildPamGuacParams("", "user", "", nil, nil, false, "", "")
		if _, ok := p["password"]; ok {
			t.Fatal("empty credential must not set password")
		}
		if p["username"] != "user" {
			t.Fatal("username should still be set for manual login")
		}
	})

	t.Run("recording params only when recording", func(t *testing.T) {
		p := buildPamGuacParams("password", "u", "", []byte("x"), nil, true, "/rec", "pam-1-2")
		if p["recording-path"] != "/rec" || p["recording-name"] != "pam-1-2" || p["recording-include-keys"] != "true" {
			t.Fatalf("recording params missing: %v", p)
		}
		p = buildPamGuacParams("password", "u", "", []byte("x"), nil, false, "/rec", "pam-1-2")
		if _, ok := p["recording-path"]; ok {
			t.Fatal("recording params set without recording enabled")
		}
	})

	t.Run("settings pass through but cannot override reserved keys", func(t *testing.T) {
		settings := map[string]interface{}{
			"color-scheme":   "green-black", // legit protocol extra
			"security":       "nla",
			"password":       "attacker",   // must not shadow the injected credential
			"private-key":    "attacker",   // must not smuggle a key
			"username":       "attacker",   // must not swap identity
			"recording-path": "/tmp/exfil", // must not redirect recordings
			"ignore":         42,           // non-strings dropped
		}
		p := buildPamGuacParams("password", "realuser", "", []byte("realpass"), settings, true, "/rec", "n")
		if p["password"] != "realpass" || p["username"] != "realuser" || p["recording-path"] != "/rec" {
			t.Fatalf("reserved key overridden: %v", p)
		}
		if p["color-scheme"] != "green-black" || p["security"] != "nla" {
			t.Fatalf("legit settings dropped: %v", p)
		}
		if _, ok := p["private-key"]; ok {
			t.Fatal("settings smuggled a private-key")
		}
		if _, ok := p["ignore"]; ok {
			t.Fatal("non-string setting passed through")
		}
	})

	t.Run("RemoteApp forces disable-gfx and settings cannot re-enable it", func(t *testing.T) {
		// A RemoteApp launch (remote-app set) must run with GFX off
		// (GUACAMOLE-2123: RemoteApp windows stay blank with GFX on).
		settings := map[string]interface{}{
			"remote-app":  "||SSMS",
			"disable-gfx": "false", // attacker/typo trying to re-enable GFX
		}
		p := buildPamGuacParams("password", "u", "", []byte("x"), settings, false, "", "")
		if p["disable-gfx"] != "true" {
			t.Fatalf("RemoteApp must force disable-gfx=true, got %q", p["disable-gfx"])
		}
		if p["remote-app"] != "||SSMS" {
			t.Fatalf("remote-app should pass through: %v", p)
		}
	})

	t.Run("non-RemoteApp RDP keeps GFX (no disable-gfx forced)", func(t *testing.T) {
		p := buildPamGuacParams("password", "u", "", []byte("x"), nil, false, "", "")
		if _, ok := p["disable-gfx"]; ok {
			t.Fatalf("full-desktop RDP should not force disable-gfx: %v", p)
		}
	})
}

func TestValidateRemoteAppArgs(t *testing.T) {
	t.Parallel()

	ok := []string{
		"",
		"   ",
		"-E",                       // SSMS integrated auth — the correct pattern
		"-S sql01.corp.local -E",   // host + integrated auth
		"--nowelcome",              // ordinary flags
		"/log C:\\logs\\app.log",   // a path arg
		"-server tcp:db01,1433 -E", // no secret
	}
	for _, a := range ok {
		if err := validateRemoteAppArgs(a); err != nil {
			t.Errorf("expected %q to be allowed, got %v", a, err)
		}
	}

	bad := []string{
		"-P hunter2",
		"-p hunter2",
		"--password hunter2",
		"--pass=hunter2",
		"/password:hunter2",
		"/pass hunter2",
		"-U sa -P hunter2",
		"password=hunter2",
		"PWD=hunter2",
		"-S db;PWD=secret",
	}
	for _, a := range bad {
		if err := validateRemoteAppArgs(a); err == nil {
			t.Errorf("expected %q to be rejected as a secret", a)
		}
	}
}

// The session ledger DTO must expose availability only — never the on-disk
// recording path (same contract as the guacamole session history DTO).
func TestPamEntrySessionHidesRecordingPath(t *testing.T) {
	t.Parallel()

	if got := jsonFields(t, PamEntrySession{}); !got["recording_available"] || got["recording_path"] {
		t.Fatalf("PamEntrySession fields wrong: %v", got)
	}
}

// jsonFields marshals v and reports which JSON keys exist.
func jsonFields(t *testing.T, v interface{}) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := map[string]interface{}{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for k := range m {
		out[k] = true
	}
	return out
}
