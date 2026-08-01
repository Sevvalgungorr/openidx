package access

import "testing"

// placeApp is the GUACAMOLE-1951 placement contract: pick a host with capacity
// that isn't already running this user's session; otherwise return a resolvable
// conflict rather than silently killing a session.
func TestPlaceApp(t *testing.T) {
	t.Run("picks the first host with free capacity", func(t *testing.T) {
		hosts := []candidateHost{
			{HostEntryID: "h1", HostName: "RDS01", MaxSessions: 2, ActiveSessions: 2}, // full
			{HostEntryID: "h2", HostName: "RDS02", MaxSessions: 2, ActiveSessions: 1}, // free
		}
		chosen, conflict := placeApp(hosts)
		if conflict != nil || chosen == nil || chosen.HostEntryID != "h2" {
			t.Fatalf("expected h2, got chosen=%v conflict=%v", chosen, conflict)
		}
	})

	t.Run("skips a host where the user already has a session", func(t *testing.T) {
		// h1 has free capacity but the user already runs a session there —
		// launching would kill it, so placement must skip to h2.
		hosts := []candidateHost{
			{HostEntryID: "h1", HostName: "RDS01", MaxSessions: 2, ActiveSessions: 1, UserSessionID: "s1", UserAppName: "Notepad"},
			{HostEntryID: "h2", HostName: "RDS02", MaxSessions: 2, ActiveSessions: 0},
		}
		chosen, conflict := placeApp(hosts)
		if conflict != nil || chosen == nil || chosen.HostEntryID != "h2" {
			t.Fatalf("expected h2, got chosen=%v conflict=%v", chosen, conflict)
		}
	})

	t.Run("no capacity anywhere → no_capacity conflict", func(t *testing.T) {
		hosts := []candidateHost{
			{HostEntryID: "h1", HostName: "RDS01", MaxSessions: 1, ActiveSessions: 1},
			{HostEntryID: "h2", HostName: "RDS02", MaxSessions: 2, ActiveSessions: 2},
		}
		chosen, conflict := placeApp(hosts)
		if chosen != nil || conflict == nil || conflict.Reason != "no_capacity" {
			t.Fatalf("expected no_capacity conflict, got chosen=%v conflict=%v", chosen, conflict)
		}
		if len(conflict.Conflicts) != 0 {
			t.Fatalf("no_capacity should not list sessions to disconnect: %+v", conflict.Conflicts)
		}
	})

	t.Run("only the user's own occupied host has room → user_session_conflict lists it", func(t *testing.T) {
		hosts := []candidateHost{
			{HostEntryID: "h1", HostName: "RDS01", MaxSessions: 2, ActiveSessions: 1, UserSessionID: "s9", UserAppName: "SSMS"},
		}
		chosen, conflict := placeApp(hosts)
		if chosen != nil || conflict == nil || conflict.Reason != "user_session_conflict" {
			t.Fatalf("expected user_session_conflict, got chosen=%v conflict=%v", chosen, conflict)
		}
		if len(conflict.Conflicts) != 1 || conflict.Conflicts[0].SessionID != "s9" || conflict.Conflicts[0].AppName != "SSMS" {
			t.Fatalf("conflict should surface the blocking session: %+v", conflict.Conflicts)
		}
	})

	t.Run("prefers a free host over the user's occupied one (order preserved by caller)", func(t *testing.T) {
		// Caller orders least-loaded first; a free host ahead of the user's
		// occupied host must win without reporting a conflict.
		hosts := []candidateHost{
			{HostEntryID: "h2", HostName: "RDS02", MaxSessions: 2, ActiveSessions: 0},
			{HostEntryID: "h1", HostName: "RDS01", MaxSessions: 2, ActiveSessions: 1, UserSessionID: "s1"},
		}
		chosen, conflict := placeApp(hosts)
		if conflict != nil || chosen == nil || chosen.HostEntryID != "h2" {
			t.Fatalf("expected h2, got chosen=%v conflict=%v", chosen, conflict)
		}
	})
}

func TestWindowsAppInputValidate(t *testing.T) {
	t.Run("strips || prefix and requires a single target", func(t *testing.T) {
		in := windowsAppInput{Alias: "||SSMS", DisplayName: "SSMS", HostEntryID: "h1"}
		if err := in.validate(); err != nil {
			t.Fatalf("valid input rejected: %v", err)
		}
		if in.Alias != "SSMS" {
			t.Fatalf("alias should be stripped of ||, got %q", in.Alias)
		}
	})

	t.Run("rejects both host and pool", func(t *testing.T) {
		in := windowsAppInput{Alias: "SSMS", DisplayName: "SSMS", HostEntryID: "h1", PoolID: "p1"}
		if err := in.validate(); err == nil {
			t.Fatal("an app targeting both a host and a pool must be rejected")
		}
	})

	t.Run("rejects neither host nor pool", func(t *testing.T) {
		in := windowsAppInput{Alias: "SSMS", DisplayName: "SSMS"}
		if err := in.validate(); err == nil {
			t.Fatal("an app with no target must be rejected")
		}
	})

	t.Run("rejects a secret in args", func(t *testing.T) {
		in := windowsAppInput{Alias: "SSMS", DisplayName: "SSMS", HostEntryID: "h1", Args: "-U sa -P hunter2"}
		if err := in.validate(); err == nil {
			t.Fatal("secret-looking args must be rejected")
		}
	})
}

func TestIsPNG(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0}
	if !isPNG(png) {
		t.Fatal("valid PNG header not recognized")
	}
	if isPNG([]byte("GIF89a")) {
		t.Fatal("non-PNG accepted")
	}
	if isPNG([]byte{0x89}) {
		t.Fatal("truncated header accepted")
	}
}
