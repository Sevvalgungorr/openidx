package selfheal

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestModeRoundTripAndValidation(t *testing.T) {
	s := New(t.TempDir())

	// Absent MODE → safe default.
	if m, err := s.Mode(); err != nil || m != "observe" {
		t.Fatalf("default Mode = %q, %v", m, err)
	}
	// Valid set round-trips.
	if err := s.SetMode("tier0"); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.Mode(); m != "tier0" {
		t.Fatalf("Mode after SetMode(tier0) = %q", m)
	}
	// Invalid is rejected and does not corrupt the stored value.
	if err := s.SetMode("bogus"); err == nil {
		t.Fatal("SetMode(bogus) should error")
	}
	if m, _ := s.Mode(); m != "tier0" {
		t.Fatalf("Mode unchanged after bad set = %q", m)
	}
}

func TestKillSwitch(t *testing.T) {
	s := New(t.TempDir())
	if on, _ := s.KillSwitch(); on {
		t.Fatal("kill-switch should start off")
	}
	if err := s.SetKillSwitch(true); err != nil {
		t.Fatal(err)
	}
	if on, _ := s.KillSwitch(); !on {
		t.Fatal("kill-switch should be on")
	}
	if err := s.SetKillSwitch(false); err != nil {
		t.Fatal(err)
	}
	if on, _ := s.KillSwitch(); on {
		t.Fatal("kill-switch should be off")
	}
	// Removing an already-absent DISABLE is not an error (idempotent).
	if err := s.SetKillSwitch(false); err != nil {
		t.Fatalf("idempotent off: %v", err)
	}
}

func TestFindingsParseFilterAndBadLines(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "ledger.jsonl", `{"fingerprint":"ops:x","class":"ops","severity":"high","status":"open","last_seen":"2026-08-20T10:00:00Z"}
not json, must be skipped
{"fingerprint":"bug:y","class":"bug","severity":"warn","status":"open","last_seen":"2026-08-20T12:00:00Z"}
`)
	s := New(dir)

	all, err := s.Findings(FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("want 2 findings (bad line skipped), got %d", len(all))
	}
	// Newest last_seen first.
	if all[0].Fingerprint != "bug:y" {
		t.Fatalf("want newest-first, got %s", all[0].Fingerprint)
	}
	// Filter by class.
	ops, _ := s.Findings(FindingFilter{Class: "ops"})
	if len(ops) != 1 || ops[0].Fingerprint != "ops:x" {
		t.Fatalf("class filter wrong: %+v", ops)
	}
}

func TestMissingFilesAreEmptyNotError(t *testing.T) {
	s := New(t.TempDir())
	if _, stale, err := s.Status(); err != nil || !stale {
		t.Fatalf("missing latest.json: stale=%v err=%v", stale, err)
	}
	if f, err := s.Findings(FindingFilter{}); err != nil || len(f) != 0 {
		t.Fatalf("missing ledger: %v %v", f, err)
	}
	if h, err := s.History(0); err != nil || len(h) != 0 {
		t.Fatalf("missing actions: %v %v", h, err)
	}
}

func TestHistoryNewestFirstAndLimit(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "actions.jsonl", `{"ts":"1","fingerprint":"a","action":"restart_unit","result":"recovered"}
{"ts":"2","fingerprint":"a","action":"restart_unit","result":"still-bad"}
{"ts":"3","fingerprint":"b","action":"restart_nginx","result":"halted"}
`)
	s := New(dir)
	h, err := s.History(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 2 {
		t.Fatalf("limit not applied: %d", len(h))
	}
	if h[0].TS != "3" || h[1].TS != "2" {
		t.Fatalf("want newest-first, got %s,%s", h[0].TS, h[1].TS)
	}
}
