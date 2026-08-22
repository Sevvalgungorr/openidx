// Package selfheal is a thin, dependency-free reader/writer over the on-disk
// state the self-heal loop scripts produce (see scripts/selfheal/). The admin
// console control panel uses it to view findings/history and to drive the mode
// + kill-switch. Keeping it free of gin/DB makes it unit-testable against a
// temp dir and keeps the single source of truth on disk (the scripts and the
// panel read/write the same files).
package selfheal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Valid modes, matching sh_mode in scripts/selfheal/lib.sh.
var validModes = map[string]bool{"off": true, "observe": true, "tier0": true, "tier1": true}

// Finding is one ledger entry (fingerprint-deduped). Fields mirror the JSON the
// collectors emit plus the ledger's bookkeeping.
type Finding struct {
	Fingerprint     string          `json:"fingerprint"`
	Class           string          `json:"class"`
	Severity        string          `json:"severity"`
	Service         string          `json:"service"`
	Message         string          `json:"message"`
	Data            json.RawMessage `json:"data,omitempty"`
	SuggestedAction string          `json:"suggested_action,omitempty"`
	Count           int             `json:"count,omitempty"`
	FirstSeen       string          `json:"first_seen,omitempty"`
	LastSeen        string          `json:"last_seen,omitempty"`
	Status          string          `json:"status,omitempty"`
}

// Snapshot is the latest sweep result.
type Snapshot struct {
	TS       string    `json:"ts"`
	Findings []Finding `json:"findings"`
}

// Action is one remediation attempt outcome (from actions.jsonl).
type Action struct {
	TS          string `json:"ts"`
	Fingerprint string `json:"fingerprint"`
	Action      string `json:"action"`
	Result      string `json:"result"`
}

// State is the panel's top-level view: current control state + snapshot summary.
type State struct {
	Mode       string    `json:"mode"`
	KillSwitch bool      `json:"kill_switch"`
	Stale      bool      `json:"stale"`
	SnapshotTS string    `json:"snapshot_ts"`
	Findings   []Finding `json:"findings"`
}

// FindingFilter narrows Findings(); empty fields match everything.
type FindingFilter struct{ Class, Severity, Status string }

// Store is rooted at the self-heal state dir.
type Store struct{ Dir string }

func New(dir string) *Store { return &Store{Dir: dir} }

func (s *Store) path(name string) string { return filepath.Join(s.Dir, name) }

// Status returns the latest snapshot. stale=true when latest.json is missing
// (the sweep has not run yet) — that is a normal empty state, not an error.
func (s *Store) Status() (Snapshot, bool, error) {
	var snap Snapshot
	b, err := os.ReadFile(s.path("latest.json"))
	if os.IsNotExist(err) {
		return snap, true, nil
	}
	if err != nil {
		return snap, false, err
	}
	if err := json.Unmarshal(b, &snap); err != nil {
		return snap, false, fmt.Errorf("parse latest.json: %w", err)
	}
	return snap, false, nil
}

// Findings reads the deduped ledger, newest-first by last_seen, applying the
// filter. A malformed line is skipped, not fatal (a partial write must not blind
// the whole panel).
func (s *Store) Findings(f FindingFilter) ([]Finding, error) {
	rows, err := readJSONL[Finding](s.path("ledger.jsonl"))
	if err != nil {
		return nil, err
	}
	out := rows[:0]
	for _, r := range rows {
		if f.Class != "" && r.Class != f.Class {
			continue
		}
		if f.Severity != "" && r.Severity != f.Severity {
			continue
		}
		if f.Status != "" && r.Status != f.Status {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastSeen > out[j].LastSeen })
	return out, nil
}

// History returns the most recent remediation actions, newest-first, capped at
// limit (0 = all).
func (s *Store) History(limit int) ([]Action, error) {
	rows, err := readJSONL[Action](s.path("actions.jsonl"))
	if err != nil {
		return nil, err
	}
	// actions.jsonl is append-order (oldest first); reverse for newest-first.
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

// Mode reads the MODE file; absent/blank/invalid → "observe" (the safe default,
// same fallback as the scripts).
func (s *Store) Mode() (string, error) {
	b, err := os.ReadFile(s.path("MODE"))
	if os.IsNotExist(err) {
		return "observe", nil
	}
	if err != nil {
		return "", err
	}
	m := strings.TrimSpace(string(b))
	if !validModes[m] {
		return "observe", nil
	}
	return m, nil
}

// SetMode writes the MODE file after validating the enum. An invalid mode is
// rejected so the panel can never wedge the loop into an unknown state.
func (s *Store) SetMode(m string) error {
	if !validModes[m] {
		return fmt.Errorf("invalid mode %q", m)
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.path("MODE"), []byte(m+"\n"), 0o644)
}

// KillSwitch reports whether the DISABLE file is present.
func (s *Store) KillSwitch() (bool, error) {
	_, err := os.Stat(s.path("DISABLE"))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// SetKillSwitch creates or removes the DISABLE file. Creating it halts ALL
// autonomy immediately (the remediator checks it every run).
func (s *Store) SetKillSwitch(on bool) error {
	if on {
		if err := os.MkdirAll(s.Dir, 0o755); err != nil {
			return err
		}
		return os.WriteFile(s.path("DISABLE"), []byte("disabled via admin console\n"), 0o644)
	}
	err := os.Remove(s.path("DISABLE"))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// ValidMode exposes the enum check for the handler layer.
func ValidMode(m string) bool { return validModes[m] }

// readJSONL parses a JSON-lines file into a slice, skipping blank/malformed
// lines. A missing file is an empty slice, not an error.
func readJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var v T
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			continue
		}
		out = append(out, v)
	}
	return out, sc.Err()
}
