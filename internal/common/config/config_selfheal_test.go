package config

import "testing"

// The self-heal panel reads/writes state from SelfHealStateDir; if the env
// binding is missing the admin-api silently uses the default and the panel
// points at the wrong (empty) dir. Verify both the default and the override.
func TestSelfHealDirsEnvBinding(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")

	cfg, err := Load("test")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SelfHealStateDir != "/home/cmit/oidx-runtime/selfheal" {
		t.Fatalf("default SelfHealStateDir = %q", cfg.SelfHealStateDir)
	}
	if cfg.SelfHealScriptsDir != "scripts/selfheal" {
		t.Fatalf("default SelfHealScriptsDir = %q", cfg.SelfHealScriptsDir)
	}

	t.Setenv("SELFHEAL_STATE_DIR", "/tmp/sh-state")
	t.Setenv("SELFHEAL_SCRIPTS_DIR", "/tmp/sh-scripts")
	cfg, err = Load("test")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SelfHealStateDir != "/tmp/sh-state" {
		t.Fatalf("SELFHEAL_STATE_DIR not bound: %q", cfg.SelfHealStateDir)
	}
	if cfg.SelfHealScriptsDir != "/tmp/sh-scripts" {
		t.Fatalf("SELFHEAL_SCRIPTS_DIR not bound: %q", cfg.SelfHealScriptsDir)
	}
}
