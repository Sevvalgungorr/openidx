//go:build !windows

package updater

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSelectStrategy(t *testing.T) {
	cases := []struct {
		goos, artifact string
		want           updateStrategy
	}{
		{"darwin", "/tmp/OpenIDX-1.2.0.pkg", strategyMacPkg},
		{"darwin", "/tmp/OpenIDX-1.2.0", strategySelfReplace},
		{"darwin", "/tmp/OpenIDX.bin", strategySelfReplace},
		{"linux", "/tmp/openidx_1.2.0_amd64.deb", strategyDebPkg},
		{"linux", "/tmp/openidx-1.2.0.rpm", strategyRPMPkg},
		{"linux", "/tmp/OpenIDX-1.2.0.AppImage", strategySelfReplace},
		{"linux", "/tmp/openidx-agent", strategySelfReplace},
		{"linux", "/tmp/OpenIDX-1.2.0.MSI", strategySelfReplace}, // wrong-OS ext → still self-replace on linux
		{"freebsd", "/tmp/whatever", strategyUnsupported},
	}
	for _, c := range cases {
		if got := selectStrategy(c.goos, c.artifact); got != c.want {
			t.Errorf("selectStrategy(%q, %q) = %d, want %d", c.goos, c.artifact, got, c.want)
		}
	}
}

func TestAtomicReplaceExecutable(t *testing.T) {
	dir := t.TempDir()

	dst := filepath.Join(dir, "openidx-agent")
	if err := os.WriteFile(dst, []byte("OLD-BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "download")
	if err := os.WriteFile(src, []byte("NEW-BINARY-v2"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := atomicReplaceExecutable(src, dst); err != nil {
		t.Fatalf("atomicReplaceExecutable: %v", err)
	}

	// dst now has the new content and is executable.
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "NEW-BINARY-v2" {
		t.Errorf("dst content = %q, want NEW-BINARY-v2", got)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("dst mode %v is not executable", info.Mode().Perm())
	}

	// The previous binary is preserved as a .bak for rollback.
	bak, err := os.ReadFile(dst + ".bak")
	if err != nil {
		t.Fatalf("expected rollback .bak: %v", err)
	}
	if string(bak) != "OLD-BINARY" {
		t.Errorf(".bak content = %q, want OLD-BINARY", bak)
	}

	// No stray temp files left in the target directory.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == "" && len(e.Name()) > 10 && e.Name()[0] == '.' {
			t.Errorf("stray temp file left behind: %s", e.Name())
		}
	}
}

func TestAtomicReplaceExecutable_MissingSource(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "openidx-agent")
	if err := os.WriteFile(dst, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := atomicReplaceExecutable(filepath.Join(dir, "nonexistent"), dst); err == nil {
		t.Fatal("expected error when source is missing")
	}
	// dst must be untouched when the source can't be opened.
	got, _ := os.ReadFile(dst)
	if string(got) != "OLD" {
		t.Errorf("dst mutated on failure: %q", got)
	}
}
