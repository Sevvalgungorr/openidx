//go:build !windows

package updater

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// updateStrategy is how a downloaded artifact is installed on this platform.
type updateStrategy int

const (
	strategyUnsupported updateStrategy = iota
	strategySelfReplace                // artifact IS the new executable; swap in place + relaunch
	strategyMacPkg                     // macOS .pkg via `installer`
	strategyDebPkg                     // Debian .deb via `dpkg -i`
	strategyRPMPkg                     // RPM .rpm via `rpm -U`
)

// selectStrategy chooses the install strategy from the OS and artifact filename.
// Pure (no side effects) so it can be unit-tested across platforms.
func selectStrategy(goos, artifactPath string) updateStrategy {
	ext := strings.ToLower(filepath.Ext(artifactPath))
	switch goos {
	case "darwin":
		if ext == ".pkg" {
			return strategyMacPkg
		}
		return strategySelfReplace // bare binary
	case "linux":
		switch ext {
		case ".deb":
			return strategyDebPkg
		case ".rpm":
			return strategyRPMPkg
		default:
			return strategySelfReplace // .AppImage or bare binary
		}
	default:
		return strategyUnsupported
	}
}

// apply installs the downloaded artifact using the platform-appropriate strategy.
// For self-replace the running executable is swapped atomically and the process
// re-execs into the new binary (so it never returns on success); package
// strategies shell out to the OS installer (which may need privilege).
func apply(artifactPath string) error {
	switch selectStrategy(runtime.GOOS, artifactPath) {
	case strategySelfReplace:
		return applySelfReplace(artifactPath)
	case strategyMacPkg:
		return runInstaller("installer", "-pkg", artifactPath, "-target", "/")
	case strategyDebPkg:
		return runInstaller("dpkg", "-i", artifactPath)
	case strategyRPMPkg:
		return runInstaller("rpm", "-U", "--force", artifactPath)
	default:
		return fmt.Errorf("self-update is not supported on %s", runtime.GOOS)
	}
}

// runInstaller runs a system package installer, escalating with `sudo -n` when
// not already root (a LaunchDaemon/systemd service typically runs as root and
// skips the escalation).
func runInstaller(name string, args ...string) error {
	if os.Geteuid() != 0 {
		if _, err := exec.LookPath("sudo"); err == nil {
			args = append([]string{"-n", name}, args...)
			name = "sudo"
		}
	}
	cmd := exec.Command(name, args...) //nolint:gosec // installer name is a compile-time constant, artifact is checksum-verified
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s failed: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// applySelfReplace swaps the running executable with the freshly downloaded one
// (atomic rename within the same directory, keeping a .bak for rollback) and
// re-execs so the new code takes over immediately. If a supervisor
// (systemd/launchd) manages the process, a plain exit would also restart it into
// the new binary — but re-exec works whether or not it's supervised.
func applySelfReplace(artifactPath string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	if err := atomicReplaceExecutable(artifactPath, self); err != nil {
		return err
	}
	// Replace the process image with the new binary, preserving args + environment.
	return syscall.Exec(self, os.Args, os.Environ()) //nolint:gosec // self path from os.Executable, binary is checksum-verified
}

// atomicReplaceExecutable copies src over the file at dst atomically: it writes a
// temp file in dst's directory, makes it executable, moves the current dst aside
// to dst+".bak" (rollback), then renames the temp into place. Renames within one
// directory are atomic on POSIX, so a crash mid-update never leaves a truncated
// executable. Pure filesystem work, so it is unit-testable without a real update.
func atomicReplaceExecutable(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // src is our downloaded, checksum-verified artifact
	if err != nil {
		return fmt.Errorf("open new binary: %w", err)
	}
	defer in.Close()

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".openidx-update-*")
	if err != nil {
		return fmt.Errorf("create temp in target dir: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed into place

	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return fmt.Errorf("copy new binary: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync new binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close new binary: %w", err)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return fmt.Errorf("chmod new binary: %w", err)
	}

	// Keep the previous binary as a .bak for rollback, then move the new one in.
	_ = os.Remove(dst + ".bak")
	if err := os.Rename(dst, dst+".bak"); err != nil {
		return fmt.Errorf("back up current binary: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Rename(dst+".bak", dst) // best-effort rollback
		return fmt.Errorf("install new binary: %w", err)
	}
	return nil
}
