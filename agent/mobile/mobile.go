// Package mobile is the gomobile-bind surface for the OpenIDX engine.
//
// It exposes package-level functions with gomobile-safe signatures (only
// string/error crossing the boundary; rich data is JSON) that wrap a singleton
// *control.Engine, so the Flutter mobile app drives the SAME engine core as the
// desktop client — critically, the real Go OpenZiti dial (ZitiDial), which the
// prior Swift/Kotlin scaffold in mobile/modules/ziti never finished.
//
// Build the bindings (runs in CI / on a dev box; needs the gomobile tool):
//
//	gomobile bind -target=ios     -o Engine.xcframework ./agent/mobile
//	gomobile bind -target=android -o engine.aar         ./agent/mobile
//
// The Flutter engine plugin (client/plugins/engine, Phase 2b) calls these over a
// platform channel / FFI — the mobile analogue of the desktop control socket.
package mobile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/openidx/openidx/agent/internal/control"
)

var (
	mu      sync.Mutex
	engine  *control.Engine
	logPath string // <configDir>/control.log, set on Start; read by Logs()
)

// newMobileLogger routes engine/control activity to BOTH stderr (which gomobile
// surfaces as Android logcat "GoLog" / the iOS console) and a control.log file
// in the app sandbox, so the in-app viewer (Logs) and `adb pull` can read it
// without a live logcat session. Replaces the no-op logger the scaffold used —
// which is why the client previously had no control logs at all.
func newMobileLogger(configDir string) *zap.Logger {
	logPath = filepath.Join(configDir, "control.log")
	encCfg := zap.NewProductionEncoderConfig()
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	enc := zapcore.NewConsoleEncoder(encCfg)

	cores := []zapcore.Core{
		zapcore.NewCore(enc, zapcore.AddSync(os.Stderr), zapcore.InfoLevel),
	}
	if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		cores = append(cores, zapcore.NewCore(enc, zapcore.AddSync(f), zapcore.InfoLevel))
	}
	return zap.New(zapcore.NewTee(cores...))
}

// Logs returns the tail (up to ~64 KiB) of the on-device control log so the app
// can show engine/control activity without adb. Empty when nothing is logged yet.
func Logs() (string, error) {
	mu.Lock()
	p := logPath
	mu.Unlock()
	if p == "" {
		return "", errNotStarted
	}
	f, err := os.Open(p) //nolint:gosec // path is <configDir>/control.log, app-owned
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()
	const maxTail = 64 * 1024
	if info, err := f.Stat(); err == nil && info.Size() > maxTail {
		if _, err := f.Seek(-maxTail, io.SeekEnd); err != nil {
			return "", err
		}
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// errNotStarted is returned by every call before Start has succeeded.
var errNotStarted = errors.New("openidx engine not started; call Start(configDir) first")

// Start initializes the engine against the app's per-app config directory (the
// mobile OS sandbox documents dir the host passes in). Idempotent — safe to call
// on every app launch; a second call with an already-started engine is a no-op.
func Start(configDir string) error {
	mu.Lock()
	defer mu.Unlock()
	if engine != nil {
		return nil
	}
	e, err := control.NewEngine(configDir, newMobileLogger(configDir))
	if err != nil {
		return err
	}
	engine = e
	return nil
}

func get() (*control.Engine, error) {
	mu.Lock()
	defer mu.Unlock()
	if engine == nil {
		return nil, errNotStarted
	}
	return engine, nil
}

// Status returns the engine status JSON (enrollment + login + ziti state).
func Status() (string, error) {
	e, err := get()
	if err != nil {
		return "", err
	}
	return e.Status()
}

// Login runs the engine's PKCE login. NOTE: on mobile the app normally
// authenticates natively (passkey / native login-init) at the Dart layer and
// imports the session; this desktop-style loopback login is exposed for parity
// but is not the primary mobile auth path.
func Login() (string, error) {
	e, err := get()
	if err != nil {
		return "", err
	}
	return e.Login()
}

// Logout clears the stored session.
func Logout() error {
	e, err := get()
	if err != nil {
		return err
	}
	return e.Logout()
}

// SetServer configures the target/enrollment server URL before Enroll. Mobile
// has no seeded config, so the app supplies it (from the enroll code's server,
// a deep-link, or manual entry).
func SetServer(url string) error {
	e, err := get()
	if err != nil {
		return err
	}
	return e.SetServer(url)
}

// Enroll onboards this device with a one-time enrollment code. Call SetServer
// first (mobile has no seeded server config).
func Enroll(code string) (string, error) {
	e, err := get()
	if err != nil {
		return "", err
	}
	return e.Enroll(code)
}

// Posture runs the device posture checks and returns the compliance summary JSON.
func Posture() (string, error) {
	e, err := get()
	if err != nil {
		return "", err
	}
	return e.Posture()
}

// PamList returns the PAM entries the user may launch, as a JSON array.
func PamList() (string, error) {
	e, err := get()
	if err != nil {
		return "", err
	}
	return e.PamList()
}

// PamConnect brokers a session for the entry and returns its connect URL.
func PamConnect(entryID string) (string, error) {
	e, err := get()
	if err != nil {
		return "", err
	}
	return e.PamConnect(entryID)
}

// PamRequest asks for access to an approval-gated entry.
func PamRequest(entryID, reason string) error {
	e, err := get()
	if err != nil {
		return err
	}
	return e.PamRequest(entryID, reason)
}

// ZitiDial opens the OpenZiti service over the overlay (in Go) and returns the
// loopback address the app connects to. This is what makes native overlay access
// real on iOS/Android.
func ZitiDial(service string) (string, error) {
	e, err := get()
	if err != nil {
		return "", err
	}
	return e.ZitiDial(service)
}

// ZitiClose tears down a previously-dialed service bridge.
func ZitiClose(service string) error {
	e, err := get()
	if err != nil {
		return err
	}
	return e.ZitiClose(service)
}
