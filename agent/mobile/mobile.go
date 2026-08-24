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
	"sync"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/control"
)

var (
	mu     sync.Mutex
	engine *control.Engine
)

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
	e, err := control.NewEngine(configDir, zap.NewNop())
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

// Enroll onboards this device with a one-time enrollment code.
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
