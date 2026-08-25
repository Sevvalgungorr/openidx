package mobile

import (
	"reflect"
	"strings"
	"testing"
)

// Before Start, every accessor must fail cleanly rather than panic.
func TestNotStartedReturnsError(t *testing.T) {
	mu.Lock()
	engine = nil
	mu.Unlock()

	if _, err := Status(); err == nil {
		t.Fatal("Status before Start should error")
	}
	if err := Logout(); err == nil {
		t.Fatal("Logout before Start should error")
	}
}

// Start against a fresh (unenrolled) config dir must succeed and be idempotent,
// and Status must then return a non-empty JSON payload.
func TestStartAndStatus(t *testing.T) {
	mu.Lock()
	engine = nil
	mu.Unlock()

	dir := t.TempDir()
	if err := Start(dir); err != nil {
		t.Fatalf("Start: %v", err)
	}
	s, err := Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.Contains(s, "enrolled") {
		t.Fatalf("status JSON missing expected field: %q", s)
	}
	if err := Start(dir); err != nil {
		t.Fatalf("second Start (idempotent) should be nil: %v", err)
	}
}

// The whole point of this package is to be gomobile-bindable, so every exported
// binding function must use only gomobile-safe types (string / error) across the
// boundary. A non-conforming signature fails here instead of at `gomobile bind`.
func TestSignaturesAreGomobileSafe(t *testing.T) {
	fns := map[string]interface{}{
		"Start": Start, "SetServer": SetServer, "Status": Status, "Login": Login,
		"LoginStart": LoginStart, "LoginFinish": LoginFinish, "Logout": Logout,
		"Enroll": Enroll, "Posture": Posture, "PamList": PamList,
		"PamConnect": PamConnect, "PamRequest": PamRequest,
		"ZitiDial": ZitiDial, "ZitiClose": ZitiClose,
		"Logs": Logs,
	}
	errType := reflect.TypeOf((*error)(nil)).Elem()
	safe := func(tp reflect.Type) bool {
		return tp.Kind() == reflect.String || tp == errType
	}
	for name, fn := range fns {
		ft := reflect.TypeOf(fn)
		for i := 0; i < ft.NumIn(); i++ {
			if !safe(ft.In(i)) {
				t.Errorf("%s: param %d type %v is not gomobile-safe", name, i, ft.In(i))
			}
		}
		for i := 0; i < ft.NumOut(); i++ {
			if !safe(ft.Out(i)) {
				t.Errorf("%s: return %d type %v is not gomobile-safe", name, i, ft.Out(i))
			}
		}
	}
}
