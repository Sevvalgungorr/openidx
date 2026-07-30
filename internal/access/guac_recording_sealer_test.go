package access

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// makeTestRing builds an enabled single-key recording keyring for tests.
func makeTestRing(t *testing.T) *recordingKeyring {
	t.Helper()
	key := make([]byte, recordingMasterKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	ring, err := newRecordingKeyring("", 0, base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("newRecordingKeyring: %v", err)
	}
	if ring == nil || !ring.Enabled() {
		t.Fatal("expected an enabled keyring")
	}
	return ring
}

// TestSealOneGuacRecording_RoundTrip seals a plaintext recording and verifies
// (1) the returned SHA-256 matches the original bytes, (2) the on-disk file is
// no longer the plaintext, and (3) the decrypting reader reproduces the exact
// original bytes.
func TestSealOneGuacRecording_RoundTrip(t *testing.T) {
	root := t.TempDir()
	sessionDir := filepath.Join(root, "sess-123")
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	recPath := filepath.Join(sessionDir, "recording")

	// A payload larger than one seal chunk so multi-frame framing is exercised.
	plaintext := make([]byte, guacSealChunkBytes*2+12345)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recPath, plaintext, 0o644); err != nil {
		t.Fatal(err)
	}
	wantSum := sha256.Sum256(plaintext)

	ring := makeTestRing(t)
	h := &RemoteSupportHandler{
		logger:             zap.NewNop(),
		guacRecordingRing:  ring,
		guacRecordingsRoot: root,
	}

	sum, keyID, err := h.sealOneGuacRecording(recPath)
	if err != nil {
		t.Fatalf("sealOneGuacRecording: %v", err)
	}
	if sum != hex.EncodeToString(wantSum[:]) {
		t.Fatalf("sha256 mismatch: got %s want %s", sum, hex.EncodeToString(wantSum[:]))
	}
	if keyID != ring.ActiveID() {
		t.Fatalf("key id = %d, want %d", keyID, ring.ActiveID())
	}

	// On-disk bytes must now be ciphertext (not the plaintext prefix).
	onDisk, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(onDisk, plaintext[:64]) {
		t.Fatal("on-disk file still starts with plaintext — not sealed")
	}
	if len(onDisk) <= len(plaintext) {
		t.Fatalf("sealed file (%d) should be larger than plaintext (%d) due to framing", len(onDisk), len(plaintext))
	}

	// The temp file must be gone (atomic rename committed).
	if _, err := os.Stat(recPath + ".sealing"); !os.IsNotExist(err) {
		t.Fatal("temp .sealing file should not remain after a successful seal")
	}

	// Decrypt via the same reader the download handler uses.
	f, err := os.Open(recPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reader := newDecryptingReader(f, ring, guacRecordingSessionKey(recPath))
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decrypt read: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted bytes differ from original (got %d, want %d)", len(got), len(plaintext))
	}
}

// TestGuacRecordingPathSafe rejects traversal, root-equality, and empty paths
// while accepting a legitimate recording under the root.
func TestGuacRecordingPathSafe(t *testing.T) {
	root := t.TempDir()
	h := &RemoteSupportHandler{logger: zap.NewNop(), guacRecordingsRoot: root}

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"empty", "", false},
		{"root itself", root, false},
		{"legit under root", filepath.Join(root, "s1", "recording"), true},
		{"escape via ..", filepath.Join(root, "..", "etc", "passwd"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := h.guacRecordingPathSafe(c.path); got != c.want {
				t.Fatalf("guacRecordingPathSafe(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}

	// With no configured root, everything is rejected (fail-safe).
	h2 := &RemoteSupportHandler{logger: zap.NewNop()}
	if h2.guacRecordingPathSafe(filepath.Join(root, "x")) {
		t.Fatal("expected fail-safe rejection when no root configured")
	}
}

// TestGuacRecordingSessionKey is stable and distinguishes same-base files in
// different directories.
func TestGuacRecordingSessionKey(t *testing.T) {
	a := guacRecordingSessionKey("/rec/s1/recording")
	b := guacRecordingSessionKey("/rec/s2/recording")
	if a == b {
		t.Fatal("same-base files in different dirs must derive different keys")
	}
	if a != guacRecordingSessionKey("/rec/s1/recording") {
		t.Fatal("session key must be stable for the same path")
	}
}
