package access

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
	"testing"
)

// This encrypter had no tests at all while it lived in internal/mfa — the one
// piece of that package with a production caller was the piece nobody covered.
// It guards the Ziti controller's admin password, so the properties below are
// what stand between a stored blob and a plaintext credential.

const testKey = "0123456789abcdef0123456789abcdef" // exactly 32 bytes

func TestSecretCipherRoundTrip(t *testing.T) {
	c, err := newSecretCipher(testKey)
	if err != nil {
		t.Fatalf("newSecretCipher: %v", err)
	}

	for _, plaintext := range []string{
		"hunter2",
		"",
		"a password with spaces and $ymbol$",
		strings.Repeat("long", 500),
		"ünïcödé パスワード",
	} {
		ct, err := c.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", plaintext, err)
		}
		got, err := c.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if got != plaintext {
			t.Errorf("round trip = %q, want %q", got, plaintext)
		}
	}
}

func TestSecretCipherNeverEmitsPlaintext(t *testing.T) {
	c, _ := newSecretCipher(testKey)
	const secret = "s3cr3t-admin-password"

	ct, err := c.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if strings.Contains(ct, secret) {
		t.Fatal("the ciphertext contains the plaintext")
	}
	raw, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatalf("output is not base64: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Error("the decoded ciphertext contains the plaintext")
	}
}

func TestSecretCipherNonceIsPerCall(t *testing.T) {
	// A fixed nonce under a fixed key is a catastrophic GCM misuse — it leaks
	// the XOR of plaintexts and destroys authentication. Encrypting the same
	// value twice must not produce the same bytes.
	c, _ := newSecretCipher(testKey)

	first, err := c.Encrypt("same-password")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	second, err := c.Encrypt("same-password")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if first == second {
		t.Error("two encryptions of the same plaintext are identical; the nonce is not per-call")
	}
}

func TestSecretCipherRejectsTamperedCiphertext(t *testing.T) {
	// GCM authenticates. A modified blob must error, not decrypt to something
	// plausible — otherwise anyone with write access to system_settings could
	// steer the controller password.
	c, _ := newSecretCipher(testKey)

	ct, err := c.Encrypt("hunter2")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw[len(raw)-1] ^= 0xff // flip a bit in the auth tag
	if _, err := c.Decrypt(base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Error("a tampered ciphertext decrypted without error")
	}
}

func TestSecretCipherRejectsWrongKey(t *testing.T) {
	enc, _ := newSecretCipher(testKey)
	ct, err := enc.Encrypt("hunter2")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	other, _ := newSecretCipher("ffffffffffffffffffffffffffffffff")
	if got, err := other.Decrypt(ct); err == nil {
		t.Errorf("decrypted under the wrong key to %q; must fail closed", got)
	}
}

func TestSecretCipherRejectsMalformedInput(t *testing.T) {
	c, _ := newSecretCipher(testKey)

	tests := []struct {
		name  string
		input string
	}{
		{"not base64", "!!!not-base64!!!"},
		{"empty", ""},
		{"shorter than the nonce", base64.StdEncoding.EncodeToString([]byte("short"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := c.Decrypt(tt.input); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestNewSecretCipherRequiresA32ByteKey(t *testing.T) {
	// A short key must be refused rather than padded or hashed into one:
	// silently accepting it would mean a weaker key than the name promises.
	for _, key := range []string{"", "short", strings.Repeat("x", 31), strings.Repeat("x", 33)} {
		if _, err := newSecretCipher(key); err == nil {
			t.Errorf("accepted a %d-byte key", len(key))
		}
	}
	if _, err := newSecretCipher(testKey); err != nil {
		t.Errorf("rejected a valid 32-byte key: %v", err)
	}
}

func TestSecretCipherDecryptsTheLegacyMFAFormat(t *testing.T) {
	// The stored format must not change with the move out of internal/mfa, or
	// every Ziti password already in system_settings becomes unreadable.
	//
	// This builds a ciphertext the way the deleted mfa.AES256GCMEncrypter did —
	// raw AES-256-GCM, nonce prepended, base64 std encoding, no tag or prefix —
	// and requires the relocated cipher to read it.
	block, err := aes.NewCipher([]byte(testKey))
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize()) // deterministic zero nonce, test-only
	legacy := base64.StdEncoding.EncodeToString(
		gcm.Seal(nonce, nonce, []byte("legacy-ziti-password"), nil))

	c, _ := newSecretCipher(testKey)
	got, err := c.Decrypt(legacy)
	if err != nil {
		t.Fatalf("failed to decrypt a value written by the previous implementation: %v", err)
	}
	if got != "legacy-ziti-password" {
		t.Errorf("legacy decrypt = %q, want legacy-ziti-password", got)
	}
}
