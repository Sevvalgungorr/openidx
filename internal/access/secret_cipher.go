package access

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/openidx/openidx/internal/common/secretcrypt"
)

// AES-256-GCM for the stored Ziti controller admin password.
//
// This moved here from internal/mfa, which was deleted: that package had no
// production caller except this one symbol, so ~7k lines of unreachable MFA
// code existed to supply one encrypter. It lives next to its only consumer now
// rather than in a shared package, because one caller is not a library.
//
// As of migration v124 this type is the LEGACY READER only: new values are
// written through internal/common/secretcrypt by zitiSecretCipher below, so the
// Ziti password uses the same tagged format and the same KEK keyring as every
// other secret column. Encrypt is kept because reconstructing a pre-v124 value
// is exactly what the migration and its tests need.
//
// The wire format is preserved byte-for-byte so that passwords encrypted
// before that move keep decrypting.

// secretCipher encrypts a single secret with AES-256-GCM under a fixed key.
type secretCipher struct {
	key []byte
}

// newSecretCipher builds a cipher from a 32-byte (AES-256) key.
func newSecretCipher(key string) (*secretCipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes for AES-256, got %d bytes", len(key))
	}
	return &secretCipher{key: []byte(key)}, nil
}

// Encrypt returns base64(nonce || ciphertext). The nonce is random per call, so
// encrypting the same password twice yields different output — that is the
// point, and it is why callers must never compare ciphertexts for equality.
func (c *secretCipher) Encrypt(plaintext string) (string, error) {
	gcm, err := c.gcm()
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plaintext), nil)), nil
}

// Decrypt reverses Encrypt. GCM authenticates, so a tampered or
// wrong-key ciphertext is an error rather than garbage plaintext.
func (c *secretCipher) Decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	gcm, err := c.gcm()
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}
	return string(plaintext), nil
}

func (c *secretCipher) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return gcm, nil
}

// zitiSecretCipher stores the Ziti controller admin password through
// internal/common/secretcrypt while still reading the untagged values written
// before migration v124.
//
// Dispatching reads on the version tag is the whole point, not a courtesy.
// secretcrypt.Decrypt returns an *untagged* value unchanged by design, so that
// a column mid-rollout still yields its plaintext. Point that at a legacy Ziti
// ciphertext and it hands back the base64 blob as the password: no error, no
// log line, just a wrong secret posted to a controller login. So an untagged
// value is routed to the legacy opener, which authenticates it, rather than to
// secretcrypt, which would wave it through.
//
// Writes always go through secretcrypt, so a saved password is tagged (encv1,
// or encv2 under the active KEK when ENCRYPTION_KEYS is configured).
//
// The tag is also what makes this value reachable by rotation: cmd/rekey walks
// json/jsonb columns and re-seals any string carrying the prefix, so a password
// living inside system_settings.value is swept by a key retirement like any
// other secret column. An untagged write would silently drop back out of that
// sweep, which is the second reason writes never bypass secretcrypt.
type zitiSecretCipher struct {
	sc     *secretcrypt.Cipher
	legacy *secretCipher
}

// newZitiSecretCipher builds the cipher pair from the 32-byte encryption key.
// Both halves take the same key: the formats differ only by the tag, so the
// legacy reader and secretcrypt's encv1 reader are the same AES-256-GCM.
func newZitiSecretCipher(key string) (*zitiSecretCipher, error) {
	legacy, err := newSecretCipher(key)
	if err != nil {
		return nil, err
	}
	sc, err := secretcrypt.New(key)
	if err != nil {
		return nil, err
	}
	return &zitiSecretCipher{sc: sc, legacy: legacy}, nil
}

// Encrypt seals the password under secretcrypt, producing a tagged value.
func (c *zitiSecretCipher) Encrypt(plaintext string) (string, error) {
	return c.sc.Encrypt(plaintext)
}

// Decrypt reads either shape: tagged values via secretcrypt, untagged ones as
// pre-v124 legacy ciphertext.
func (c *zitiSecretCipher) Decrypt(stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if secretcrypt.IsEncrypted(stored) {
		return c.sc.Decrypt(stored)
	}
	return c.legacy.Decrypt(stored)
}
