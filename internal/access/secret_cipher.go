package access

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// AES-256-GCM for the stored Ziti controller admin password.
//
// This moved here from internal/mfa, which was deleted: that package had no
// production caller except this one symbol, so ~7k lines of unreachable MFA
// code existed to supply one encrypter. It lives next to its only consumer now
// rather than in a shared package, because one caller is not a library.
//
// It is deliberately NOT internal/common/secretcrypt, which is the better
// facility (KEK keyring, rotation, noop mode) and would otherwise be the
// obvious home. The formats are incompatible in a way that fails silently:
// this encrypter writes an untagged base64(nonce||ciphertext), while
// secretcrypt tags its output ("encv1:"/"encv2:<id>:") and, by design, passes
// an *untagged* value through Decrypt unchanged so that plaintext survives a
// rollout. Feeding an already-encrypted Ziti password to secretcrypt would
// therefore return the base64 blob as if it were the password — no error, just
// a wrong secret handed to a controller login. Migrating to secretcrypt means
// re-encrypting the stored value under a tagged format first; that is a data
// migration, not a refactor, and is left as follow-up.
//
// The wire format is preserved byte-for-byte so that passwords encrypted
// before this move keep decrypting.

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
