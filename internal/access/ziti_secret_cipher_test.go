package access

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/migrations"
)

// The password below is a literal in a test; it is never a real credential.
const zitiTestPassword = "sup3r-s3cret-ziti-admin-pw"

// TestZitiSecretCipherAuthenticatesLegacyValuesInsteadOfPassingThemThrough is
// the reason zitiSecretCipher exists at all.
//
// secretcrypt.Decrypt returns an untagged value unchanged, by design, so a
// column still mid-rollout yields its plaintext. A pre-v124 Ziti password is
// untagged *ciphertext*, not plaintext, so routing it straight at secretcrypt
// returns the base64 blob and calls it the password — silently. This asserts
// the adapter opens it instead, and that what comes back is the password rather
// than the stored bytes.
func TestZitiSecretCipherAuthenticatesLegacyValuesInsteadOfPassingThemThrough(t *testing.T) {
	legacy, err := newSecretCipher(testKey)
	if err != nil {
		t.Fatalf("newSecretCipher: %v", err)
	}
	stored, err := legacy.Encrypt(zitiTestPassword)
	if err != nil {
		t.Fatalf("legacy encrypt: %v", err)
	}

	c, err := newZitiSecretCipher(testKey)
	if err != nil {
		t.Fatalf("newZitiSecretCipher: %v", err)
	}
	got, err := c.Decrypt(stored)
	if err != nil {
		t.Fatalf("decrypt of legacy value: %v", err)
	}
	if got == stored {
		t.Fatalf("legacy ciphertext was passed through unchanged — the stored blob would have been sent to the controller as the password")
	}
	if got != zitiTestPassword {
		t.Fatalf("legacy value decrypted to %q, want %q", got, zitiTestPassword)
	}

	// Guard the premise: bare secretcrypt really does wave this value through,
	// so the dispatch above is load-bearing and not defensive decoration.
	bare, err := secretcrypt.New(testKey)
	if err != nil {
		t.Fatalf("secretcrypt.New: %v", err)
	}
	waved, err := bare.Decrypt(stored)
	if err != nil {
		t.Fatalf("expected silent passthrough from bare secretcrypt, got error: %v", err)
	}
	if waved != stored {
		t.Fatalf("premise changed: bare secretcrypt no longer passes untagged values through (got %q)", waved)
	}
}

// TestZitiSecretCipherWritesTaggedValues pins the write side: an untagged write
// would recreate the exact ambiguity v124 removes, and would keep the password
// invisible to the rekey tool.
func TestZitiSecretCipherWritesTaggedValues(t *testing.T) {
	c, err := newZitiSecretCipher(testKey)
	if err != nil {
		t.Fatalf("newZitiSecretCipher: %v", err)
	}
	stored, err := c.Encrypt(zitiTestPassword)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !secretcrypt.IsEncrypted(stored) {
		t.Fatalf("stored value %q carries no secretcrypt tag", stored)
	}
	if strings.Contains(stored, zitiTestPassword) {
		t.Fatalf("stored value contains the plaintext password")
	}
	got, err := c.Decrypt(stored)
	if err != nil || got != zitiTestPassword {
		t.Fatalf("round trip: got %q, err %v", got, err)
	}
}

// TestZitiSecretCipherEmptyStaysEmpty — an unconfigured password must not
// become a decrypt error on every boot.
func TestZitiSecretCipherEmptyStaysEmpty(t *testing.T) {
	c, err := newZitiSecretCipher(testKey)
	if err != nil {
		t.Fatalf("newZitiSecretCipher: %v", err)
	}
	if got, err := c.Decrypt(""); err != nil || got != "" {
		t.Fatalf("empty decrypt: got %q, err %v", got, err)
	}
	if got, err := c.Encrypt(""); err != nil || got != "" {
		t.Fatalf("empty encrypt: got %q, err %v", got, err)
	}
}

// TestZitiSecretCipherKeyringModeSealsEncv2AndStillReadsLegacy covers the point
// of the move: with a KEK ring configured the Ziti password now rotates like
// every other secret column, while values written before v124 keep opening.
func TestZitiSecretCipherKeyringModeSealsEncv2AndStillReadsLegacy(t *testing.T) {
	legacy, err := newSecretCipher(testKey)
	if err != nil {
		t.Fatalf("newSecretCipher: %v", err)
	}
	legacyStored, err := legacy.Encrypt(zitiTestPassword)
	if err != nil {
		t.Fatalf("legacy encrypt: %v", err)
	}

	kek := []byte("ffffffffffffffffffffffffffffffff")
	t.Setenv("ENCRYPTION_KEYS", "7:"+base64.StdEncoding.EncodeToString(kek))
	t.Setenv("ENCRYPTION_ACTIVE_KEK_ID", "7")

	c, err := newZitiSecretCipher(testKey)
	if err != nil {
		t.Fatalf("newZitiSecretCipher (keyring): %v", err)
	}

	fresh, err := c.Encrypt(zitiTestPassword)
	if err != nil {
		t.Fatalf("keyring encrypt: %v", err)
	}
	if !strings.HasPrefix(fresh, "encv2:7:") {
		t.Fatalf("keyring write %q is not sealed under the active KEK", fresh)
	}
	if got, err := c.Decrypt(fresh); err != nil || got != zitiTestPassword {
		t.Fatalf("keyring round trip: got %q, err %v", got, err)
	}

	// The pre-v124 value is not sealed under any KEK; it must still open.
	if got, err := c.Decrypt(legacyStored); err != nil || got != zitiTestPassword {
		t.Fatalf("legacy value under keyring mode: got %q, err %v", got, err)
	}
}

// TestZitiAdminPasswordRetagMigration exercises migration v124 end to end
// against real PostgreSQL: a legacy row is written in the pre-v124 format, the
// registered migration runs, and the new reader must recover the original
// password. It pulls the SQL from the migration registry rather than restating
// it, so an edit to the migration is what this test checks.
func TestZitiAdminPasswordRetagMigration(t *testing.T) {
	db, cleanup := setupTestDB(t) // skips if testcontainers unavailable
	defer cleanup()
	ctx := context.Background()

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS system_settings (
		    key        VARCHAR(255) PRIMARY KEY,
		    value      JSONB NOT NULL,
		    updated_at TIMESTAMPTZ DEFAULT NOW(),
		    updated_by UUID
		)`); err != nil {
		t.Fatalf("create system_settings: %v", err)
	}

	up, down := zitiRetagMigrationSQL(t)

	legacy, err := newSecretCipher(testKey)
	if err != nil {
		t.Fatalf("newSecretCipher: %v", err)
	}
	legacyStored, err := legacy.Encrypt(zitiTestPassword)
	if err != nil {
		t.Fatalf("legacy encrypt: %v", err)
	}

	seed := func(t *testing.T, enc string) {
		t.Helper()
		blob, _ := json.Marshal(ZitiConnSettings{
			Enabled:          true,
			ControllerURL:    "https://ziti.example.test:1280",
			AdminUser:        "admin",
			AdminPasswordEnc: enc,
		})
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO system_settings (key, value) VALUES ('ziti_connection', $1)
			 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, blob); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	storedEnc := func(t *testing.T) string {
		t.Helper()
		var raw []byte
		if err := db.Pool.QueryRow(ctx,
			`SELECT value FROM system_settings WHERE key = 'ziti_connection'`).Scan(&raw); err != nil {
			t.Fatalf("read back: %v", err)
		}
		var s ZitiConnSettings
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return s.AdminPasswordEnc
	}

	c, err := newZitiSecretCipher(testKey)
	if err != nil {
		t.Fatalf("newZitiSecretCipher: %v", err)
	}

	t.Run("legacy value is tagged and still decrypts", func(t *testing.T) {
		seed(t, legacyStored)
		if _, err := db.Pool.Exec(ctx, up); err != nil {
			t.Fatalf("migration up: %v", err)
		}
		got := storedEnc(t)
		if !strings.HasPrefix(got, "encv1:") {
			t.Fatalf("stored value %q was not tagged", got)
		}
		if got != "encv1:"+legacyStored {
			t.Fatalf("migration altered the ciphertext bytes; want a pure re-tag")
		}
		pw, err := c.Decrypt(got)
		if err != nil {
			t.Fatalf("decrypt after migration: %v", err)
		}
		if pw != zitiTestPassword {
			t.Fatalf("after migration the password is %q, want %q", pw, zitiTestPassword)
		}
	})

	t.Run("re-running is a no-op", func(t *testing.T) {
		before := storedEnc(t)
		if _, err := db.Pool.Exec(ctx, up); err != nil {
			t.Fatalf("migration up (second run): %v", err)
		}
		if after := storedEnc(t); after != before {
			t.Fatalf("second run changed the value: %q -> %q", before, after)
		}
	})

	t.Run("down restores the pre-migration bytes", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, down); err != nil {
			t.Fatalf("migration down: %v", err)
		}
		if got := storedEnc(t); got != legacyStored {
			t.Fatalf("down left %q, want the original %q", got, legacyStored)
		}
	})

	t.Run("a value already sealed under a KEK is left alone", func(t *testing.T) {
		// encv2 rows post-date the migration; re-tagging one would corrupt it.
		const encv2 = "encv2:7:Zm9vYmFyYmF6cXV1eA=="
		seed(t, encv2)
		if _, err := db.Pool.Exec(ctx, up); err != nil {
			t.Fatalf("migration up: %v", err)
		}
		if got := storedEnc(t); got != encv2 {
			t.Fatalf("encv2 value was rewritten: %q", got)
		}
	})

	t.Run("an unset password is left alone", func(t *testing.T) {
		seed(t, "")
		if _, err := db.Pool.Exec(ctx, up); err != nil {
			t.Fatalf("migration up: %v", err)
		}
		if got := storedEnc(t); got != "" {
			t.Fatalf("empty password became %q", got)
		}
	})
}

// zitiRetagMigrationSQL returns v124's up/down SQL from the migration registry,
// so the test runs the statements that actually ship.
func zitiRetagMigrationSQL(t *testing.T) (string, string) {
	t.Helper()
	m := migrations.NewMigrator(nil, zap.NewNop())
	list, err := m.LoadMigrations()
	if err != nil {
		t.Fatalf("LoadMigrations: %v", err)
	}
	for _, mig := range list {
		if mig.Version == 124 {
			return mig.UpSQL, mig.DownSQL
		}
	}
	t.Fatalf("migration v124 not found in the registry")
	return "", ""
}
