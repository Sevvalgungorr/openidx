package signingkeys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/common/testsupport"
	"github.com/openidx/openidx/internal/migrations"
)

// 32 bytes → real AES-256 cipher, so the test proves encryption at rest.
const testEncryptionKey = "0123456789abcdef0123456789abcdef"

func setupTestDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(30 * time.Second),
	}
	container := testsupport.RunOrSkip(t, req.Image, func() (testcontainers.Container, error) {
		return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
	})
	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container host: %v", err)
		return nil, func() {}
	}
	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container port: %v", err)
		return nil, func() {}
	}
	db, err := database.NewPostgres("postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to connect to test database: %v", err)
		return nil, func() {}
	}
	return db, func() {
		db.Close()
		container.Terminate(ctx)
	}
}

// TestSigningKeyStore_Lifecycle walks the full key lifecycle against the real
// v79 table: legacy import under LegacyKid, rotation with grace, verification
// set ordering, single-active enforcement, encryption at rest, and pruning.
func TestSigningKeyStore_Lifecycle(t *testing.T) {
	db, cleanup := setupTestDB(t) // skips if testcontainers unavailable
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	store := NewStore(db.Pool, testEncryptionKey, zap.NewNop())

	// EnsureActive with a legacy key imports it under the legacy kid, so
	// pre-upgrade tokens keep resolving against the same JWKS entry.
	legacy, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	active, err := store.EnsureActive(ctx, legacy)
	if err != nil {
		t.Fatalf("EnsureActive(legacy): %v", err)
	}
	if active.Kid != LegacyKid {
		t.Fatalf("imported kid = %q, want %q", active.Kid, LegacyKid)
	}
	if active.Private.N.Cmp(legacy.N) != 0 {
		t.Fatal("imported key does not round-trip the legacy private key")
	}

	// Idempotent: a second call (e.g. another replica booting) returns the
	// same key rather than minting a new one.
	again, err := store.EnsureActive(ctx, nil)
	if err != nil || again.Kid != LegacyKid {
		t.Fatalf("EnsureActive re-entry = (%v, %v), want existing %s", again, err, LegacyKid)
	}

	// Encryption at rest: the stored column must be ciphertext, not PEM.
	var storedPEM string
	if err := db.Pool.QueryRow(ctx,
		`SELECT private_key_pem FROM oauth_signing_keys WHERE kid = $1`, LegacyKid).Scan(&storedPEM); err != nil {
		t.Fatalf("read stored key: %v", err)
	}
	if !secretcrypt.IsEncrypted(storedPEM) {
		t.Fatal("private_key_pem stored in plaintext despite a 32-byte encryption key")
	}

	// Rotate: new active key, legacy retired with a not_after grace.
	rotated, err := store.Rotate(ctx, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated.Kid == LegacyKid || rotated.Status != "active" {
		t.Fatalf("rotated key = %s/%s, want fresh active kid", rotated.Kid, rotated.Status)
	}

	keys, err := store.VerificationKeys(ctx)
	if err != nil {
		t.Fatalf("VerificationKeys: %v", err)
	}
	if len(keys) != 2 || keys[0].Kid != rotated.Kid || keys[1].Kid != LegacyKid {
		t.Fatalf("verification set = %+v, want [active %s, retired %s]", kidsOf(keys), rotated.Kid, LegacyKid)
	}
	if keys[1].NotAfter == nil || !keys[1].NotAfter.After(time.Now().Add(29*24*time.Hour)) {
		t.Fatalf("retired key not_after = %v, want ~30 days out", keys[1].NotAfter)
	}

	// The partial unique index allows at most one active key.
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO oauth_signing_keys (kid, private_key_pem, status) VALUES ('rogue', 'x', 'active')
	`); err == nil {
		t.Fatal("second active key accepted; partial unique index missing")
	}

	// Expired grace → pruned; unexpired keys survive.
	if _, err := db.Pool.Exec(ctx,
		`UPDATE oauth_signing_keys SET not_after = NOW() - INTERVAL '1 hour' WHERE kid = $1`, LegacyKid); err != nil {
		t.Fatal(err)
	}
	pruned, err := store.PruneExpired(ctx)
	if err != nil || pruned != 1 {
		t.Fatalf("PruneExpired = (%d, %v), want (1, nil)", pruned, err)
	}
	keys, err = store.VerificationKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].Kid != rotated.Kid {
		t.Fatalf("post-prune verification set = %v (%v), want only %s", kidsOf(keys), err, rotated.Kid)
	}

	// List never exposes private material.
	listed, err := store.List(ctx)
	if err != nil || len(listed) != 1 {
		t.Fatalf("List = %v (%v), want 1 key", kidsOf(listed), err)
	}
	if listed[0].Private != nil {
		t.Fatal("List leaked private key material")
	}
}

// TestSigningKeyStore_GeneratesWithoutLegacy covers the fresh-install path:
// no legacy key → a generated key under a random kid.
func TestSigningKeyStore_GeneratesWithoutLegacy(t *testing.T) {
	db, cleanup := setupTestDB(t) // skips if testcontainers unavailable
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	store := NewStore(db.Pool, testEncryptionKey, zap.NewNop())
	active, err := store.EnsureActive(ctx, nil)
	if err != nil {
		t.Fatalf("EnsureActive(nil): %v", err)
	}
	if active.Kid == LegacyKid || active.Private == nil {
		t.Fatalf("generated key = %s, want fresh random kid with material", active.Kid)
	}
}

func kidsOf(keys []*Key) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.Kid + "/" + k.Status
	}
	return out
}
