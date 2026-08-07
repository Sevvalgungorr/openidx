//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/webhooks"
)

// TestWebhookSecretEncryptedAtRest proves the encrypt-at-rest guarantee for the
// webhook HMAC signing secret: CreateSubscription stores ciphertext (tagged
// encv1:, never the plaintext), GetSubscription decrypts it back, and a legacy
// (untagged) plaintext row still reads through unchanged. Runs on the real test
// DB with a miniredis; requires migration v65 (secret TEXT) applied.
func TestWebhookSecretEncryptedAtRest(t *testing.T) {
	db, err := database.NewPostgres(integrationDSN(t))
	require.NoError(t, err, "connect test DB")
	defer db.Close()
	ctx := context.Background()

	mini, err := miniredis.Run()
	require.NoError(t, err)
	defer mini.Close()
	rc := &database.RedisClient{Client: redis.NewClient(&redis.Options{Addr: mini.Addr()})}

	cipher, err := secretcrypt.New("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	svc := webhooks.NewService(db, rc, zaptest.NewLogger(t), cipher)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	// Webhook rows are tenant-scoped: CreateSubscription reads org_id from the
	// request context and the RLS WITH CHECK on webhook_subscriptions rejects a
	// row whose org_id does not match app.org_id. So the whole test runs inside
	// a real org context rather than a bare background context.
	orgID := seedOrg(t, db.Pool, "wh-enc-"+suffix)
	t.Cleanup(func() { bypassExec(t, db.Pool, "DELETE FROM organizations WHERE id=$1", orgID) })
	ctx = orgctx.With(orgctx.WithBypassRLS(ctx), orgctx.Org{ID: orgID})

	const plaintext = "whsec_ABC123_do_not_store_plaintext"

	sub, err := svc.CreateSubscription(ctx, "enc-"+suffix, "https://example.test/hook",
		plaintext, []string{"user.created"}, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), "DELETE FROM webhook_subscriptions WHERE id=$1", sub.ID)
	})

	// Create returns the caller-supplied plaintext.
	assert.Equal(t, plaintext, sub.Secret)

	// At rest the column holds tagged ciphertext, never the plaintext.
	var stored string
	require.NoError(t, db.Pool.QueryRow(ctx,
		"SELECT secret FROM webhook_subscriptions WHERE id=$1", sub.ID).Scan(&stored))
	assert.True(t, secretcrypt.IsEncrypted(stored), "stored secret must be encrypted (encv1: tag)")
	assert.NotEqual(t, plaintext, stored)
	assert.NotContains(t, stored, plaintext)

	// Read decrypts back to the plaintext.
	got, err := svc.GetSubscription(ctx, sub.ID)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got.Secret)

	// A legacy plaintext row (no tag) still reads through unchanged.
	legacyID := uuid.NewString()
	_, err = db.Pool.Exec(ctx,
		`INSERT INTO webhook_subscriptions (id, name, url, secret, events, status, org_id)
		 VALUES ($1, $2, $3, $4, $5::TEXT[], 'active', $6)`,
		legacyID, "legacy-"+suffix, "https://example.test/legacy", "legacy-plaintext-secret",
		[]string{"user.created"}, orgID)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), "DELETE FROM webhook_subscriptions WHERE id=$1", legacyID)
	})
	legacyGot, err := svc.GetSubscription(ctx, legacyID)
	require.NoError(t, err)
	assert.Equal(t, "legacy-plaintext-secret", legacyGot.Secret)
}
