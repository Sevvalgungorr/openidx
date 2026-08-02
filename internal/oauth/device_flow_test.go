package oauth

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

func TestNormalizeUserCode(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"ACDE-FGHJ", "ACDEFGHJ"},
		{"acde-fghj", "ACDEFGHJ"},
		{"  ACDE FGHJ  ", "ACDEFGHJ"},
		{"acde_fghj", "ACDEFGHJ"},
		{"ACDEFGHJ", "ACDEFGHJ"},
		{"", ""},
		{"   ", ""},
	} {
		if got := normalizeUserCode(tc.in); got != tc.want {
			t.Errorf("normalizeUserCode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestUserCodeRoundTripsThroughDisplay — the code is shown grouped and typed
// back by a human. If display and normalization disagree, every user who types
// exactly what the screen shows is rejected.
func TestUserCodeRoundTripsThroughDisplay(t *testing.T) {
	for i := 0; i < 50; i++ {
		code, err := randomUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if got := normalizeUserCode(formatUserCode(code)); got != code {
			t.Fatalf("display round trip broke: %q -> %q -> %q", code, formatUserCode(code), got)
		}
	}
}

// TestUserCodeAvoidsAmbiguousCharacters — a code read off a television and typed
// on a phone fails just as hard when it is mistranscribed as when it is wrong.
func TestUserCodeAvoidsAmbiguousCharacters(t *testing.T) {
	const ambiguous = "01258BILOSZ"
	seen := map[rune]bool{}
	for i := 0; i < 200; i++ {
		code, err := randomUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != deviceUserCodeLength {
			t.Fatalf("code %q has length %d, want %d", code, len(code), deviceUserCodeLength)
		}
		for _, r := range code {
			if strings.ContainsRune(ambiguous, r) {
				t.Fatalf("code %q contains the easily-confused character %q", code, r)
			}
			if !strings.ContainsRune(deviceUserCodeAlphabet, r) {
				t.Fatalf("code %q contains %q which is outside the alphabet", code, r)
			}
			seen[r] = true
		}
	}
	// Sanity: the generator should be using the whole alphabet, not a corner of
	// it. 200 codes x 8 chars over 20 symbols makes near-total coverage certain.
	if len(seen) < len(deviceUserCodeAlphabet)-2 {
		t.Fatalf("only %d of %d alphabet characters ever appeared", len(seen), len(deviceUserCodeAlphabet))
	}
}

func TestUserCodesAreNotPredictable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		code, err := randomUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if seen[code] {
			t.Fatalf("randomUserCode repeated %q within 200 draws", code)
		}
		seen[code] = true
	}
}

// TestDeviceCodeIsStoredHashed — device_code is a bearer credential the client
// polls with, so what lands in the row must not be redeemable as-is.
func TestDeviceCodeIsStoredHashed(t *testing.T) {
	const code = "some-device-code-value"
	h := hashDeviceCode(code)
	if h == code || strings.Contains(h, code) {
		t.Fatalf("hashDeviceCode returned something containing the raw code: %q", h)
	}
	if h != hashDeviceCode(code) {
		t.Fatalf("hashDeviceCode is not deterministic")
	}
	if h == hashDeviceCode(code+"x") {
		t.Fatalf("distinct codes hash the same")
	}
	if len(h) != 64 {
		t.Fatalf("expected a hex SHA-256, got %d chars", len(h))
	}
}

// deviceTestService builds a service over a throwaway Postgres carrying the
// v125 schema, pulled from the migration registry rather than restated so an
// edit to the migration is what these tests run against.
func deviceTestService(t *testing.T) (*Service, context.Context) {
	t.Helper()
	db, cleanup := ssfSetupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := context.Background()
	m := migrations.NewMigrator(nil, zap.NewNop())
	list, err := m.LoadMigrations()
	if err != nil {
		t.Fatalf("LoadMigrations: %v", err)
	}
	var up string
	for _, mig := range list {
		if mig.Version == 125 {
			up = mig.UpSQL
		}
	}
	if up == "" {
		t.Fatalf("migration v125 not found in the registry")
	}
	if _, err := db.Pool.Exec(ctx, up); err != nil {
		t.Fatalf("apply v125: %v", err)
	}
	return &Service{db: db, logger: zap.NewNop()}, ctx
}

const (
	deviceTestOrg    = "33333333-0000-0000-0000-00000000000c"
	deviceTestUser   = "44444444-0000-0000-0000-00000000000d"
	deviceTestOther  = "55555555-0000-0000-0000-00000000000e"
	deviceTestClient = "tv-app"
)

// seedDeviceCode inserts one authorization and returns its id.
func seedDeviceCode(t *testing.T, s *Service, ctx context.Context, userCode, state string, expiresIn time.Duration) string {
	t.Helper()
	var id string
	err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO oauth_device_codes
		    (device_code_hash, user_code, client_id, scope, state, org_id, interval_secs, expires_at)
		VALUES ($1, $2, $3, 'openid', $4, $5, 5, NOW() + $6::interval)
		RETURNING id`,
		hashDeviceCode("dc-"+userCode), userCode, deviceTestClient, state, deviceTestOrg,
		expiresIn.String()).Scan(&id)
	if err != nil {
		t.Fatalf("seed device code: %v", err)
	}
	return id
}

// TestApprovedDeviceCodeIsRedeemableExactlyOnce is the core single-use property.
// A device polls in a loop; if two polls land together and both are handed a
// token, one authorization has minted two credentials.
func TestApprovedDeviceCodeIsRedeemableExactlyOnce(t *testing.T) {
	s, ctx := deviceTestService(t)
	id := seedDeviceCode(t, s, ctx, "ACDEFGHJ", "approved", 10*time.Minute)
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE oauth_device_codes SET user_id = $2 WHERE id = $1`, id, deviceTestUser); err != nil {
		t.Fatal(err)
	}

	const pollers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	var wins int
	wg.Add(pollers)
	for i := 0; i < pollers; i++ {
		go func() {
			defer wg.Done()
			user, err := s.claimApprovedDeviceCode(ctx, id)
			if err == nil && user == deviceTestUser {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if wins != 1 {
		t.Fatalf("%d of %d concurrent polls redeemed the same device code; want exactly 1", wins, pollers)
	}
	if _, err := s.claimApprovedDeviceCode(ctx, id); err == nil {
		t.Fatalf("a consumed device code was redeemable again")
	}
}

func TestPendingAndDeniedCodesCannotBeRedeemed(t *testing.T) {
	s, ctx := deviceTestService(t)

	pending := seedDeviceCode(t, s, ctx, "ACDEFGHK", "pending", 10*time.Minute)
	if _, err := s.claimApprovedDeviceCode(ctx, pending); err == nil {
		t.Fatalf("a pending device code was redeemed")
	}

	denied := seedDeviceCode(t, s, ctx, "ACDEFGHM", "denied", 10*time.Minute)
	if _, err := s.claimApprovedDeviceCode(ctx, denied); err == nil {
		t.Fatalf("a denied device code was redeemed")
	}
}

// TestExpiredApprovedCodeCannotBeRedeemed — an approval that was never collected
// must stop being a live grant when the code expires, not linger indefinitely.
func TestExpiredApprovedCodeCannotBeRedeemed(t *testing.T) {
	s, ctx := deviceTestService(t)
	id := seedDeviceCode(t, s, ctx, "ACDEFGHN", "approved", -1*time.Minute)
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE oauth_device_codes SET user_id = $2 WHERE id = $1`, id, deviceTestUser); err != nil {
		t.Fatal(err)
	}
	if _, err := s.claimApprovedDeviceCode(ctx, id); err == nil {
		t.Fatalf("an expired but approved device code was redeemed")
	}
}

// TestDecisionIsFinal — a second decision must not overwrite the first. Letting
// a later "deny" land on an approval the device already redeemed would move a
// consumed row back to a decidable state.
func TestDecisionIsFinal(t *testing.T) {
	s, ctx := deviceTestService(t)
	seedDeviceCode(t, s, ctx, "ACDEFGHP", "pending", 10*time.Minute)

	id, client, err := s.decideDeviceCode(ctx, "ACDEFGHP", deviceTestOrg, "approved", deviceTestUser)
	if err != nil {
		t.Fatalf("first decision: %v", err)
	}
	if client != deviceTestClient {
		t.Fatalf("client_id = %q, want %q", client, deviceTestClient)
	}

	if _, _, err := s.decideDeviceCode(ctx, "ACDEFGHP", deviceTestOrg, "denied", deviceTestOther); err == nil {
		t.Fatalf("a second decision overwrote the first")
	}

	var state, user string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT state, COALESCE(user_id::text,'') FROM oauth_device_codes WHERE id = $1`, id).
		Scan(&state, &user); err != nil {
		t.Fatal(err)
	}
	if state != "approved" || user != deviceTestUser {
		t.Fatalf("row was changed by the rejected second decision: state=%s user=%s", state, user)
	}
}

// TestDecisionIsOrgScoped — user codes are unique per organization, so a code
// approved from another tenant's context must not match.
func TestDecisionIsOrgScoped(t *testing.T) {
	s, ctx := deviceTestService(t)
	seedDeviceCode(t, s, ctx, "ACDEFGHQ", "pending", 10*time.Minute)

	if _, _, err := s.decideDeviceCode(ctx, "ACDEFGHQ", deviceTestOther, "approved", deviceTestUser); err == nil {
		t.Fatalf("a device code was decided from a different organization")
	}
}

func TestExpiredCodeCannotBeDecided(t *testing.T) {
	s, ctx := deviceTestService(t)
	seedDeviceCode(t, s, ctx, "ACDEFGHR", "pending", -1*time.Minute)

	if _, _, err := s.decideDeviceCode(ctx, "ACDEFGHR", deviceTestOrg, "approved", deviceTestUser); err == nil {
		t.Fatalf("an expired device code was approved")
	}
}

// TestPollThrottleRaisesTheInterval — RFC 8628 §3.5. A client that ignores the
// interval must be told a bigger one, so a misbehaving device backs off instead
// of hammering the token endpoint for the code's whole lifetime.
func TestPollThrottleRaisesTheInterval(t *testing.T) {
	s, ctx := deviceTestService(t)
	id := seedDeviceCode(t, s, ctx, "ACDEFGHT", "pending", 10*time.Minute)

	rec, err := s.loadDeviceCodeByHash(ctx, hashDeviceCode("dc-ACDEFGHT"), deviceTestOrg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if rec.ID != id {
		t.Fatalf("loaded the wrong row")
	}

	// First poll is always allowed — there is nothing to be too fast relative to.
	if tooFast, _ := s.throttleDevicePoll(ctx, rec); tooFast {
		t.Fatalf("the first poll was throttled")
	}

	// Immediately again: inside the interval.
	rec, _ = s.loadDeviceCodeByHash(ctx, hashDeviceCode("dc-ACDEFGHT"), deviceTestOrg)
	tooFast, next := s.throttleDevicePoll(ctx, rec)
	if !tooFast {
		t.Fatalf("a poll inside the interval was not throttled")
	}
	if next <= rec.Interval {
		t.Fatalf("interval did not increase: was %d, told %d", rec.Interval, next)
	}

	var stored int
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT interval_secs FROM oauth_device_codes WHERE id = $1`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != next {
		t.Fatalf("raised interval was not persisted: row has %d, client told %d", stored, next)
	}
}

// TestLoadDeviceCodeIsOrgScoped — the device_code hash is looked up together
// with the org, so a code cannot be redeemed from another tenant's context.
func TestLoadDeviceCodeIsOrgScoped(t *testing.T) {
	s, ctx := deviceTestService(t)
	seedDeviceCode(t, s, ctx, "ACDEFGHU", "approved", 10*time.Minute)

	if _, err := s.loadDeviceCodeByHash(ctx, hashDeviceCode("dc-ACDEFGHU"), deviceTestOther); err == nil {
		t.Fatalf("a device code resolved from a different organization")
	}
}

// TestUserCodeLookupNormalizesInput — the user types what the screen showed,
// dashes and all.
func TestUserCodeLookupNormalizesInput(t *testing.T) {
	s, ctx := deviceTestService(t)
	seedDeviceCode(t, s, ctx, "ACDEFGHV", "pending", 10*time.Minute)

	for _, typed := range []string{"ACDEFGHV", "ACDE-FGHV", "acde-fghv", " acde fghv "} {
		rec, err := s.resolveUserCode(ctx, typed, deviceTestOrg)
		if err != nil {
			t.Fatalf("resolveUserCode(%q): %v", typed, err)
		}
		if rec.UserCode != "ACDEFGHV" {
			t.Fatalf("resolved %q to %q", typed, rec.UserCode)
		}
	}
	if _, err := s.resolveUserCode(ctx, "", deviceTestOrg); err == nil {
		t.Fatalf("an empty user code resolved")
	}
}
