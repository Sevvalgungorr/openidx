package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// RFC 8628 — OAuth 2.0 Device Authorization Grant.
//
// For clients that can display text but cannot host a browser or accept typed
// input: a TV app, a CLI on a headless machine, a kiosk. The device asks this
// server for a pair of codes, shows the user a short user_code and a URL, and
// polls the token endpoint while the user authorizes on a phone or laptop.
//
// Without it, such clients get pushed onto the resource-owner password grant
// (handing the device the user's actual password, which is what OAuth exists to
// avoid) or onto a token pasted in by hand.

const (
	grantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

	// deviceCodeLifetime is how long the user has to finish authorizing.
	// RFC 8628 suggests a short window; 10 minutes is long enough to walk to
	// another device and short enough that an abandoned code stops being a live
	// grant quickly.
	deviceCodeLifetime = 10 * time.Minute

	// devicePollInterval is the initial minimum gap between polls, in seconds.
	devicePollInterval = 5

	// deviceUserCodeLength is the number of characters in a user_code.
	// With the 20-character alphabet below that is ~34.6 bits, well past the 20
	// bits RFC 8628 §5.1 sets as the floor, and it stays short enough to read
	// off a screen and type without a keyboard.
	deviceUserCodeLength = 8

	// deviceUserCodeAlphabet omits characters that get confused when a code is
	// read off a television across a room and typed on a phone: 0/O, 1/I/L,
	// 5/S, 2/Z, 8/B. A user_code that cannot be transcribed reliably fails the
	// flow just as surely as one that is rejected.
	deviceUserCodeAlphabet = "ACDEFGHJKMNPQRTUVWXY"
)

// errDeviceCodeNotFound distinguishes "no such device code" from a query error,
// so a database fault is never reported to a client as an expired grant.
var errDeviceCodeNotFound = errors.New("device code not found")

// deviceCodeRecord is one in-flight device authorization.
type deviceCodeRecord struct {
	ID           string
	UserCode     string
	ClientID     string
	Scope        string
	State        string
	UserID       string
	OrgID        string
	Interval     int
	LastPolledAt *time.Time
	ConsumedAt   *time.Time
	ExpiresAt    time.Time
}

// scrubLogValue strips CR/LF from a value before it reaches a log line.
//
// client_id arrives in the request body, so without this a caller could embed
// newlines and forge additional log entries — the reader of an incident log
// cannot tell a forged line from a real one. Mirrors the helper of the same name
// in internal/identity; it is duplicated rather than shared because a one-line
// string filter is not worth a package dependency between two services.
func scrubLogValue(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), "\r", "")
}

// hashDeviceCode returns the stored form of a device_code.
func hashDeviceCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// normalizeUserCode makes what a human typed comparable to what was issued:
// upper-cased, with the separators and whitespace people naturally add ("WDJB
// -MJHT") removed. Without this the flow rejects codes that are, to the user,
// exactly what the screen showed.
func normalizeUserCode(in string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(in)) {
		if r == '-' || r == ' ' || r == '\t' || r == '_' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// formatUserCode groups a code for display ("ACDEFGHJ" -> "ACDE-FGHJ"). Only
// presentational; normalizeUserCode undoes it on the way back in.
func formatUserCode(code string) string {
	if len(code) != deviceUserCodeLength {
		return code
	}
	return code[:4] + "-" + code[4:]
}

// randomUserCode draws a user_code from the unambiguous alphabet using the
// crypto RNG. Modulo bias is avoided by rejecting nothing — len(alphabet) is
// used with rand.Int, which is uniform over the range.
func randomUserCode() (string, error) {
	limit := big.NewInt(int64(len(deviceUserCodeAlphabet)))
	out := make([]byte, deviceUserCodeLength)
	for i := range out {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		out[i] = deviceUserCodeAlphabet[n.Int64()]
	}
	return string(out), nil
}

// handleDeviceAuthorization implements RFC 8628 §3.1/§3.2: the device asks for a
// code pair and is told where to send the user.
func (s *Service) handleDeviceAuthorization(c *gin.Context) {
	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "organization context required"})
		return
	}

	clientID, clientSecret, credsOK := clientCredentials(c)
	if !credsOK {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "use only one client authentication method"})
		return
	}
	if clientID == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "client_id is required"})
		return
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}
	// Confidential clients still authenticate. The grant is aimed at public
	// clients, but a client that has a secret must not be usable without it.
	if client.Type == "confidential" &&
		subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}

	scope := c.PostForm("scope")
	// Same rule as every other grant: a client cannot mint itself scopes it was
	// never provisioned for (RFC 6749 §3.3).
	if scope != "" && !scopeAllowedForClient(client, scope) {
		c.JSON(400, gin.H{
			"error":             "invalid_scope",
			"error_description": "requested scope exceeds the scopes registered for this client",
		})
		return
	}

	// Retire expired rows before issuing. The unique index on (org_id,
	// user_code) covers expired rows on purpose, so without this the code space
	// only ever shrinks.
	if _, err := s.db.Pool.Exec(ctx,
		`DELETE FROM oauth_device_codes WHERE org_id = $1 AND expires_at < NOW() - INTERVAL '1 hour'`,
		org.ID); err != nil {
		s.logger.Warn("device code sweep failed", zap.Error(err))
	}

	deviceCode := GenerateRandomToken(32)
	now := time.Now()

	// Retry on user_code collision rather than failing the request: the unique
	// index is the authority on uniqueness, and a race between two devices
	// drawing the same code is rare but real.
	var userCode string
	var insertErr error
	for attempt := 0; attempt < 5; attempt++ {
		candidate, gerr := randomUserCode()
		if gerr != nil {
			c.JSON(500, gin.H{"error": "server_error"})
			return
		}
		_, insertErr = s.db.Pool.Exec(ctx, `
			INSERT INTO oauth_device_codes
			    (device_code_hash, user_code, client_id, scope, org_id, interval_secs, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			hashDeviceCode(deviceCode), candidate, clientID, scope, org.ID,
			devicePollInterval, now.Add(deviceCodeLifetime))
		if insertErr == nil {
			userCode = candidate
			break
		}
	}
	if userCode == "" {
		s.logger.Error("failed to issue device code", zap.Error(insertErr))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	issuer := s.issuerForOrg(org)
	verificationURI := issuer + "/device"

	s.logger.Info("device authorization issued",
		zap.String("client_id", scrubLogValue(clientID)), zap.String("org_id", org.ID))

	c.JSON(200, gin.H{
		"device_code":      deviceCode,
		"user_code":        formatUserCode(userCode),
		"verification_uri": verificationURI,
		// RFC 8628 §3.2: the complete URI lets a device that can render a QR
		// code skip the typing entirely.
		"verification_uri_complete": verificationURI + "?user_code=" + formatUserCode(userCode),
		"expires_in":                int(deviceCodeLifetime.Seconds()),
		"interval":                  devicePollInterval,
	})
}

// loadDeviceCodeByHash reads one device authorization by the hash of its code.
func (s *Service) loadDeviceCodeByHash(ctx context.Context, hash, orgID string) (*deviceCodeRecord, error) {
	var r deviceCodeRecord
	var userID, scope *string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, user_code, client_id, COALESCE(scope,''), state, user_id, org_id,
		       interval_secs, last_polled_at, consumed_at, expires_at
		  FROM oauth_device_codes
		 WHERE device_code_hash = $1 AND org_id = $2`, hash, orgID).
		Scan(&r.ID, &r.UserCode, &r.ClientID, &scope, &r.State, &userID, &r.OrgID,
			&r.Interval, &r.LastPolledAt, &r.ConsumedAt, &r.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errDeviceCodeNotFound
	}
	if err != nil {
		return nil, err
	}
	if userID != nil {
		r.UserID = *userID
	}
	if scope != nil {
		r.Scope = *scope
	}
	return &r, nil
}

// handleDeviceCodeGrant implements RFC 8628 §3.4/§3.5: the device polls here
// until the user approves, denies, or the code expires.
func (s *Service) handleDeviceCodeGrant(c *gin.Context) {
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}

	clientID, clientSecret, credsOK := clientCredentials(c)
	if !credsOK {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "use only one client authentication method"})
		return
	}
	deviceCode := c.PostForm("device_code")
	if deviceCode == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "device_code is required"})
		return
	}

	rec, err := s.loadDeviceCodeByHash(ctx, hashDeviceCode(deviceCode), org.ID)
	if errors.Is(err, errDeviceCodeNotFound) {
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}
	if err != nil {
		s.logger.Error("device code lookup failed", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	// The code was issued to one client; another client presenting it is not a
	// slow poll, it is a theft attempt.
	if rec.ClientID != clientID {
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}
	if client.Type == "confidential" &&
		subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}

	if rec.ConsumedAt != nil {
		// Already redeemed. Single-use, like an authorization code.
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}
	if time.Now().After(rec.ExpiresAt) {
		c.JSON(400, gin.H{"error": "expired_token"})
		return
	}

	// Rate limit before reporting state, so a client cannot poll in a tight loop
	// and be told "authorization_pending" thousands of times a second. RFC 8628
	// §3.5: answer slow_down and raise the client's interval.
	if tooFast, newInterval := s.throttleDevicePoll(ctx, rec); tooFast {
		c.JSON(400, gin.H{"error": "slow_down", "interval": newInterval})
		return
	}

	switch rec.State {
	case "denied":
		c.JSON(400, gin.H{"error": "access_denied"})
		return
	case "approved":
		// fall through to issuing
	default:
		c.JSON(400, gin.H{"error": "authorization_pending"})
		return
	}

	// Claim the code before minting anything. The conditional UPDATE is what
	// makes redemption single-use under concurrent polls: exactly one caller can
	// move consumed_at from NULL, so two simultaneous polls cannot both be
	// handed a token for one authorization.
	claimedUser, err := s.claimApprovedDeviceCode(ctx, rec.ID)
	if errors.Is(err, errDeviceCodeNotFound) {
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}
	if err != nil {
		s.logger.Error("failed to claim device code", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	if claimedUser == "" {
		s.logger.Error("approved device code has no user", zap.String("device_code_id", rec.ID))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	accessToken, err := s.GenerateJWT(ctx, claimedUser, clientID, rec.Scope, client.AccessTokenLifetime, "")
	if err != nil {
		s.logger.Error("failed to mint device grant access token", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	resp := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   client.AccessTokenLifetime,
		Scope:       rec.Scope,
	}
	if strings.Contains(rec.Scope, "openid") {
		if idToken, ierr := s.GenerateIDToken(ctx, claimedUser, clientID, "", client.AccessTokenLifetime, ""); ierr == nil {
			resp.IDToken = idToken
		}
	}
	if client.AllowRefreshToken && strings.Contains(rec.Scope, "offline_access") {
		refreshToken := GenerateRandomToken(32)
		if err := s.CreateRefreshToken(ctx, &RefreshToken{
			Token:     refreshToken,
			ClientID:  clientID,
			UserID:    claimedUser,
			Scope:     rec.Scope,
			ExpiresAt: time.Now().Add(time.Duration(client.RefreshTokenLifetime) * time.Second),
		}); err != nil {
			// Same reasoning as the authorization-code grant: never hand back a
			// refresh token that was not persisted, or every later refresh 400s.
			s.logger.Error("failed to persist device grant refresh token", zap.Error(err))
		} else {
			resp.RefreshToken = refreshToken
		}
	}

	s.logger.Info("device grant redeemed",
		zap.String("client_id", scrubLogValue(clientID)), zap.String("user_id", scrubLogValue(claimedUser)))
	c.JSON(200, resp)
}

// claimApprovedDeviceCode marks an approved device_code redeemed and returns the
// subject it was approved for.
//
// The conditional UPDATE is what makes redemption single-use under concurrent
// polls: only one caller can move consumed_at off NULL, so two simultaneous
// polls cannot both be handed a token for one authorization. Doing this check in
// Go would be the same read-then-write race that makes a "used" flag useless.
func (s *Service) claimApprovedDeviceCode(ctx context.Context, id string) (string, error) {
	var userID string
	err := s.db.Pool.QueryRow(ctx, `
		UPDATE oauth_device_codes
		   SET consumed_at = NOW()
		 WHERE id = $1 AND consumed_at IS NULL AND state = 'approved' AND expires_at > NOW()
		RETURNING COALESCE(user_id::text, '')`, id).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errDeviceCodeNotFound
	}
	if err != nil {
		return "", err
	}
	return userID, nil
}

// decideDeviceCode records an approve/deny against a pending code and returns the
// row id and the client the code belongs to.
//
// Guarded in SQL rather than Go so a second decision cannot overwrite the first
// — including flipping an approval the device has already redeemed, which would
// otherwise let a later "deny" silently re-open a consumed grant for reuse.
func (s *Service) decideDeviceCode(ctx context.Context, normalizedUserCode, orgID, next, userID string) (string, string, error) {
	var id, clientID string
	err := s.db.Pool.QueryRow(ctx, `
		UPDATE oauth_device_codes
		   SET state = $3, user_id = $4
		 WHERE user_code = $1 AND org_id = $2
		   AND state = 'pending' AND consumed_at IS NULL AND expires_at > NOW()
		RETURNING id, client_id`, normalizedUserCode, orgID, next, userID).Scan(&id, &clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", errDeviceCodeNotFound
	}
	if err != nil {
		return "", "", err
	}
	return id, clientID, nil
}

// throttleDevicePoll enforces the polling interval. It returns whether this poll
// arrived too soon and the interval the client should adopt.
//
// The increase is the point: a client that ignores the interval is told a larger
// one each time, so a misbehaving device backs off instead of hammering the
// token endpoint for the full lifetime of the code.
func (s *Service) throttleDevicePoll(ctx context.Context, rec *deviceCodeRecord) (bool, int) {
	now := time.Now()
	if rec.LastPolledAt == nil {
		if _, err := s.db.Pool.Exec(ctx,
			`UPDATE oauth_device_codes SET last_polled_at = $2 WHERE id = $1`, rec.ID, now); err != nil {
			s.logger.Warn("failed to record device poll", zap.Error(err))
		}
		return false, rec.Interval
	}

	if now.Sub(*rec.LastPolledAt) >= time.Duration(rec.Interval)*time.Second {
		if _, err := s.db.Pool.Exec(ctx,
			`UPDATE oauth_device_codes SET last_polled_at = $2 WHERE id = $1`, rec.ID, now); err != nil {
			s.logger.Warn("failed to record device poll", zap.Error(err))
		}
		return false, rec.Interval
	}

	next := rec.Interval + devicePollInterval
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE oauth_device_codes SET interval_secs = $2, last_polled_at = $3 WHERE id = $1`,
		rec.ID, next, now); err != nil {
		s.logger.Warn("failed to raise device poll interval", zap.Error(err))
	}
	return true, next
}

// resolveUserCode finds a pending authorization by the code a user typed.
func (s *Service) resolveUserCode(ctx context.Context, userCode, orgID string) (*deviceCodeRecord, error) {
	normalized := normalizeUserCode(userCode)
	if normalized == "" {
		return nil, errDeviceCodeNotFound
	}
	var r deviceCodeRecord
	var userID, scope *string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, user_code, client_id, COALESCE(scope,''), state, user_id, org_id,
		       interval_secs, last_polled_at, consumed_at, expires_at
		  FROM oauth_device_codes
		 WHERE user_code = $1 AND org_id = $2`, normalized, orgID).
		Scan(&r.ID, &r.UserCode, &r.ClientID, &scope, &r.State, &userID, &r.OrgID,
			&r.Interval, &r.LastPolledAt, &r.ConsumedAt, &r.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errDeviceCodeNotFound
	}
	if err != nil {
		return nil, err
	}
	if userID != nil {
		r.UserID = *userID
	}
	if scope != nil {
		r.Scope = *scope
	}
	return &r, nil
}

// handleDeviceVerificationLookup backs the verification page: the user types the
// code they were shown and is told what they are about to authorize.
func (s *Service) handleDeviceVerificationLookup(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}

	userCode := c.Query("user_code")
	if userCode == "" {
		userCode = c.PostForm("user_code")
	}

	rec, err := s.resolveUserCode(ctx, userCode, org.ID)
	if errors.Is(err, errDeviceCodeNotFound) {
		// One message for "no such code" and for "expired": distinguishing them
		// turns this endpoint into an oracle for probing which codes exist.
		c.JSON(404, gin.H{"error": "invalid_user_code", "error_description": "that code is not valid or has expired"})
		return
	}
	if err != nil {
		s.logger.Error("user code lookup failed", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	if time.Now().After(rec.ExpiresAt) || rec.ConsumedAt != nil {
		c.JSON(404, gin.H{"error": "invalid_user_code", "error_description": "that code is not valid or has expired"})
		return
	}

	clientName := rec.ClientID
	if client, cerr := s.GetClient(ctx, rec.ClientID); cerr == nil && client.Name != "" {
		clientName = client.Name
	}

	c.JSON(200, gin.H{
		"user_code":   formatUserCode(rec.UserCode),
		"client_id":   rec.ClientID,
		"client_name": clientName,
		"scope":       rec.Scope,
		"state":       rec.State,
		"expires_in":  int(time.Until(rec.ExpiresAt).Seconds()),
	})
}

// handleDeviceVerificationDecision records the user's approve/deny for a code.
//
// The caller must be an authenticated user: this is the step that binds a
// subject to the device's pending grant, so taking the user id from anywhere
// other than the session would let anyone approve anyone's device.
func (s *Service) handleDeviceVerificationDecision(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}

	userID := currentUserID(c)
	if userID == "" {
		c.JSON(401, gin.H{"error": "login_required", "error_description": "sign in before approving a device"})
		return
	}

	var body struct {
		UserCode string `json:"user_code" form:"user_code"`
		Approve  bool   `json:"approve" form:"approve"`
	}
	if err := c.ShouldBind(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}

	normalized := normalizeUserCode(body.UserCode)
	if normalized == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "user_code is required"})
		return
	}

	next := "denied"
	if body.Approve {
		next = "approved"
	}

	// Only a still-pending, unexpired, unconsumed code can be decided. Guarding
	// in SQL rather than in Go means a second decision cannot overwrite the
	// first — including flipping an approval the device has already redeemed.
	id, decidedClient, err := s.decideDeviceCode(ctx, normalized, org.ID, next, userID)
	if errors.Is(err, errDeviceCodeNotFound) {
		c.JSON(404, gin.H{"error": "invalid_user_code", "error_description": "that code is not valid or has expired"})
		return
	}
	if err != nil {
		s.logger.Error("device decision failed", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	s.logAuditEvent(ctx, "oauth", "authorization", "oauth.device_"+next, "success",
		userID, c.ClientIP(), id, "device_code",
		map[string]interface{}{"approved": body.Approve, "client_id": decidedClient})

	c.JSON(200, gin.H{"status": next})
}

// currentUserID pulls the authenticated subject from the gin context, matching
// how the other interactive OAuth handlers identify the signed-in user.
func currentUserID(c *gin.Context) string {
	for _, key := range []string{"user_id", "userID", "sub"} {
		if v, ok := c.Get(key); ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
