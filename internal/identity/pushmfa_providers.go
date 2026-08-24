// Package identity - Push MFA delivery transports (FCM HTTP v1 + APNS token auth).
//
// This replaces the decommissioned legacy FCM server-key endpoint and the
// unauthenticated APNS path. FCM uses an OAuth2 bearer token minted from a
// service-account credentials file; APNS uses a provider authentication token
// (an ES256 JWT signed with the .p8 key), refreshed well within Apple's 60-min
// ceiling. Both token sources are cached per process.
package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// fcmMessagingScope is the OAuth2 scope required to send FCM HTTP v1 messages.
const fcmMessagingScope = "https://www.googleapis.com/auth/firebase.messaging"

// errDeadPushToken signals that the destination push token is no longer valid
// (the app was uninstalled or its token rotated). The provider transports wrap
// this when FCM reports UNREGISTERED / APNS reports Unregistered, and the caller
// prunes the stale device registration so it isn't retried forever.
var errDeadPushToken = errors.New("push token no longer registered")

// apnsTokenTTL is how long a minted APNS provider token is reused before being
// refreshed. Apple rejects tokens older than 60 minutes and throttles clients
// that mint a fresh token per request, so we refresh at 45 minutes.
const apnsTokenTTL = 45 * time.Minute

// fcmProvider holds a cached FCM HTTP v1 token source and the resolved project ID.
// Only a *successful* build is memoized: a transient failure (credentials file
// mounted late at boot, a flaky read) must not permanently disable push for the
// whole process lifetime, so it is retried on the next call.
type fcmProvider struct {
	mu        sync.Mutex
	tokenSrc  oauth2.TokenSource
	projectID string
}

// apnsProvider caches a minted APNS provider token until it needs refreshing.
type apnsProvider struct {
	mu        sync.Mutex
	token     string
	mintedAt  time.Time
	keyPath   string
	keyID     string
	teamID    string
	parsedKey *ecdsa.PrivateKey
}

// fcmMessage is the FCM HTTP v1 request envelope. In v1 every data value must be
// a string, so callers pass a pre-stringified data map.
type fcmMessage struct {
	Message struct {
		Token        string            `json:"token"`
		Notification map[string]string `json:"notification,omitempty"`
		Data         map[string]string `json:"data,omitempty"`
	} `json:"message"`
}

// getFCMToken lazily builds (once) an OAuth2 token source from the configured
// service-account credentials file and returns a fresh bearer token plus the
// resolved project ID.
func (p *fcmProvider) getToken(ctx context.Context, credFile, projectID string) (string, string, error) {
	p.mu.Lock()
	if p.tokenSrc == nil {
		src, pid, err := buildFCMTokenSource(ctx, credFile, projectID)
		if err != nil {
			// Do NOT cache the failure — leave tokenSrc nil so the next call retries.
			p.mu.Unlock()
			return "", "", err
		}
		p.tokenSrc = src
		p.projectID = pid
	}
	src, pid := p.tokenSrc, p.projectID
	p.mu.Unlock()

	tok, err := src.Token()
	if err != nil {
		return "", "", fmt.Errorf("obtain FCM access token: %w", err)
	}
	return tok.AccessToken, pid, nil
}

// buildFCMTokenSource loads the service-account credentials file and returns an
// OAuth2 token source plus the resolved project ID (explicit config wins, else
// the credentials JSON).
func buildFCMTokenSource(ctx context.Context, credFile, projectID string) (oauth2.TokenSource, string, error) {
	if credFile == "" {
		return nil, "", fmt.Errorf("FCM credentials file not configured")
	}
	raw, err := os.ReadFile(credFile) //nolint:gosec // operator-supplied credentials path
	if err != nil {
		return nil, "", fmt.Errorf("read FCM credentials file: %w", err)
	}
	// The credentials JSON is an operator-supplied service-account file from our
	// own config (not untrusted input), so the validation caveat behind the
	// SA1019 deprecation does not apply here.
	creds, err := google.CredentialsFromJSON(ctx, raw, fcmMessagingScope) //nolint:staticcheck // operator-supplied, trusted service-account file
	if err != nil {
		return nil, "", fmt.Errorf("parse FCM credentials: %w", err)
	}
	pid := projectID
	if pid == "" {
		pid = creds.ProjectID
	}
	if pid == "" {
		var sa struct {
			ProjectID string `json:"project_id"`
		}
		if json.Unmarshal(raw, &sa) == nil {
			pid = sa.ProjectID
		}
	}
	if pid == "" {
		return nil, "", fmt.Errorf("FCM project ID not configured and not present in credentials")
	}
	return creds.TokenSource, pid, nil
}

// getToken returns a cached APNS provider token, minting a new ES256 JWT when the
// current one is missing or older than apnsTokenTTL.
func (p *apnsProvider) getToken(keyPath, keyID, teamID string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.token != "" && p.keyPath == keyPath && p.keyID == keyID && p.teamID == teamID &&
		time.Since(p.mintedAt) < apnsTokenTTL {
		return p.token, nil
	}

	// (Re)load the signing key if the path changed or it isn't parsed yet.
	if p.parsedKey == nil || p.keyPath != keyPath {
		key, err := loadAPNSKey(keyPath)
		if err != nil {
			return "", err
		}
		p.parsedKey = key
		p.keyPath = keyPath
	}

	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": teamID,
		"iat": now.Unix(),
	})
	tok.Header["kid"] = keyID

	signed, err := tok.SignedString(p.parsedKey)
	if err != nil {
		return "", fmt.Errorf("sign APNS token: %w", err)
	}

	p.token = signed
	p.mintedAt = now
	p.keyID = keyID
	p.teamID = teamID
	return signed, nil
}

// loadAPNSKey reads and parses the ECDSA private key from an APNS .p8 PEM file.
func loadAPNSKey(path string) (*ecdsa.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("APNS key path not configured")
	}
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied credentials path
	if err != nil {
		return nil, fmt.Errorf("read APNS key file: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("APNS key is not valid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse APNS PKCS8 key: %w", err)
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("APNS key is not an ECDSA key")
	}
	return ecKey, nil
}

// stringifyPayload converts a mixed-type notification payload into the all-string
// data map FCM HTTP v1 requires.
func stringifyPayload(payload map[string]interface{}) map[string]string {
	out := make(map[string]string, len(payload))
	for k, v := range payload {
		switch t := v.(type) {
		case string:
			out[k] = t
		default:
			out[k] = fmt.Sprintf("%v", t)
		}
	}
	return out
}
