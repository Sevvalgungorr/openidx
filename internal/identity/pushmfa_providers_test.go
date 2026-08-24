package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// writeTempServiceAccount writes a minimal but valid FCM service-account JSON
// (with a real RSA private key so google.CredentialsFromJSON can build a token
// source without touching the network) and returns its path.
func writeTempServiceAccount(t *testing.T, projectID string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	sa := map[string]string{
		"type":           "service_account",
		"project_id":     projectID,
		"private_key_id": "test-kid",
		"private_key":    string(keyPEM),
		"client_email":   "svc@example.iam.gserviceaccount.com",
		"client_id":      "123456789",
		"token_uri":      "https://oauth2.googleapis.com/token",
	}
	raw, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("marshal sa: %v", err)
	}
	path := filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write sa: %v", err)
	}
	return path
}

func TestBuildFCMTokenSource_ProjectIDResolution(t *testing.T) {
	ctx := context.Background()
	path := writeTempServiceAccount(t, "creds-project")

	// With no explicit config, the project ID comes from the credentials JSON.
	if _, pid, err := buildFCMTokenSource(ctx, path, ""); err != nil {
		t.Fatalf("build: %v", err)
	} else if pid != "creds-project" {
		t.Errorf("resolved project ID = %q, want creds-project", pid)
	}

	// An explicit config value wins over the credentials JSON.
	if _, pid, err := buildFCMTokenSource(ctx, path, "override-project"); err != nil {
		t.Fatalf("build: %v", err)
	} else if pid != "override-project" {
		t.Errorf("resolved project ID = %q, want override-project", pid)
	}
}

func TestBuildFCMTokenSource_Errors(t *testing.T) {
	ctx := context.Background()
	if _, _, err := buildFCMTokenSource(ctx, "", ""); err == nil {
		t.Error("empty credentials file should error")
	}
	if _, _, err := buildFCMTokenSource(ctx, "/nonexistent/sa.json", ""); err == nil {
		t.Error("missing credentials file should error")
	}
	// Valid key but no project ID anywhere (creds nor config) must error.
	path := writeTempServiceAccount(t, "")
	if _, _, err := buildFCMTokenSource(ctx, path, ""); err == nil {
		t.Error("missing project ID should error")
	}
}

// A transient build failure must NOT be memoized — otherwise a credentials file
// mounted late at boot would disable push for the whole process lifetime.
func TestFCMProvider_DoesNotCacheBuildFailure(t *testing.T) {
	ctx := context.Background()
	p := &fcmProvider{}

	if _, _, err := p.getToken(ctx, "", "proj"); err == nil {
		t.Fatal("expected error with empty credentials file")
	}
	if p.tokenSrc != nil {
		t.Fatal("a failed build must leave tokenSrc nil so the next call retries")
	}
	// Retry path still works (doesn't panic on the nil source).
	if _, _, err := p.getToken(ctx, "", "proj"); err == nil {
		t.Fatal("expected error on retry")
	}

	// Once a valid file appears, the build succeeds and IS cached (even if the
	// subsequent network Token() call fails offline in CI).
	path := writeTempServiceAccount(t, "proj")
	_, _, _ = p.getToken(ctx, path, "")
	if p.tokenSrc == nil {
		t.Fatal("a successful build should cache the token source")
	}
	if p.projectID != "proj" {
		t.Errorf("cached project ID = %q, want proj", p.projectID)
	}
}

func TestStringifyPayload(t *testing.T) {
	out := stringifyPayload(map[string]interface{}{
		"challenge_id": "abc",
		"expires_at":   int64(1700000000),
		"count":        3,
		"flag":         true,
	})
	// FCM HTTP v1 requires every data value to be a string.
	for k, v := range out {
		if v == "" && k != "" {
			// empty string is allowed, but our inputs are non-empty
			t.Errorf("unexpected empty value for %q", k)
		}
	}
	if out["challenge_id"] != "abc" {
		t.Errorf("challenge_id = %q, want abc", out["challenge_id"])
	}
	if out["expires_at"] != "1700000000" {
		t.Errorf("expires_at = %q, want 1700000000", out["expires_at"])
	}
	if out["count"] != "3" {
		t.Errorf("count = %q, want 3", out["count"])
	}
	if out["flag"] != "true" {
		t.Errorf("flag = %q, want true", out["flag"])
	}
}

func writeTestAPNSKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "AuthKey.p8")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func TestLoadAPNSKey(t *testing.T) {
	path := writeTestAPNSKey(t)
	if _, err := loadAPNSKey(path); err != nil {
		t.Fatalf("loadAPNSKey failed on a valid P-256 key: %v", err)
	}

	if _, err := loadAPNSKey(""); err == nil {
		t.Error("loadAPNSKey accepted an empty path")
	}

	badPath := filepath.Join(t.TempDir(), "bad.p8")
	_ = os.WriteFile(badPath, []byte("not a pem"), 0o600)
	if _, err := loadAPNSKey(badPath); err == nil {
		t.Error("loadAPNSKey accepted non-PEM content")
	}
}

func TestAPNSProviderToken(t *testing.T) {
	path := writeTestAPNSKey(t)
	p := &apnsProvider{}

	tok, err := p.getToken(path, "KEY123456", "TEAM123456")
	if err != nil {
		t.Fatalf("getToken failed: %v", err)
	}
	if tok == "" {
		t.Fatal("getToken returned an empty token")
	}

	// The token must be a well-formed ES256 JWT carrying the expected claims/header.
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("token is not a valid JWT: %v", err)
	}
	if parsed.Method.Alg() != "ES256" {
		t.Errorf("alg = %q, want ES256", parsed.Method.Alg())
	}
	if kid, _ := parsed.Header["kid"].(string); kid != "KEY123456" {
		t.Errorf("kid header = %q, want KEY123456", kid)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || claims["iss"] != "TEAM123456" {
		t.Errorf("iss claim = %v, want TEAM123456", claims["iss"])
	}

	// A second call with identical params returns the cached token.
	tok2, err := p.getToken(path, "KEY123456", "TEAM123456")
	if err != nil {
		t.Fatalf("second getToken failed: %v", err)
	}
	if tok2 != tok {
		t.Error("expected cached token to be reused within TTL")
	}
}

func TestAPNSTokenIsCompactJWT(t *testing.T) {
	// An APNS provider token must be a compact JWS: header.payload.signature.
	path := writeTestAPNSKey(t)
	p := &apnsProvider{}
	tok, err := p.getToken(path, "K", "T")
	if err != nil {
		t.Fatalf("getToken: %v", err)
	}
	if n := strings.Count(tok, "."); n != 2 {
		t.Errorf("APNS JWT should have 2 dots, got %d", n)
	}
}
