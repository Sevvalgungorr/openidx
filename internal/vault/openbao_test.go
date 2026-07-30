package vault

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testKEKb64() string {
	return base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
}

// fakeBao serves a KV-v2 read of secret/openidx/vault-kek.
func fakeBao(t *testing.T, token, payload string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/data/openidx/vault-kek", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write([]byte(payload))
	})
	return httptest.NewServer(mux)
}

func TestKeyringFromOpenBaoSingleKEK(t *testing.T) {
	srv := fakeBao(t, "tok", `{"data":{"data":{"kek":"`+testKEKb64()+`"}}}`)
	defer srv.Close()

	r, err := KeyringFromConfig(KeyConfig{
		Bao: BaoConfig{Addr: srv.URL, Token: "tok", SecretPath: "secret/openidx/vault-kek"},
	})
	if err != nil {
		t.Fatalf("KeyringFromConfig: %v", err)
	}
	if !r.Enabled() || r.activeID != 0 {
		t.Fatalf("expected enabled ring with active id 0, got %+v", r)
	}
}

func TestKeyringFromOpenBaoMultiKEK(t *testing.T) {
	payload := `{"data":{"data":{"keks":"0:` + testKEKb64() + `,3:` + testKEKb64() + `","active_kek_id":"3"}}}`
	srv := fakeBao(t, "tok", payload)
	defer srv.Close()

	r, err := KeyringFromConfig(KeyConfig{
		Bao: BaoConfig{Addr: srv.URL, Token: "tok", SecretPath: "secret/openidx/vault-kek"},
	})
	if err != nil {
		t.Fatalf("KeyringFromConfig: %v", err)
	}
	// active_kek_id delivered as a quoted string must still select id 3.
	if r.activeID != 3 || len(r.keys) != 2 {
		t.Fatalf("expected active id 3 with 2 keys, got active=%d keys=%d", r.activeID, len(r.keys))
	}
}

func TestKeyringOpenBaoFailClosed(t *testing.T) {
	// Wrong token → 403 → startup must fail even though env fallback exists.
	srv := fakeBao(t, "right", `{"data":{"data":{"kek":"`+testKEKb64()+`"}}}`)
	defer srv.Close()

	_, err := KeyringFromConfig(KeyConfig{
		EncryptionKey: "0123456789abcdef0123456789abcdef", // would be a valid fallback
		Bao:           BaoConfig{Addr: srv.URL, Token: "wrong", SecretPath: "secret/openidx/vault-kek"},
	})
	if err == nil {
		t.Fatal("expected fail-closed error when OpenBao is configured but denies access")
	}
	if !strings.Contains(err.Error(), "fail-closed") {
		t.Fatalf("expected fail-closed error, got: %v", err)
	}
}

func TestKeyringOpenBaoEmptySecretFails(t *testing.T) {
	srv := fakeBao(t, "tok", `{"data":{"data":{"note":"nothing here"}}}`)
	defer srv.Close()

	_, err := KeyringFromConfig(KeyConfig{
		Bao: BaoConfig{Addr: srv.URL, Token: "tok", SecretPath: "secret/openidx/vault-kek"},
	})
	if err == nil {
		t.Fatal("expected error for secret without kek/keks")
	}
}

func TestKeyringOpenBaoDisabledFallsThrough(t *testing.T) {
	// Partial Bao config (no token) = disabled → env path is used as before.
	r, err := KeyringFromConfig(KeyConfig{
		EncryptionKey: "0123456789abcdef0123456789abcdef",
		Bao:           BaoConfig{Addr: "https://bao:8200"},
	})
	if err != nil {
		t.Fatalf("KeyringFromConfig: %v", err)
	}
	if !r.Enabled() {
		t.Fatal("expected env-based ring when Bao config is incomplete")
	}
}

func TestBaoConfigValidation(t *testing.T) {
	if _, err := KeyringFromConfig(KeyConfig{
		Bao: BaoConfig{Addr: "ftp://x", Token: "t", SecretPath: "secret/k"},
	}); err == nil {
		t.Fatal("expected invalid address error")
	}
	if _, err := KeyringFromConfig(KeyConfig{
		Bao: BaoConfig{Addr: "https://bao:8200", Token: "t", SecretPath: "nopath"},
	}); err == nil {
		t.Fatal("expected mount/path validation error")
	}
}
