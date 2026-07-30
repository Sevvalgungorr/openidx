// OpenBao KEK source — fetch the vault key-encryption keys from a self-hosted
// OpenBao (the MPL-2.0 open-source fork of HashiCorp Vault) instead of process
// environment variables. The KEK material then never lives in the container
// env/manifest: it is read once at startup over TLS with a scoped token, and
// OpenBao provides the audit trail and rotation workflow around it.
//
// Scope is deliberately minimal: one KV-v2 read at boot. Auto-unseal, dynamic
// re-fetch, and transit-based sealing are follow-ups; this removes the
// weakest link (KEK in env) without coupling request paths to OpenBao's
// availability — after boot, the vault runs exactly as before.
package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// BaoConfig locates the KEK secret in OpenBao. All three of Addr, Token and
// SecretPath must be set to enable the source.
type BaoConfig struct {
	// Addr is the OpenBao base URL, e.g. https://openbao.internal:8200.
	Addr string
	// Token is a token with read capability on SecretPath.
	Token string
	// SecretPath is the KV-v2 location as "mount/path", e.g.
	// "secret/openidx/vault-kek". The data may contain:
	//   kek            base64 32-byte key (single-key form), or
	//   keks           "id:base64,..." multi-key form
	//   active_kek_id  integer selecting the write key for the multi form
	SecretPath string
	// CACertFile optionally points at a PEM CA bundle to trust for the OpenBao
	// TLS endpoint. Verification is never skipped.
	CACertFile string
}

func (b BaoConfig) enabled() bool {
	return strings.TrimSpace(b.Addr) != "" && strings.TrimSpace(b.Token) != "" &&
		strings.TrimSpace(b.SecretPath) != ""
}

// baoKeyMaterial is the KEK payload read from OpenBao.
type baoKeyMaterial struct {
	KEK         string
	KEKs        string
	ActiveKEKID int
}

// fetchBaoKeyMaterial reads the KEK secret from OpenBao KV v2. Fail-closed by
// contract: any error (unreachable, 403, malformed payload) must abort startup
// — silently falling back to env keys would mask a mis-configured or
// compromised OpenBao and could silently split the keyring across sources.
func fetchBaoKeyMaterial(ctx context.Context, cfg BaoConfig) (*baoKeyMaterial, error) {
	base, err := url.Parse(strings.TrimSpace(cfg.Addr))
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" {
		return nil, fmt.Errorf("openbao: invalid address %q", cfg.Addr)
	}

	mount, rest, ok := strings.Cut(strings.Trim(cfg.SecretPath, "/"), "/")
	if !ok || mount == "" || rest == "" {
		return nil, fmt.Errorf("openbao: secret path %q must be \"mount/path\"", cfg.SecretPath)
	}

	tlsCfg := &tls.Config{}
	if cfg.CACertFile != "" {
		pem, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("openbao: read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("openbao: CA file %s contains no usable certificates", cfg.CACertFile)
		}
		tlsCfg.RootCAs = pool
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	// KV v2 read: GET {addr}/v1/{mount}/data/{path}
	reqURL := base.Scheme + "://" + base.Host + "/v1/" +
		url.PathEscape(mount) + "/data/" + rest
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", cfg.Token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openbao: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openbao: read %s: HTTP %d", cfg.SecretPath, resp.StatusCode)
	}

	var out struct {
		Data struct {
			Data struct {
				KEK         string          `json:"kek"`
				KEKs        string          `json:"keks"`
				ActiveKEKID json.RawMessage `json:"active_kek_id"`
			} `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("openbao: decode response: %w", err)
	}
	d := out.Data.Data
	if d.KEK == "" && d.KEKs == "" {
		return nil, fmt.Errorf("openbao: secret %s has neither \"kek\" nor \"keks\"", cfg.SecretPath)
	}

	mat := &baoKeyMaterial{KEK: d.KEK, KEKs: d.KEKs}
	if len(d.ActiveKEKID) > 0 {
		// Accept both a JSON number and a quoted string (KV UIs often store strings).
		var asInt int
		if err := json.Unmarshal(d.ActiveKEKID, &asInt); err == nil {
			mat.ActiveKEKID = asInt
		} else {
			var asStr string
			if err := json.Unmarshal(d.ActiveKEKID, &asStr); err != nil {
				return nil, fmt.Errorf("openbao: active_kek_id is neither number nor string")
			}
			if _, err := fmt.Sscanf(strings.TrimSpace(asStr), "%d", &asInt); err != nil {
				return nil, fmt.Errorf("openbao: active_kek_id %q is not an integer", asStr)
			}
			mat.ActiveKEKID = asInt
		}
	}
	return mat, nil
}
