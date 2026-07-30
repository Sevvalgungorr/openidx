package vault

import (
	"context"
	"fmt"
	"time"
)

// KeyConfig is the subset of app config the vault keyring needs. Kept local so
// internal/vault does not import internal/common/config.
type KeyConfig struct {
	KEK           string // VAULT_KEK (base64, 32 bytes)
	KEKs          string // VAULT_KEKS ("id:base64,...")
	ActiveKEKID   int    // VAULT_ACTIVE_KEK_ID
	EncryptionKey string // ENCRYPTION_KEY (raw 32-byte string) — fallback KEK id 0

	// Bao, when fully set (Addr+Token+SecretPath), sources the KEK material
	// from OpenBao at startup INSTEAD of the fields above — the root key then
	// never lives in process env. Any OpenBao error is fatal (fail-closed).
	Bao BaoConfig
}

// KeyringFromConfig builds the vault KEK ring. Precedence: OpenBao-sourced
// keys (when configured — errors are fatal, never silently bypassed), else
// explicit VAULT_* keys, else the raw ENCRYPTION_KEY as id 0. Fails closed
// when nothing yields a usable 32-byte key — the vault never silently stores
// plaintext.
func KeyringFromConfig(cfg KeyConfig) (*keyring, error) {
	if cfg.Bao.enabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		mat, err := fetchBaoKeyMaterial(ctx, cfg.Bao)
		if err != nil {
			return nil, fmt.Errorf("vault: OpenBao KEK source configured but unusable (fail-closed): %w", err)
		}
		r, err := newKeyring(mat.KEKs, mat.ActiveKEKID, mat.KEK)
		if err != nil {
			return nil, fmt.Errorf("vault: OpenBao-sourced key material invalid: %w", err)
		}
		if r == nil {
			return nil, fmt.Errorf("vault: OpenBao secret yielded no key material (fail-closed)")
		}
		return r, nil
	}

	r, err := newKeyring(cfg.KEKs, cfg.ActiveKEKID, cfg.KEK)
	if err != nil {
		return nil, err
	}
	if r != nil {
		return r, nil
	}
	if len(cfg.EncryptionKey) != kekLen {
		return nil, fmt.Errorf("vault: no VAULT_KEK/VAULT_KEKS set and ENCRYPTION_KEY is not %d bytes; refusing to start (fail-closed)", kekLen)
	}
	return &keyring{keys: map[byte][]byte{0: []byte(cfg.EncryptionKey)}, activeID: 0}, nil
}
