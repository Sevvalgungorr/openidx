package access

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openidx/openidx/internal/common/database"
)

// zitiConnSettingsKey is the system_settings row that backs the admin-managed
// OpenZiti controller connection. Install-wide (system_settings is not
// org-scoped) — the controller endpoint + admin creds are one-per-box infra,
// consistent with the single shared ZitiManager.
const zitiConnSettingsKey = "ziti_connection"

// maskedSecret is returned in place of the admin password on reads and, when
// sent back unchanged on a write, signals "keep the stored value" (merge).
const maskedSecret = "********"

// ZitiConnSettings is the persisted connection config. The admin password is
// stored AES-256-GCM-encrypted in admin_password_enc; the plaintext is only
// ever held transiently in memory while building a manager.
type ZitiConnSettings struct {
	Enabled            bool   `json:"enabled"`
	ControllerURL      string `json:"controller_url"`
	AdminUser          string `json:"admin_user"`
	AdminPasswordEnc   string `json:"admin_password_enc,omitempty"`
	IdentityDir        string `json:"identity_dir"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

// ZitiConnSettingsView is the API shape: password masked, never the ciphertext.
type ZitiConnSettingsView struct {
	Enabled            bool   `json:"enabled"`
	ControllerURL      string `json:"controller_url"`
	AdminUser          string `json:"admin_user"`
	AdminPassword      string `json:"admin_password"`
	IdentityDir        string `json:"identity_dir"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

// View returns the masked, API-safe representation.
func (s ZitiConnSettings) View() ZitiConnSettingsView {
	pw := ""
	if s.AdminPasswordEnc != "" {
		pw = maskedSecret
	}
	return ZitiConnSettingsView{
		Enabled:            s.Enabled,
		ControllerURL:      s.ControllerURL,
		AdminUser:          s.AdminUser,
		AdminPassword:      pw,
		IdentityDir:        s.IdentityDir,
		InsecureSkipVerify: s.InsecureSkipVerify,
	}
}

// decryptPassword returns the plaintext admin password (empty if unset).
func (s ZitiConnSettings) decryptPassword(encKey string) (string, error) {
	if s.AdminPasswordEnc == "" {
		return "", nil
	}
	enc, err := newZitiSecretCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("ziti settings: %w", err)
	}
	return enc.Decrypt(s.AdminPasswordEnc)
}

// loadZitiConnSettings reads the connection row; ok=false if no row exists.
func loadZitiConnSettings(ctx context.Context, db *database.PostgresDB) (ZitiConnSettings, bool, error) {
	var raw []byte
	err := db.Pool.QueryRow(ctx,
		//orgscope:ignore install-wide infra connection (system_settings is not org-scoped); single shared ZitiManager
		`SELECT value FROM system_settings WHERE key = $1`, zitiConnSettingsKey).Scan(&raw)
	if err != nil {
		// No row → not configured.
		return ZitiConnSettings{}, false, nil //nolint:nilerr
	}
	var s ZitiConnSettings
	if err := json.Unmarshal(raw, &s); err != nil {
		return ZitiConnSettings{}, false, fmt.Errorf("ziti settings: decode: %w", err)
	}
	return s, true, nil
}

// saveZitiConnSettings upserts the connection row. The incoming plaintext
// password (from the API) is encrypted here; pass "" to leave the stored
// ciphertext untouched (merge — used when the masked sentinel comes back).
func saveZitiConnSettings(ctx context.Context, db *database.PostgresDB, encKey string, in ZitiConnSettingsView, updatedBy string) error {
	cur, _, err := loadZitiConnSettings(ctx, db)
	if err != nil {
		return err
	}
	out := ZitiConnSettings{
		Enabled:            in.Enabled,
		ControllerURL:      in.ControllerURL,
		AdminUser:          in.AdminUser,
		IdentityDir:        in.IdentityDir,
		InsecureSkipVerify: in.InsecureSkipVerify,
		AdminPasswordEnc:   cur.AdminPasswordEnc, // keep by default (merge)
	}
	if in.AdminPassword != "" && in.AdminPassword != maskedSecret {
		enc, eerr := newZitiSecretCipher(encKey)
		if eerr != nil {
			// Never silently store plaintext — refuse.
			return fmt.Errorf("ziti settings: cannot encrypt password: %w", eerr)
		}
		ct, eerr := enc.Encrypt(in.AdminPassword)
		if eerr != nil {
			return fmt.Errorf("ziti settings: encrypt: %w", eerr)
		}
		out.AdminPasswordEnc = ct
	}
	blob, err := json.Marshal(out)
	if err != nil {
		return err
	}
	var by interface{}
	if updatedBy != "" {
		by = updatedBy
	}
	_, err = db.Pool.Exec(ctx,
		//orgscope:ignore install-wide infra connection (system_settings is not org-scoped)
		`INSERT INTO system_settings (key, value, updated_at, updated_by)
		 VALUES ($1, $2, NOW(), $3)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW(), updated_by = EXCLUDED.updated_by`,
		zitiConnSettingsKey, blob, by)
	return err
}

// ResolveBootZitiConn resolves the connection to use at startup: persisted DB
// settings win; otherwise fall back to env (the Phase-1 path). enabled reflects
// whether to actually connect. Returns the decrypted plaintext password.
func ResolveBootZitiConn(ctx context.Context, db *database.PostgresDB, encKey, envCtrlURL, envUser, envPwd, envDir string, envEnabled, envInsecure bool) (ctrlURL, user, pwd, dir string, insecure, enabled bool, err error) {
	if db != nil {
		if st, ok, lerr := loadZitiConnSettings(ctx, db); lerr == nil && ok {
			p, derr := st.decryptPassword(encKey)
			if derr != nil {
				return "", "", "", "", false, false, derr
			}
			return st.ControllerURL, st.AdminUser, p, st.IdentityDir, st.InsecureSkipVerify, st.Enabled, nil
		}
	}
	return envCtrlURL, envUser, envPwd, envDir, envInsecure, envEnabled, nil
}
